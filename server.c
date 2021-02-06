#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <glib-2.0/glib.h>
#include <math.h>
#include <gio/gio.h>
#include <mysql/mysql.h>

#include "helper.h"

#define USERNAME "[USERNAME}"
#define PASSWORD "[PASSWORD]"

#define MySQLHost "127.0.0.1"
#define MySQLUser "[MYSQLUSER]"
#define MySQLPassword "[MYSQLPASS]"
#define MySQLDB "adsb"

/* net beast + timestamp + username + sha256 hash */
#define MIN_MESSAGE_LENGTH 112

typedef struct ADSBUser {
    gint id;
    gchar *username;
    gchar *password_hash;
} ADSBUser;

typedef struct ADSBMySQL {
    MYSQL *connection;
} ADSBMySQL;

typedef struct ADSBClient {
  ADSBMySQL *mysql;
  ADSBUser *user;
} ADSBClient;

enum VALIDATE {
  VALIDATE_OK,
  VALIDATE_NOT_OK,
  VALIDATE_INVALID_USER,
  VALIDATE_NOT_BEAST,
  VALIDATE_NOT_COMPLETE
};

gchar* get_message_part(gchar *message, gint num) {
  gchar **elements = g_strsplit(message, "+", 5);
  gint i;
  for(i=0; i<num; i++) {
    if (elements[i] == NULL) { 
      return NULL;
    }
  }
  
  gchar *temp = g_strdup(elements[num]);
  g_strfreev(elements);
  return temp;    
}

void get_user(ADSBClient *adsbclient, gchar *username) {
  MYSQL *connection = adsbclient->mysql->connection;
  ADSBUser *user = adsbclient->user;

  gchar *query = g_malloc(sizeof(gchar) * 1024);
  g_sprintf(query, "SELECT `id`, `username`, `password_hash` FROM `user` WHERE `username` = '%s';", username);

  mysql_query(connection, query);
  MYSQL_RES *result = mysql_store_result(connection);
  MYSQL_ROW row = mysql_fetch_row(result);

  g_debug("mysql row: %d %s %s\n", atoi(row[0]), row[1], row[2]);

  if (row == NULL)
    return;

  if (user->username == NULL && row != NULL) {
    user->id = atoi(row[0]);
    user->username = g_strdup(row[1]);
    user->password_hash = g_strdup(row[2]);
    g_print("Got user: %s\n", user->username);
  }

  mysql_free_result(result);
}

gboolean validate_message(ADSBClient *adsbclient, gchar *message) {
    ADSBUser *user = adsbclient->user;

    gchar *beast = g_utf8_substring(message, 0, 2);
    gchar init = (gint) g_ascii_strtoll(beast, NULL, 16);
    g_free(beast);
    if (init != 0x1a)
      return VALIDATE_NOT_BEAST;

    gchar *msg = get_message_part(message, 0);
    gdouble timestamp = atof(get_message_part(message, 1));
    gchar *username = get_message_part(message, 2);
    gchar *hash = get_message_part(message, 3);

    if (msg == NULL || username == NULL || hash == NULL)
      return VALIDATE_NOT_COMPLETE;

    if (user->username == NULL)
      get_user(adsbclient, username);

    if (user == NULL)
      return VALIDATE_INVALID_USER;

    if (g_strcmp0(username, user->username) != 0)
        return VALIDATE_INVALID_USER;

    GString *temp = g_string_new(msg);
    g_string_append(temp, "+");
    g_string_append_printf(temp, "%f", timestamp);
    g_string_append(temp, "+");
    g_string_append(temp, user->username);
    g_string_append(temp, "+");
    g_string_append(temp, user->password_hash);

    gchar *check = generate_checksum(temp->str);

    gint result = g_strcmp0(hash, check);
    g_string_free(temp, TRUE);

    g_free(msg);
    g_free(username);
    g_free(hash);
    g_free(check);

    if (result == 0)
        return VALIDATE_OK;
    else
        return VALIDATE_NOT_OK;
}

gchar * message_get_adsb_message(gchar *message) {
  return g_utf8_substring(message, 18, 100);
}

gint message_get_signal(gchar *message) {
  gchar *signal = g_utf8_substring(message, 16, 18);
  return (gint) g_ascii_strtoll(signal, NULL, 16);
}

unsigned long message_get_mlat(gchar *message) {
  gchar t[6], *temp;
  gint i;
  for (i=0; i<6; i++) {
      temp = g_utf8_substring(message, i*2+4, i*2+6);
      t[i] = (gint) g_ascii_strtoll(temp, NULL, 16);
      g_free(temp);
  }

  unsigned long timestamp = t[0] * pow(2,40) +
                      t[1] * pow(2,32) +
                      t[2] * pow(2,24) +
                      t[3] * pow(2,16) +
                      t[4] * pow(2,8) +
                      t[5];
  return timestamp;
}

gboolean save_message_in_mysql(ADSBClient *adsbclient, gchar *message) {
  MYSQL *connection = adsbclient->mysql->connection;
  ADSBUser *user = adsbclient->user;

  gchar *msg = get_message_part(message, 0);
  gchar *temp = get_message_part(message, 1);
  gchar **timestamp = g_strsplit(temp, ".", 2);
  g_free(temp);
  gint signal = message_get_signal(msg);
  unsigned long mlat = message_get_mlat(msg);
  gchar *adsbmsg = message_get_adsb_message(msg);

  gchar *query = g_malloc(sizeof(gchar) * 1024);
  g_sprintf(query, "INSERT INTO `raw` (`userid`,`timestamp`,`miliseconds`,`signal`,`message`,`mlat`) VALUES (%d, FROM_UNIXTIME(%s), %s, %d, '%s', %llu);", user->id, timestamp[0], timestamp[1], signal, adsbmsg, mlat);
  printf("*%s;\n", adsbmsg);
  fflush(stdout);
  mysql_query(connection, query);
  g_free(msg);
  g_free(adsbmsg);
  g_free(query);
  g_strfreev(timestamp);
}

gboolean
incoming_callback  (GSocketService *service,
                    GSocketConnection *connection,
                    GObject *source_object,
                    gpointer user_data)
{
  ADSBClient *adsbclient = g_malloc(sizeof(ADSBClient));

  adsbclient->user = g_malloc(sizeof(ADSBUser));
  ADSBUser *user = adsbclient->user;

  adsbclient->mysql = g_malloc(sizeof(ADSBMySQL));
  adsbclient->mysql->connection = mysql_init(NULL);
  mysql_real_connect(adsbclient->mysql->connection, MySQLHost, MySQLUser, MySQLPassword, MySQLDB, 0, NULL, 0);

  user->username = NULL;
  user->password_hash = NULL;

  g_print("Received Connection from client!\n");
  GInputStream * istream = g_io_stream_get_input_stream (G_IO_STREAM (connection));
  gchar *input = g_malloc(sizeof(gchar)*1024);
  memset(input,'\0',1024);
  gchar **messages;
  gchar *message;
  gint i = 0;
  while (g_input_stream_read  (istream,
                        input,
                        1024,
                        NULL,
                        NULL)) {
    messages = g_strsplit(input, "*", 0);
    i = 0;
    while(messages[i] != NULL) {
      if (strlen(messages[i]) > MIN_MESSAGE_LENGTH) {
        message = g_strdup(messages[i]);
        switch(validate_message(adsbclient, message)) {
          case VALIDATE_NOT_OK:
            g_warning("Message NOT ok: %s\n", message);
            break;
          case VALIDATE_NOT_BEAST:
            g_warning("Message NOT beast: %s\n", message);
            break;
          case VALIDATE_NOT_COMPLETE:
            g_warning("Message NOT complete: %s\n", message);
            break;
          case VALIDATE_OK:
            g_debug("Message ok: %s\n", message);
            save_message_in_mysql(adsbclient, message);
            break;
          case VALIDATE_INVALID_USER:
            g_warning("Message was sent with an invalid user: %s\n", message);
            break;
        }
        g_free(message);
      }
      i++;
    }
    g_strfreev(messages);
    memset(input,'\0',1024);
  }
  return FALSE;
}

int main(int argc, char **argv)
{
#if ! GLIB_CHECK_VERSION(2,36,0)
  g_type_init();
#endif

    GError * error = NULL;
	GSocketService * service = g_threaded_socket_service_new (10);
	g_socket_listener_add_inet_port ((GSocketListener*)service,
                                    50009,
                                    NULL,
                                    &error);
	if (error != NULL)
	{
    	g_error ("%s", error->message);
	}

	  /* listen to the 'run' signal */
  g_signal_connect (service,
                    "run",
                    G_CALLBACK (incoming_callback),
                    NULL);

  /* start the socket service */
  g_socket_service_start (service);

  /* enter mainloop */
  g_print ("Waiting for client!\n");
  GMainLoop *loop = g_main_loop_new(NULL, FALSE);
  g_main_loop_run(loop);
  return 0;
}
