#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <glib-2.0/glib.h>
#include <math.h>
#include <gio/gio.h>

#include "helper.h"

typedef struct ADSBClient {
    gchar *username;
    gchar *password_hash;

    GAsyncQueue *async_queue;
} ADSBClient;

void *start_raw_client (ADSBClient *adsbclient);
void *start_reader (ADSBClient *adsbclient);

static gchar *username = NULL;
static gchar *password = NULL;
static gchar *clientip = "127.0.0.1";
static gint clientport = 30005;
static gchar *serverip = "[[SERVERIP]]";
static gint serverport = 50009;

static GOptionEntry entries[] =
{
    { "username", 'u', 0, G_OPTION_ARG_STRING, &username, "Username", NULL },
    { "password", 'p', 0, G_OPTION_ARG_STRING, &password, "Password", NULL },
    { "client-ip", 0, 0, G_OPTION_ARG_STRING, &clientip, "Client IP", NULL },
    { "client-port", 0, 0, G_OPTION_ARG_INT, &clientport, "Client port", NULL },
    { "server-ip", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_STRING, &serverip, "Server IP", NULL },
    { "server-port", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_INT, &serverport, "Server port", NULL },
    { NULL }
};

int main(int argc, char **argv)
{
#if ! GLIB_CHECK_VERSION(2,36,0)
    g_type_init();
#endif
    GError *error = NULL;
    GOptionContext *context;

    context = g_option_context_new ("- ADS-B client");
    g_option_context_add_main_entries (context, entries, NULL);
    g_option_context_set_help_enabled(context, TRUE);
    if (!g_option_context_parse (context, &argc, &argv, &error))
    {
        g_print ("option parsing failed: %s\n", error->message);
        exit (1);
    }

    if (username == NULL || password == NULL) {
        printf("%s", g_option_context_get_help(context, TRUE, NULL));
        exit(1);
    }

    ADSBClient *adsbclient = g_malloc(sizeof(ADSBClient));
    adsbclient->username = username;

    GChecksum *checksum = g_checksum_new(G_CHECKSUM_MD5);
    g_checksum_update(checksum, password, strlen(password));
    adsbclient->password_hash = g_strdup(g_checksum_get_string(checksum));
    g_checksum_free(checksum);

	adsbclient->async_queue = g_async_queue_new();
	pthread_t raw_client_thread, reader_thread;
	pthread_create(&raw_client_thread, NULL, (void *) start_raw_client, adsbclient);
	pthread_create(&reader_thread, NULL, (void *) start_reader, adsbclient);
	pthread_join(raw_client_thread,NULL);
	pthread_join(reader_thread,NULL);
}

GOutputStream *reconnect(GSocketConnection *connection, GSocketClient *client, GError *error) {
    connection = g_socket_client_connect_to_host (client, serverip, serverport, NULL, &error);
    error = NULL;
    if (error != NULL) {
        g_error ("%s", error->message);
        error = NULL;
    }
    else
        g_debug("Connection successful!\n");
    GOutputStream * ostream = g_io_stream_get_output_stream (G_IO_STREAM (connection));
    return ostream;
}

void *start_reader (ADSBClient *adsbclient) {
    GError * error = NULL;
    GSocketConnection * connection = NULL;
    GSocketClient * client = g_socket_client_new();

    //connection = g_socket_client_connect_to_host (client, (gchar*) "[REDACTED]", 50009, NULL, &error); // old server IP
    //connection = g_socket_client_connect_to_host (client, (gchar*) "127.0.0.1", 50009, NULL, &error);

    GOutputStream *ostream = reconnect(connection, client, error);

    gchar *str = NULL;
    GString *temp = NULL;
    while((str = g_async_queue_pop(adsbclient->async_queue))) {
        temp = g_string_new(str);
        g_free(str);
        g_output_stream_write(ostream, temp->str, temp->len, NULL, &error);
        g_debug("%s", temp->str);
        if (error != NULL) {
            g_print("BANG!!!");
            ostream = reconnect(connection, client, error);
        }
        g_string_free(temp, TRUE);
    }
    pthread_exit(0);
}

gchar *build_message(gchar preamble[2], guchar *data, int length, GDateTime *timestamp, gchar *username, gchar *password) {
  gint i;
  GString *temp, *output;

  temp = g_string_new(NULL);

  for (i = 0; i < 2; i++)
    g_string_append_printf(temp, "%02x", preamble[i]);

  for (i = 0; i < length; i++)
    g_string_append_printf(temp, "%02x", data[i]);

  g_string_append_printf(temp, "+%lld.%06d", (long long int) g_date_time_to_unix(timestamp), g_date_time_get_microsecond(timestamp));
  g_string_append_printf(temp, "+%s", username);
  output = g_string_new(temp->str);
  g_string_append_printf(temp, "+%s", password);
  
  gchar *hash = generate_checksum(temp->str);
  g_string_append_printf(output, "+%s", hash);
  g_string_append_printf(output, "*", hash);
  g_free(hash);

  g_string_free(temp, TRUE);
  gchar *retval = g_strdup(output->str);
  g_string_free(output, TRUE);
  return retval;
}

void *start_raw_client (ADSBClient *adsbclient) {
 
    GError * error = NULL;
    GSocketConnection * connection = NULL;
    GSocketClient * client = g_socket_client_new();

    GDateTime *timestamp = NULL;

    connection = g_socket_client_connect_to_host (client, clientip, clientport, NULL, &error);
    if (error != NULL)
        g_error ("%s", error->message);
    else
        g_print("Connection successful!\n");

    GInputStream * istream = g_io_stream_get_input_stream (G_IO_STREAM (connection));

    guchar c1, c2, preamble[2], data[32];
    memset(&data, 0x00, sizeof(data));
    memset(&preamble, 0x00, sizeof(preamble));
    gint msglength;

    while (g_input_stream_read(istream, &c1, 1, NULL, &error)) {
        timestamp = g_date_time_new_now_utc();
        if (c1 == 0x1a) {
            g_input_stream_read(istream, &c2, 1, NULL, &error);
            switch(c2) {
                case 0x31:
                    g_debug("2 byte Mode-AC\n");
                    msglength = 2+2;
                    break;
                case 0x32:
                    g_debug("7 byte Mode-S short frame\n");
                    msglength = 7+7;
                    break;
                case 0x33:
                    g_debug("14 byte Mode-S long frame\n");
                    msglength = 14+7;
                    break;
                default:
                    g_warning("unknown message (%02x)\n", c2);
                    msglength = 0;
                    break;
            }

            preamble[0] = c1;
            preamble[1] = c2;

            g_input_stream_read(istream, &data, msglength, NULL, &error);

	        gchar *message = build_message(preamble, data, msglength, timestamp, adsbclient->username, adsbclient->password_hash);

	        g_async_queue_push(adsbclient->async_queue, message);
        }
        else
            g_warning("Unknown initial char (%02x)\n", c1);
        g_date_time_unref(timestamp);
    }

    if(0 < 0)
    {
        printf("\n Read error \n");
    }

    pthread_exit(0);
}
