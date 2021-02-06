#include <glib-2.0/glib.h>
#include <string.h>

#include "helper.h"

gchar *generate_checksum (gchar *message) {
    GChecksum *checksum = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(checksum, message, strlen(message));
    gchar *hash = g_strdup(g_checksum_get_string(checksum));
    g_checksum_free(checksum);

    return hash;
}