#include "src/storage.h"
#include "default-properties.h"

#include <ofono/log.h>

#define DEFAULT_PROPERTIES_NAME "default_properties.conf"

gchar* default_properties_get_value(gchar * group, gchar * key, const char* default_value)
{
	gchar * ret = NULL;
	gboolean save = FALSE;
	GKeyFile *key_file = storage_open(NULL, DEFAULT_PROPERTIES_NAME);

	if (!key_file)
		return NULL;

	/* Check that the key exist */
	if (g_key_file_has_key(key_file, group, key, NULL))	{
		ret = g_key_file_get_string(key_file, group, key, NULL);
	} else {
		/* The file or the key does not exist so we create it with default value */
		ret = g_strdup(default_value);
		g_key_file_set_string(key_file, group, key, ret);
		save = TRUE;
	}
	storage_close(NULL, DEFAULT_PROPERTIES_NAME, key_file, save);
	if (save) {
		storage_flush(NULL, DEFAULT_PROPERTIES_NAME);
	}

	return ret;
}

void default_properties_set_value(const gchar *group, const gchar *key, const gchar *value)
{
	GKeyFile *key_file = storage_open(NULL, DEFAULT_PROPERTIES_NAME);

	if (!key_file)
		return;

	g_key_file_set_string(key_file, group, key, value);
	storage_close(NULL, DEFAULT_PROPERTIES_NAME, key_file, TRUE);
	storage_flush(NULL, DEFAULT_PROPERTIES_NAME);
}
