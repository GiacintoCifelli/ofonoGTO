#ifndef __OFONO_DEFAULT_PROP_H
#define __OFONO_DEFAULT_PROP_H

#include <glib.h>

gchar* default_properties_get_value(gchar * group, gchar * key, const char* default_value);
void default_properties_set_value(const gchar *group, const gchar *key, const gchar *value);

#endif /* __OFONO_DEFAULT_PROP_H */
