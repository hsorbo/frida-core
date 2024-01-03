#include "frida-xpc.h"

void
_frida_xpc_connection_set_event_handler (xpc_connection_t connection, FridaXpcHandler handler, gpointer user_data)
{
  xpc_connection_set_event_handler (connection, ^(xpc_object_t object)
      {
        handler (object, user_data);
      });
}

gchar *
_frida_xpc_object_to_string (xpc_object_t object)
{
  gchar * result;
  char * str;

  str = xpc_copy_description (object);
  result = g_strdup (str);
  free (str);

  return result;
}
