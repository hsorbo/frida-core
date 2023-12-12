#ifndef __FRIDA_XPC_H__
#define __FRIDA_XPC_H__

#include <glib.h>
#include <xpc/xpc.h>

typedef void (* FridaXpcHandler) (xpc_object_t object, gpointer user_data);

void _frida_xpc_connection_set_event_handler (xpc_connection_t connection, FridaXpcHandler handler, gpointer user_data);
gchar * _frida_xpc_object_to_string (xpc_object_t object);

#endif
