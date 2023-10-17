#include "frida-core.h"

#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <dispatch/dispatch.h>
#include <xpc/xpc.h>

typedef xpc_object_t remote_device_t;

static void frida_dump_device (remote_device_t device, bool connected);

static void (* remote_device_browse_present) (int kind, dispatch_queue_t queue, void (^ callback) (remote_device_t device, bool is_last_item));
static xpc_object_t (* remote_device_copy_properties) (remote_device_t self);
static xpc_object_t (* remote_device_copy_service_names) (remote_device_t self);
static xpc_object_t (* remote_device_copy_local_service_names) (remote_device_t self);
static bool (* remote_device_get_connectable) (remote_device_t self);
static void (* remote_device_set_connected_callback) (remote_device_t self, dispatch_queue_t queue, void (^ callback) (remote_device_t device));
static void (* remote_device_heartbeat) (remote_device_t self, dispatch_queue_t queue, void (^ callback) (bool alive));

void
_frida_xpc_get_endpoint_for_device (const gchar * uuid)
{
  void * rsd;
  dispatch_queue_t queue;

  rsd = dlopen ("/System/Library/PrivateFrameworks/RemoteServiceDiscovery.framework/RemoteServiceDiscovery", RTLD_GLOBAL | RTLD_LAZY);
  remote_device_browse_present = dlsym (rsd, "remote_device_browse_present");
  remote_device_copy_properties = dlsym (rsd, "remote_device_copy_properties");
  remote_device_copy_service_names = dlsym (rsd, "remote_device_copy_service_names");
  remote_device_copy_local_service_names = dlsym (rsd, "remote_device_copy_local_service_names");
  remote_device_get_connectable = dlsym (rsd, "remote_device_get_connectable");
  remote_device_set_connected_callback = dlsym (rsd, "remote_device_set_connected_callback");
  remote_device_heartbeat = dlsym (rsd, "remote_device_heartbeat");

  queue = dispatch_queue_create ("re.frida.fruity.queue", DISPATCH_QUEUE_SERIAL);

  remote_device_browse_present (8, queue, ^(remote_device_t device, bool is_last_item)
      {
        g_print ("got callback!\n");
        NSLog (@"\tdevice: %@", device);
        g_print ("\tis_last_item: %s\n", is_last_item ? "true" : "false");
        if (device == nil)
          return;

        frida_dump_device (device, false);

        remote_device_set_connected_callback (device, queue, ^(remote_device_t device)
            {
              g_print ("connected! device=%p\n", device);
              frida_dump_device (device, false);

              xpc_retain (device);

              remote_device_heartbeat (device, queue, ^(bool alive)
                  {
                    g_print ("heartbeat! alive=%s\n", alive ? "true" : "false");
                    frida_dump_device (device, true);
                    xpc_release (device);
                  });
            });
      });

  g_usleep (5 * G_USEC_PER_SEC);
}

static void
frida_dump_device (remote_device_t device, bool connected)
{
  xpc_object_t props = remote_device_copy_properties (device);
  NSLog (@"\tproperties: %@", props);

  xpc_object_t names = remote_device_copy_service_names (device);
  NSLog (@"\tservices names: %@", names);

#if 0
  xpc_object_t local_names = remote_device_copy_local_service_names (device);
  NSLog (@"\tlocal services names: %@", local_names);
#endif

  if (connected)
  {
    bool connectable = remote_device_get_connectable (device);
    NSLog (@"\tconnectable: %s", connectable ? "true" : "false");
  }
}
