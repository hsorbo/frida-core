#include "frida-core.h"

#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>
#include <Network/Network.h>

void
_frida_xpc_get_endpoint_for_device (const gchar * uuid)
{
  dispatch_queue_t queue;
  nw_browse_descriptor_t desc;
  nw_browser_t browser;

  queue = dispatch_queue_create ("re.frida.fruity.queue", DISPATCH_QUEUE_SERIAL);

  desc = nw_browse_descriptor_create_bonjour_service ("_remotepairing._tcp", "local.");
  nw_parameters_t params = nw_parameters_create_secure_tcp (NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION);

  browser = nw_browser_create (desc, params);
  nw_browser_set_queue (browser, queue);
  nw_browser_set_browse_results_changed_handler (browser, ^(nw_browse_result_t old_result, nw_browse_result_t new_result, bool batch_complete)
      {
        NSLog (@"results_changed()\n\told_result=%@\n\tnew_result=%@\n\tbatch_complete=%s",
            old_result,
            new_result,
            batch_complete ? "true" : "false");

        nw_endpoint_t ep = nw_browse_result_copy_endpoint (new_result);
        NSLog (@"endpoint: %@", ep);

        nw_txt_record_t txt = nw_browse_result_copy_txt_record_object (new_result);
        NSLog (@"txt: %@", txt);

        NSLog (@">>>");
        nw_browse_result_enumerate_interfaces (new_result, ^bool (nw_interface_t iface)
            {
              NSLog (@"interface: %@", iface);
              return true;
            });
        NSLog (@"<<<\n");
      });
  nw_browser_start (browser);

  nw_release (params);
  nw_release (desc);

  g_usleep (5 * G_USEC_PER_SEC);
}
