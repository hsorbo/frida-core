#include "frida-core.h"

#include <dns_sd.h>

typedef struct _FridaXPCPairingBrowserBackend FridaXPCPairingBrowserBackend;

struct _FridaXPCPairingBrowserBackend
{
  FridaXPCPairingBrowser * browser;
  dispatch_queue_t queue;
  DNSServiceRef dns_connection;
  GPtrArray * dns_sessions;
};

static void frida_xpc_pairing_browser_backend_start (FridaXPCPairingBrowserBackend * self);
static void frida_xpc_pairing_browser_backend_stop (FridaXPCPairingBrowserBackend * self);
static void frida_xpc_pairing_browser_backend_on_browse_reply (DNSServiceRef sd_ref, DNSServiceFlags flags, uint32_t interface_index,
    DNSServiceErrorType error_code, const char * service_name, const char * regtype, const char * reply_domain, void * context);
static void frida_xpc_pairing_browser_backend_on_resolve_reply (DNSServiceRef sd_ref, DNSServiceFlags flags, uint32_t interface_index,
    DNSServiceErrorType error_code, const char * fullname, const char * hosttarget, uint16_t port, uint16_t txt_len,
    const unsigned char * txt_record, void * context);

void *
_frida_xpc_pairing_browser_create_backend (FridaXPCPairingBrowser * browser)
{
  FridaXPCPairingBrowserBackend * backend;

  backend = g_slice_new0 (FridaXPCPairingBrowserBackend);
  backend->browser = browser;
  backend->queue = dispatch_queue_create ("re.frida.fruity.queue", DISPATCH_QUEUE_SERIAL);
  backend->dns_sessions = g_ptr_array_new_with_free_func ((GDestroyNotify) DNSServiceRefDeallocate);

  dispatch_async (backend->queue, ^{ frida_xpc_pairing_browser_backend_start (backend); });

  return backend;
}

void
_frida_xpc_pairing_browser_destroy_backend (void * backend)
{
  FridaXPCPairingBrowserBackend * b = backend;

  dispatch_sync (b->queue, ^{ frida_xpc_pairing_browser_backend_stop (backend); });

  g_ptr_array_unref (b->dns_sessions);
  dispatch_release (b->queue);

  g_slice_free (FridaXPCPairingBrowserBackend, b);
}

static void
frida_xpc_pairing_browser_backend_start (FridaXPCPairingBrowserBackend * self)
{
  DNSServiceRef browse_session;

  DNSServiceCreateConnection (&self->dns_connection);
  DNSServiceSetDispatchQueue (self->dns_connection, self->queue);

  browse_session = self->dns_connection;
  if (DNSServiceBrowse (&browse_session,
      kDNSServiceFlagsPrivateFive | kDNSServiceFlagsShareConnection,
      0,
      "_remotepairing._tcp",
      "local.",
      frida_xpc_pairing_browser_backend_on_browse_reply,
      self) == kDNSServiceErr_NoError)
  {
    g_ptr_array_add (self->dns_sessions, browse_session);
  }
}

static void
frida_xpc_pairing_browser_backend_stop (FridaXPCPairingBrowserBackend * self)
{
  g_ptr_array_set_size (self->dns_sessions, 0);
  DNSServiceRefDeallocate (self->dns_connection);
}

static void
frida_xpc_pairing_browser_backend_on_browse_reply (DNSServiceRef sd_ref, DNSServiceFlags flags, uint32_t interface_index,
    DNSServiceErrorType error_code, const char * service_name, const char * regtype, const char * reply_domain, void * context)
{
  FridaXPCPairingBrowserBackend * self = context;
  DNSServiceRef resolve_session;

  if (error_code != kDNSServiceErr_NoError)
    return;

  resolve_session = self->dns_connection;
  if (DNSServiceResolve (&resolve_session,
        kDNSServiceFlagsPrivateFive | kDNSServiceFlagsShareConnection,
        interface_index,
        service_name,
        regtype,
        reply_domain,
        frida_xpc_pairing_browser_backend_on_resolve_reply,
        self) == kDNSServiceErr_NoError)
  {
    g_ptr_array_add (self->dns_sessions, resolve_session);
  }
}

static void
frida_xpc_pairing_browser_backend_on_resolve_reply (DNSServiceRef sd_ref, DNSServiceFlags flags, uint32_t interface_index,
    DNSServiceErrorType error_code, const char * fullname, const char * hosttarget, uint16_t port, uint16_t txt_len,
    const unsigned char * txt_record, void * context)
{
  FridaXPCPairingBrowserBackend * self = context;

  if (error_code == kDNSServiceErr_NoError)
  {
    GBytes * txt_bytes = g_bytes_new (txt_record, txt_len);

    _frida_xpc_pairing_browser_on_match (self->browser, fullname, hosttarget, GUINT16_FROM_BE (port), txt_bytes);

    g_bytes_unref (txt_bytes);
  }

  g_ptr_array_remove (self->dns_sessions, sd_ref);
}
