#include "frida-core.h"

#include <dns_sd.h>
#include <nghttp2/nghttp2.h>

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

static ssize_t frida_xpc_service_connection_on_send (nghttp2_session * session, const uint8_t * data, size_t length, int flags,
    void * user_data);

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

void
_frida_xpc_service_connection_create_session (FridaXPCServiceConnection * self)
{
  nghttp2_session_callbacks * callbacks;
  nghttp2_session * session;

  nghttp2_session_callbacks_new (&callbacks);
  nghttp2_session_callbacks_set_send_callback (callbacks, frida_xpc_service_connection_on_send);

  nghttp2_session_client_new (&session, callbacks, self);

  nghttp2_session_callbacks_del (callbacks);

  self->session = session;
}

void
_frida_xpc_service_connection_destroy_session (FridaXPCServiceConnection * self)
{
  nghttp2_session * session = g_steal_pointer (&self->session);

  nghttp2_session_del (session);
}

void
_frida_xpc_service_connection_on_recv (FridaXPCServiceConnection * self, guint8 * data, gint data_length, GError ** error)
{
  nghttp2_session * session = self->session;
  ssize_t res;

  if ((res = nghttp2_session_mem_recv (session, data, data_length)) < 0)
    goto recv_failed;

  return;

recv_failed:
  {
    g_set_error (error, FRIDA_ERROR, FRIDA_ERROR_PROTOCOL, "Unexpected HTTP error encountered: %zd", res);
    return;
  }
}

static ssize_t
frida_xpc_service_connection_on_send (nghttp2_session * session, const uint8_t * data, size_t length, int flags, void * user_data)
{
  g_printerr ("on_send() length=%zu\n", length);
  return length;
}
