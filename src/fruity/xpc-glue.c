#include "frida-core.h"

#include <dns_sd.h>
#include <net/if.h>
#include <nghttp2/nghttp2.h>

#define FRIDA_REMOTE_XPC_PAIRING_REGTYPE "_remotepairing._tcp"
#define FRIDA_REMOTE_XPC_PAIRING_DOMAIN  "local."

typedef struct _FridaXPCPairingBrowserBackend FridaXPCPairingBrowserBackend;

struct _FridaXPCPairingBrowserBackend
{
  FridaXPCPairingBrowser * browser;
  dispatch_queue_t queue;
  DNSServiceRef dns_connection;
  GPtrArray * dns_sessions;
  GQueue operations;
  gboolean operation_in_progress;
};

static void frida_xpc_pairing_browser_backend_start (FridaXPCPairingBrowserBackend * self);
static void frida_xpc_pairing_browser_backend_stop (FridaXPCPairingBrowserBackend * self);
static void frida_xpc_pairing_browser_backend_on_browse_reply (DNSServiceRef sd_ref, DNSServiceFlags flags, uint32_t interface_index,
    DNSServiceErrorType error_code, const char * service_name, const char * regtype, const char * reply_domain, void * context);
static void frida_xpc_pairing_browser_backend_maybe_perform_next_resolve_operation (FridaXPCPairingBrowserBackend * self);
static void frida_xpc_pairing_browser_backend_complete_resolve_operation (FridaXPCPairingBrowserBackend * self, GError * error);
static void frida_xpc_pairing_browser_backend_on_resolve_reply (DNSServiceRef sd_ref, DNSServiceFlags flags, uint32_t interface_index,
    DNSServiceErrorType error_code, const char * fullname, const char * hosttarget, uint16_t port, uint16_t txt_len,
    const unsigned char * txt_record, void * context);
#if 0
static void frida_xpc_pairing_browser_backend_on_info_reply (DNSServiceRef sd_ref, DNSServiceFlags flags, uint32_t interface_index,
    DNSServiceErrorType error_code, const char * hostname, const struct sockaddr * address, uint32_t ttl, void * context);
#endif

void *
_frida_xpc_pairing_browser_create_backend (FridaXPCPairingBrowser * browser)
{
  FridaXPCPairingBrowserBackend * backend;

  backend = g_slice_new0 (FridaXPCPairingBrowserBackend);
  backend->browser = browser;
  backend->queue = dispatch_queue_create ("re.frida.fruity.queue", DISPATCH_QUEUE_SERIAL);
  backend->dns_sessions = g_ptr_array_new_with_free_func ((GDestroyNotify) DNSServiceRefDeallocate);
  g_queue_init (&backend->operations);

  dispatch_async (backend->queue, ^{ frida_xpc_pairing_browser_backend_start (backend); });

  return backend;
}

void
_frida_xpc_pairing_browser_destroy_backend (void * backend)
{
  FridaXPCPairingBrowserBackend * b = backend;

  dispatch_sync (b->queue, ^{ frida_xpc_pairing_browser_backend_stop (backend); });

  g_assert (g_queue_is_empty (&b->operations));
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
  if (DNSServiceBrowse (
        &browse_session,
        kDNSServiceFlagsPrivateFive | kDNSServiceFlagsShareConnection,
        0,
        FRIDA_REMOTE_XPC_PAIRING_REGTYPE,
        FRIDA_REMOTE_XPC_PAIRING_DOMAIN,
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
  gchar interface_name[IFNAMSIZ];
  FridaXPCPairingService * service;

  if (error_code != kDNSServiceErr_NoError || (flags & kDNSServiceFlagsAdd) == 0)
    return;

  if (if_indextoname (interface_index, interface_name) == NULL)
    return;

  service = g_object_new (FRIDA_XPC_TYPE_PAIRING_SERVICE,
      "name", service_name,
      "interface-index", interface_index,
      "interface-name", interface_name,
      NULL);
  g_object_set_data (G_OBJECT (service), "backend", self);

  _frida_xpc_pairing_browser_on_match (self->browser, service);

  g_object_unref (service);
}

static void
frida_xpc_pairing_browser_backend_schedule_resolve_operation (FridaXPCPairingBrowserBackend * self,
    FridaXPCPairingServiceResolveOperation * op)
{
  g_queue_push_tail (&self->operations, op);
  frida_xpc_pairing_browser_backend_maybe_perform_next_resolve_operation (self);
}

static void
frida_xpc_pairing_browser_backend_maybe_perform_next_resolve_operation (FridaXPCPairingBrowserBackend * self)
{
  FridaXPCPairingServiceResolveOperation * op;
  FridaXPCPairingService * service;
  DNSServiceRef session;
  DNSServiceErrorType res;

  if (self->operation_in_progress || g_queue_is_empty (&self->operations))
    return;

  self->operation_in_progress = TRUE;

  op = g_queue_peek_head (&self->operations);
  service = op->parent;

  session = self->dns_connection;
  res = DNSServiceResolve (
        &session,
        kDNSServiceFlagsPrivateFive | kDNSServiceFlagsShareConnection,
        frida_xpc_pairing_service_get_interface_index (service),
        frida_xpc_pairing_service_get_name (service),
        FRIDA_REMOTE_XPC_PAIRING_REGTYPE,
        FRIDA_REMOTE_XPC_PAIRING_DOMAIN,
        frida_xpc_pairing_browser_backend_on_resolve_reply,
        self);
  if (res == kDNSServiceErr_NoError)
  {
    g_ptr_array_add (self->dns_sessions, session);
  }
  else
  {
    frida_xpc_pairing_browser_backend_complete_resolve_operation (self,
        g_error_new (FRIDA_ERROR, FRIDA_ERROR_TRANSPORT, "Unable to resolve (%d)", res));
  }
}

static void
frida_xpc_pairing_browser_backend_complete_resolve_operation (FridaXPCPairingBrowserBackend * self, GError * error)
{
  FridaXPCPairingServiceResolveOperation * op;

  op = g_queue_pop_head (&self->operations);

  frida_xpc_pairing_service_resolve_operation_complete (op, self->browser->_main_context, error);

  if (error != NULL)
    g_error_free (error);

  self->operation_in_progress = FALSE;
  frida_xpc_pairing_browser_backend_maybe_perform_next_resolve_operation (self);
}

static void
frida_xpc_pairing_browser_backend_on_resolve_reply (DNSServiceRef sd_ref, DNSServiceFlags flags, uint32_t interface_index,
    DNSServiceErrorType error_code, const char * fullname, const char * hosttarget, uint16_t port, uint16_t txt_len,
    const unsigned char * txt_record, void * context)
{
  FridaXPCPairingBrowserBackend * self = context;
  FridaXPCPairingServiceResolveOperation * op;
  GBytes * txt_bytes;
  FridaXPCPairingServiceHost * host;

  op = g_queue_peek_head (&self->operations);

  if (error_code != kDNSServiceErr_NoError)
    goto propagate_error;

  txt_bytes = g_bytes_new (txt_record, txt_len);

  host = g_object_new (FRIDA_XPC_TYPE_PAIRING_SERVICE_HOST,
      "name", hosttarget,
      "port", GUINT16_FROM_BE (port),
      "txt-record", txt_bytes,
      NULL);

  gee_collection_add (GEE_COLLECTION (op->hosts), host);

  g_object_unref (host);
  g_bytes_unref (txt_bytes);

  if ((flags & kDNSServiceFlagsMoreComing) != 0)
    return;

  frida_xpc_pairing_browser_backend_complete_resolve_operation (self, NULL);

  goto end_session;

propagate_error:
  {
    frida_xpc_pairing_browser_backend_complete_resolve_operation (self,
        g_error_new (FRIDA_ERROR, FRIDA_ERROR_TRANSPORT, "Unable to resolve (%d)", error_code));
    goto end_session;
  }
end_session:
  {
    g_ptr_array_remove (self->dns_sessions, sd_ref);
  }
}

void
_frida_xpc_pairing_service_schedule_resolve (FridaXPCPairingService * self, FridaXPCPairingServiceResolveOperation * op)
{
  FridaXPCPairingBrowserBackend * backend;

  backend = g_object_get_data (G_OBJECT (self), "backend");

  dispatch_async (backend->queue, ^{ frida_xpc_pairing_browser_backend_schedule_resolve_operation (backend, op); });
}

#if 0
    DNSServiceRef info_session;
    info_session = self->dns_connection;
    if (DNSServiceGetAddrInfo (
        &info_session,
        kDNSServiceFlagsShareConnection,
        0,
        kDNSServiceProtocol_IPv6,
        hosttarget,
        frida_xpc_pairing_browser_backend_on_info_reply,
        service) == kDNSServiceErr_NoError)
    {
      g_ptr_array_add (self->dns_sessions, info_session);
    }
    else
    {
      g_object_unref (service);
    }

static void
frida_xpc_pairing_browser_backend_on_info_reply (DNSServiceRef sd_ref, DNSServiceFlags flags, uint32_t interface_index,
    DNSServiceErrorType error_code, const char * hostname, const struct sockaddr * address, uint32_t ttl, void * context)
{
  FridaXPCPairingService * service = context;
  FridaXPCPairingBrowserBackend * self;

  self = g_object_get_data (G_OBJECT (service), "backend");

  g_printerr ("hostname: %s ttl=%u\n", hostname, ttl);

  if (error_code == kDNSServiceErr_NoError)
  {
    GSocketAddress * addr;

    addr = g_native_socket_address_new ((gpointer) address, sizeof (struct sockaddr_in6));
    gee_collection_add (GEE_COLLECTION (frida_xpc_pairing_service_get_addresses (service)), addr);
    g_object_unref (addr);

    if ((flags & kDNSServiceFlagsMoreComing) != 0)
      return;

    _frida_xpc_pairing_browser_on_match (self->browser, service);
  }

  g_object_unref (service);
  g_ptr_array_remove (self->dns_sessions, sd_ref);
}

#endif
