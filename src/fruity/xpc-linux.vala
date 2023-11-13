[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity.XPC {
	public class LinuxPairingBrowser : Object, PairingBrowser {
		private DBusConnection connection;
		private AvahiServer server;
		private AvahiServiceBrowser browser;

		private Gee.List<PairingService> current_batch = new Gee.ArrayList<PairingService> ();

		private Cancellable io_cancellable = new Cancellable ();

		construct {
			start.begin ();
		}

		private async void start () {
			try {
				connection = yield GLib.Bus.get (BusType.SYSTEM, io_cancellable);

				server = yield connection.get_proxy (AVAHI_SERVICE_NAME, "/", DO_NOT_LOAD_PROPERTIES, io_cancellable);

				GLib.ObjectPath browser_path = yield server.service_browser_new (-1, INET6, PAIRING_REGTYPE, PAIRING_DOMAIN,
					0, io_cancellable);
				browser = yield connection.get_proxy (AVAHI_SERVICE_NAME, browser_path, DO_NOT_LOAD_PROPERTIES,
					io_cancellable);
				browser.item_new.connect (on_item_new);
				browser.all_for_now.connect (on_all_for_now);
				yield browser.start (io_cancellable);
				printerr ("Browser started!\n");
			} catch (GLib.Error e) {
				printerr ("Oopsie: %s\n", e.message);
			}
		}

		private void on_item_new (int interface_index, AvahiProtocol protocol, string name, string type, string domain, uint flags) {
			printerr ("item_new: interface_index=%d protocol=%s name=\"%s\" type=\"%s\" domain=\"%s\" flags=%u\n",
				interface_index,
				protocol.to_string (),
				name,
				type,
				domain,
				flags);
			current_batch.add (new LinuxPairingService (name, interface_index, "FIXME", server));
		}

		private void on_all_for_now () {
			services_discovered (current_batch.to_array ());
			current_batch.clear ();
		}
	}

	private class LinuxPairingService : Object, PairingService {
		public string name {
			get;
			construct;
		}

		public uint interface_index {
			get;
			construct;
		}

		public string interface_name {
			get;
			construct;
		}

		private AvahiServer server;

		internal LinuxPairingService (string name, uint interface_index, string interface_name, AvahiServer server) {
			Object (
				name: name,
				interface_index: interface_index,
				interface_name: interface_name
			);
			this.server = server;
		}

		public async Gee.List<PairingServiceHost> resolve (Cancellable? cancellable) throws Error, IOError {
			AvahiServiceResolver resolver;
			try {
				printerr ("Creating resolver for name=\"%s\" regtype=\"%s\" domain=\"%s\"\n", name, PAIRING_REGTYPE,
					PAIRING_DOMAIN);
				GLib.ObjectPath path = yield server.service_resolver_new ((int) interface_index, INET6, name,
					PAIRING_REGTYPE, PAIRING_DOMAIN, INET6, 0, cancellable);
				DBusConnection connection = ((DBusProxy) server).get_connection ();
				resolver = yield connection.get_proxy (AVAHI_SERVICE_NAME, path, DO_NOT_LOAD_PROPERTIES, cancellable);
			} catch (GLib.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}

			var promise = new Promise<Gee.List<PairingServiceHost>> ();
			var hosts = new Gee.ArrayList<PairingServiceHost> ();
			resolver.found.connect ((interface_index, protocol, name, type, domain, host, address_protocol, address, port, txt, flags) => {
				printerr ("found! address=\"%s\"\n", address);
				printerr ("on resolver: %p\n", resolver);
				hosts.add (new LinuxPairingServiceHost (
					host,
					new InetSocketAddress.from_string (address, port),
					port,
					new Bytes ({})));
				if (!promise.future.ready)
					promise.resolve (hosts);
			});
			resolver.failure.connect (error => {
				printerr ("failure: %s\n", error);
				if (!promise.future.ready)
					promise.reject (new Error.NOT_SUPPORTED ("%s", error));
			});

			try {
				printerr (">>> start()\n");
				yield resolver.start (cancellable);
				printerr ("<<< start()\n");
			} catch (GLib.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}

			try {
				printerr (">>> wait_async()\n");
				var x = yield promise.future.wait_async (cancellable);
				printerr ("<<< wait_async()\n");
				return x;
			} catch (GLib.Error e) {
				printerr ("!!! wait_async(): %s\n", e.message);
				throw_api_error (e);
			}
		}
	}

	public class LinuxPairingServiceHost : Object, PairingServiceHost {
		public string name {
			get;
			construct;
		}

		public InetSocketAddress address {
			get;
			construct;
		}

		public uint16 port {
			get;
			construct;
		}

		public Bytes txt_record {
			get;
			construct;
		}

		internal LinuxPairingServiceHost (string name, InetSocketAddress address, uint16 port, Bytes txt_record) {
			Object (
				name: name,
				address: address,
				port: port,
				txt_record: txt_record
			);
		}

		public async Gee.List<InetSocketAddress> resolve (Cancellable? cancellable) throws Error, IOError {
			var result = new Gee.ArrayList<InetSocketAddress> ();
			result.add (address);
			return result;
		}
	}

	private const string AVAHI_SERVICE_NAME = "org.freedesktop.Avahi";

	[DBus (name = "org.freedesktop.Avahi.Server")]
	private interface AvahiServer : Object {
		public abstract async GLib.ObjectPath service_browser_new (int interface_index, AvahiProtocol protocol, string type,
			string domain, uint flags, Cancellable? cancellable) throws GLib.Error;
		public abstract async GLib.ObjectPath service_resolver_new (int interface_index, AvahiProtocol protocol, string name,
			string type, string domain, AvahiProtocol aprotocol, uint flags, Cancellable? cancellable) throws GLib.Error;
	}

	[DBus (name = "org.freedesktop.Avahi.ServiceBrowser")]
	private interface AvahiServiceBrowser : Object {
		public signal void item_new (int interface_index, AvahiProtocol protocol, string name, string type, string domain,
			uint flags);
		public signal void item_remove (int interface_index, AvahiProtocol protocol, string name, string type, string domain,
			uint flags);
		public signal void failure (string error);
		public signal void all_for_now ();
		public signal void cache_exhausted ();

		public abstract async void start (Cancellable? cancellable) throws GLib.Error;
		public abstract async void free (Cancellable? cancellable) throws GLib.Error;
	}

	[DBus (name = "org.freedesktop.Avahi.ServiceResolver")]
	private interface AvahiServiceResolver : Object {
		public signal void found (int interface_index, AvahiProtocol protocol, string name, string type, string domain, string host,
			AvahiProtocol address_protocol, string address, uint16 port, [DBus (signature = "aay")] Variant txt, uint flags);
		public signal void failure (string error);

		public abstract async void start (Cancellable? cancellable) throws GLib.Error;
		public abstract async void free (Cancellable? cancellable) throws GLib.Error;
	}

	private enum AvahiProtocol {
		INET,
		INET6,
		UNSPEC = -1,
	}
}
