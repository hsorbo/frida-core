[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity.XPC {
	public class LinuxPairingBrowser : Object, PairingBrowser {
		private AvahiServer server;
		private AvahiServiceBrowser browser;

		private Gee.List<PairingService> current_batch = new Gee.ArrayList<PairingService> ();

		private Cancellable io_cancellable = new Cancellable ();

		private const string AVAHI_SERVICE_NAME = "org.freedesktop.Avahi";

		construct {
			start.begin ();
		}

		private async void start () {
			try {
				DBusConnection connection = yield GLib.Bus.get (BusType.SYSTEM, io_cancellable);

				server = yield connection.get_proxy (AVAHI_SERVICE_NAME, "/", DO_NOT_LOAD_PROPERTIES, io_cancellable);

				GLib.ObjectPath browser_path = yield server.service_browser_new (-1, -1, PAIRING_REGTYPE, PAIRING_DOMAIN, 0);
				browser = yield connection.get_proxy (AVAHI_SERVICE_NAME, browser_path, DO_NOT_LOAD_PROPERTIES,
					io_cancellable);
				browser.item_new.connect (on_item_new);
				browser.all_for_now.connect (on_all_for_now);
				yield browser.start ();
				printerr ("Browser started!\n");
			} catch (GLib.Error e) {
				printerr ("Oopsie: %s\n", e.message);
			}
		}

		private void on_item_new (int iface, int protocol, string name, string type, string domain, uint flags) {
			printerr ("item_new: iface=%d protocol=%d name=\"%s\" type\"%s\" domain=\"%s\" flags=%u\n",
				iface,
				protocol,
				name,
				type,
				domain,
				flags);
			current_batch.add (new LinuxPairingService (name, iface, "FIXME"));
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

		public LinuxPairingService (string name, uint interface_index, string interface_name) {
			Object (
				name: name,
				interface_index: interface_index,
				interface_name: interface_name
			);
		}

		public async Gee.List<PairingServiceHost> resolve (Cancellable? cancellable) throws Error, IOError {
			return new Gee.ArrayList<PairingServiceHost> ();
		}
	}

	[DBus (name = "org.freedesktop.Avahi.Server")]
	private interface AvahiServer : Object {
		public abstract async GLib.ObjectPath service_browser_new (int iface, int protocol, string type, string domain, uint flags) throws GLib.Error;
	}

	[DBus (name = "org.freedesktop.Avahi.ServiceBrowser")]
	private interface AvahiServiceBrowser : Object {
		public signal void item_new (int iface, int protocol, string name, string type, string domain, uint flags);
		public signal void item_remove (int iface, int protocol, string name, string type, string domain, uint flags);
		public signal void failure (string error);
		public signal void all_for_now ();
		public signal void cache_exhausted ();

		public abstract async void start () throws GLib.Error;
		public abstract async void free () throws GLib.Error;
	}
}
