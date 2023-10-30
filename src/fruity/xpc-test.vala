namespace Frida.XPC {
	private const string TUNNEL_HOST = "[fddf:a718:85ed::1]";
	private const uint16 RSD_PORT = 63025;

	private Cancellable? cancellable = null;

	private int main (string[] args) {
		var loop = new MainLoop ();
		test_xpc.begin ();
		loop.run ();

		return 0;
	}

	private async void test_xpc () {
		try {
			PairingService[]? services = null;

			var browser = new PairingBrowser ();
			browser.services_discovered.connect (s => {
				printerr ("Found %u services\n", s.length);
				if (services == null) {
					services = s;
					test_xpc.callback ();
				}
			});
			yield;

			printerr ("\n=== Got:\n");
			foreach (var service in services) {
				printerr ("\t%s\n", service.to_string ());
				yield dump_service (service);
			}
			printerr ("\n");

			var disco = yield connect_to_first (services, cancellable);
			printerr ("Opened the disco: %p\n", disco);

			yield;
		} catch (Error e) {
			printerr ("%s\n", e.message);
		} catch (IOError e) {
			assert_not_reached ();
		}
	}

	private async DiscoveryService connect_to_first (PairingService[] services, Cancellable? cancellable) throws Error, IOError {
		foreach (PairingService service in services) {
			foreach (PairingServiceHost host in yield service.resolve (cancellable)) {
				foreach (InetSocketAddress address in yield host.resolve (cancellable)) {
					SocketConnection connection;
					try {
						printerr ("Trying %s -> %s -> %s\n", service.to_string (), host.to_string (),
							socket_address_to_string (address));
						printerr (" => %s\n", address.to_string ());

						NetworkAddress address_with_port = NetworkAddress.parse (
							"[%s]".printf (address.to_string ()), 58783);
						printerr (" => %s\n", address_with_port.to_string ());

						var client = new SocketClient ();
						connection = yield client.connect_async (address_with_port, cancellable);
					} catch (GLib.Error e) {
						printerr ("\tSkipping: %s\n", e.message);
						continue;
					}

					Tcp.enable_nodelay (connection.socket);

					try {
						return yield DiscoveryService.open (connection, cancellable);
					} catch (Error e) {
						printerr ("\tSkipping: %s\n", e.message);
						continue;
					}
				}
			}
		}
		throw new Error.TRANSPORT ("Unable to connect to any of the services");
	}

	private async void dump_service (PairingService service) {
		try {
			var hosts = yield service.resolve (cancellable);
			uint i = 0;
			foreach (var host in hosts) {
				printerr ("\t\thosts[%u]: %s\n", i, host.to_string ());
				var addresses = yield host.resolve (cancellable);
				uint j = 0;
				foreach (var addr in addresses) {
					printerr ("\t\t\taddresses[%u]: %s\n", j, socket_address_to_string (addr));
					j++;
				}
				i++;
			}
		} catch (Error e) {
			printerr ("%s\n", e.message);
		} catch (IOError e) {
			assert_not_reached ();
		}
	}

	private string socket_address_to_string (SocketAddress addr) {
		var native_size = addr.get_native_size ();
		var native = new uint8[native_size];
		try {
			addr.to_native (native, native_size);
		} catch (GLib.Error e) {
			assert_not_reached ();
		}

		var desc = new StringBuilder.sized (32);
		for (uint j = 0; j != 16; j += 2) {
			if (desc.len != 0)
				desc.append_c (':');
			uint8 b1 = native[8 + j];
			uint8 b2 = native[8 + j + 1];
			bool all_zeroes = b1 == 0 && b2 == 0;
			if (desc.len == 0 || !all_zeroes)
				desc.append_printf ("%02x%02x", b1, b2);
		}

		var scope_id = (uint32 *) ((uint8 *) native + 8 + 16);

		return "(%s, scope_id: %u)".printf (desc.str, *scope_id);
	}

#if 0
	private async void test_xpc () {
		try {
			var disco = yield DiscoveryService.open (new Endpoint (TUNNEL_HOST, RSD_PORT));
			Endpoint ep = disco.get_service ("com.apple.coredevice.appservice");
			disco.close ();

			var app_service = yield AppService.open (ep);

			printerr ("=== Applications\n");
			foreach (ApplicationInfo app in yield app_service.enumerate_applications ()) {
				printerr ("%s\n", app.to_string ());
			}

			printerr ("\n=== Processes\n");
			foreach (ProcessInfo p in yield app_service.enumerate_processes ()) {
				printerr ("%s\n", p.to_string ());
			}

			yield;
		} catch (Error e) {
			printerr ("%s\n", e.message);
		} catch (IOError e) {
			assert_not_reached ();
		}
	}
#endif
}
