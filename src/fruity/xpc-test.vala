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
			Endpoint? disco_ep = null;
			var browser = new PairingBrowser ();
			browser.services_discovered.connect ((services) => {
				printerr ("Found %u services\n", services.length);
				foreach (var service in services) {
					printerr ("\t%s\n", service.to_string ());
					dump_service.begin (service);
				}
				/*
				if (disco_ep == null && service.host.has_prefix ("OA.")) {
					disco_ep = new Endpoint (service.host, 58783);
					test_xpc.callback ();
				}
				*/
			});
			yield;

			printerr ("Got to the disco_ep: %s\n", disco_ep.to_string ());
			var disco = yield DiscoveryService.open (disco_ep, cancellable);
			printerr ("Got disco! %p\n", disco);
		} catch (Error e) {
			printerr ("%s\n", e.message);
		} catch (IOError e) {
			assert_not_reached ();
		}
	}

	private async void dump_service (PairingService service) {
		try {
			printerr ("[%p] dump_service()\n", service);
			var hosts = yield service.resolve (cancellable);
			printerr ("[%p] Got %u hosts\n", service, hosts.size);
			uint i = 0;
			foreach (var host in hosts) {
				printerr ("[%p]\thosts[%u]: %s\n", service, i, host.to_string ());
				var addresses = yield host.resolve (cancellable);
				uint j = 0;
				foreach (var addr in addresses) {
					printerr ("[%p]\t\taddresses[%u]: %s\n", service, j, socket_address_to_string (addr));
					j++;
				}
				i++;
			}
		} catch (Error e) {
			printerr ("[%p] %s\n", service, e.message);
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
			uint8 b1 = native[8 + j];
			uint8 b2 = native[8 + j + 1];
			if (desc.len == 0 || (b1 != 0 || b2 != 0)) {
				if (desc.len != 0)
					desc.append_c (':');
				desc.append_printf ("%02x%02x", b1, b2);
			}
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
