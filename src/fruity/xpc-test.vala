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
			browser.service_discovered.connect ((service) => {
				printerr ("Found: %s\n", service.to_string ());
				dump_service.begin (service);
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
				i++;
			}
		} catch (Error e) {
			printerr ("[%p] %s\n", service, e.message);
		} catch (IOError e) {
			assert_not_reached ();
		}
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
