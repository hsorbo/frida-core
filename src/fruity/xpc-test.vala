namespace Frida.XPC {
	private const string TUNNEL_HOST = "[fdbb:bdc1:aacb::1]";
	private const uint16 RSD_PORT = 62781;

	private int main (string[] args) {
		var loop = new MainLoop ();
		test_xpc.begin ();
		loop.run ();

		return 0;
	}

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
}
