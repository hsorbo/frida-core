namespace Frida.XPC {
	private const string TUNNEL_HOST = "[fd67:45ee:e98d::1]";
	private const uint16 RSD_PORT = 62700;

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
			yield app_service.list_processes ();

			yield;
		} catch (Error e) {
			printerr ("Unable to open RSDConnection: %s\n", e.message);
		} catch (IOError e) {
			assert_not_reached ();
		}
	}
}
