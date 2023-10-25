namespace Frida.XPC {
	private const string TUNNEL_HOST = "[fd41:537f:6137::1]";
	private const uint16 RSD_PORT = 55198;

	private int main (string[] args) {
		var loop = new MainLoop ();
		test_xpc.begin ();
		loop.run ();

		return 0;
	}

	private async void test_xpc () {
		try {
			var disco = yield DiscoveryService.open (new ServiceEndpoint (TUNNEL_HOST, RSD_PORT));

			ServiceEndpoint ep = disco.get_service ("com.apple.coredevice.appservice");
			printerr ("Got endpoint: %s\n", ep.to_string ());

			disco.close ();

			var app_service = yield AppService.open (ep);
			printerr ("Yay, got AppService!\n");

			yield;
		} catch (Error e) {
			printerr ("Unable to open RSDConnection: %s\n", e.message);
		} catch (IOError e) {
			assert_not_reached ();
		}
	}
}
