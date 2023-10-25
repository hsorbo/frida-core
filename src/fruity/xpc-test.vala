namespace Frida.XPC {
	private const string TUNNEL_HOST = "[fde3:e0c9:1e2::1]";
	private const uint16 RSD_PORT = 55682;

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

			yield app_service.request (new ObjectBuilder ()
							.begin_dictionary ()
								.set_member_name ("CoreDevice.featureIdentifier")
								.add_string_value ("com.apple.coredevice.feature.listprocesses")
								.set_member_name ("CoreDevice.action")
								.begin_dictionary ()
								.end_dictionary ()
								.set_member_name ("CoreDevice.input")
								.add_null_value ()
								.set_member_name ("CoreDevice.invocationIdentifier")
								.add_string_value ("CF561B2E-9E2B-46C8-A666-53A0BDAEE2E6")
								.set_member_name ("CoreDevice.CoreDeviceDDIProtocolVersion")
								.add_int64_value (0)
								.set_member_name ("CoreDevice.coreDeviceVersion")
								.begin_dictionary ()
									.set_member_name ("originalComponentsCount")
									.add_int64_value (2)
									.set_member_name ("components")
									.begin_array ()
										.add_uint64_value (348)
										.add_uint64_value (1)
										.add_uint64_value (0)
										.add_uint64_value (0)
										.add_uint64_value (0)
									.end_array ()
									.set_member_name ("stringValue")
									.add_string_value ("348.1")
								.end_dictionary ()
								.set_member_name ("CoreDevice.deviceIdentifier")
								.add_string_value ("C82A9C33-EFC9-4290-B53E-BA796C333BF3")
							.end_dictionary ()
						.build ());

			yield;
		} catch (Error e) {
			printerr ("Unable to open RSDConnection: %s\n", e.message);
		} catch (IOError e) {
			assert_not_reached ();
		}
	}
}
