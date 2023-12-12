namespace Frida.Fruity.XPC {
	private const string TUNNEL_HOST = "[fddf:a718:85ed::1]";
	private const uint16 RSD_PORT = 63025;

	private Cancellable? cancellable = null;

	private int main (string[] args) {
		Frida.init_with_runtime (GLIB);

		var loop = new MainLoop (Frida.get_main_context ());
		test_darwin_device_monitor.begin ();
		//test_wifi_xpc.begin ();
		//test_indirect_xpc.begin ();
		//test_direct_xpc.begin ();
		loop.run ();

		return 0;
	}

	private async void test_darwin_device_monitor () {
		var monitor = new DarwinDeviceMonitor ();
	}

	private async void test_wifi_xpc () {
		try {
			string device_address = "fdc1:9325:7cb8:4511:49:2e2e:99e8:aa72";

			var pairing_service_address = new InetSocketAddress.from_string (device_address, 49152);

			var client = new SocketClient ();
			var connection = yield client.connect_async (pairing_service_address, cancellable);
			var pairing_service = yield PairingService.open (new PlainPairingTransport (connection), cancellable);

			TunnelConnection tunnel = yield pairing_service.open_tunnel (device_address, cancellable);

			var disco = yield DiscoveryService.open (
				yield tunnel.open_connection (tunnel.remote_rsd_port, cancellable),
				cancellable);

			var app_service = yield AppService.open (
				yield tunnel.open_connection (disco.get_service ("com.apple.coredevice.appservice").port, cancellable),
				cancellable);

			printerr ("=== Applications\n");
			foreach (AppService.ApplicationInfo app in yield app_service.enumerate_applications ()) {
				printerr ("%s\n", app.to_string ());
			}

			printerr ("\n=== Processes\n");
			foreach (AppService.ProcessInfo p in yield app_service.enumerate_processes ()) {
				printerr ("%s\n", p.to_string ());
			}

			printerr ("\n\n=== Yay. Sleeping indefinitely.\n");
			yield;
		} catch (GLib.Error e) {
			printerr ("Oh noes: %s\n", e.message);
		}
	}

	private async void test_indirect_xpc () {
		try {
			var device_id_request = new Promise<DeviceId?> ();

			var usbmux = yield UsbmuxClient.open (cancellable);
			usbmux.device_attached.connect (d => {
				if (!device_id_request.future.ready)
					device_id_request.resolve (d.id);
			});
			yield usbmux.enable_listen_mode (cancellable);

			DeviceId id = yield device_id_request.future.wait_async (cancellable);

			yield usbmux.close (cancellable);

			usbmux = yield UsbmuxClient.open (cancellable);
			yield usbmux.connect_to_port (id, 49152, cancellable);

			var pairing_transport = new XpcPairingTransport (usbmux.connection);
			var pairing_service = yield PairingService.open (pairing_transport, cancellable);
		} catch (GLib.Error e) {
			printerr ("Oh noes: %s\n", e.message);
		}
	}

	private async void test_direct_xpc () {
		try {
			PairingServiceDetails[]? services = null;

			var browser = PairingBrowser.make_default ();
			browser.services_discovered.connect (s => {
				printerr ("Found %u services\n", s.length);
				if (services == null) {
					services = s;
					test_direct_xpc.callback ();
				}
			});
			yield;

			//printerr ("\n=== Got:\n");
			//foreach (var service in services) {
			//	printerr ("\t%s\n", service.to_string ());
			//	yield dump_service (service);
			//}
			//printerr ("\n");

			Device device = yield pick_device (services, cancellable);

			var pairing_transport = new XpcPairingTransport (
				yield device.open_service ("com.apple.internal.dt.coredevice.untrusted.tunnelservice", cancellable));

			var pairing_service = yield PairingService.open (pairing_transport, cancellable);

			TunnelConnection tunnel = yield pairing_service.open_tunnel (device.address, cancellable);

			var disco = yield DiscoveryService.open (
				yield tunnel.open_connection (tunnel.remote_rsd_port, cancellable),
				cancellable);

			var app_service = yield AppService.open (
				yield tunnel.open_connection (disco.get_service ("com.apple.coredevice.appservice").port, cancellable),
				cancellable);

			printerr ("=== Applications\n");
			foreach (AppService.ApplicationInfo app in yield app_service.enumerate_applications ()) {
				printerr ("%s\n", app.to_string ());
			}

			printerr ("\n=== Processes\n");
			foreach (AppService.ProcessInfo p in yield app_service.enumerate_processes ()) {
				printerr ("%s\n", p.to_string ());
			}

			printerr ("\n\n=== Yay. Sleeping indefinitely.\n");
			yield;
		} catch (Error e) {
			printerr ("Oh noes: %s\n", e.message);
		} catch (IOError e) {
			assert_not_reached ();
		}
	}

	private async Device pick_device (PairingServiceDetails[] services, Cancellable? cancellable) throws Error, IOError {
		foreach (PairingServiceDetails service in services) {
			foreach (PairingServiceHost host in yield service.resolve (cancellable)) {
				if (!("iPad" in host.name)) {
					printerr ("Skipping: %s\n", host.to_string ());
					continue;
				}

				foreach (InetSocketAddress socket_address in yield host.resolve (cancellable)) {
					string candidate_address = socket_address_to_string (socket_address) + "%" + service.interface_name;

					SocketConnection connection;
					try {
						printerr ("Trying %s -> %s\n", service.to_string (), host.to_string ());
						printerr ("\t(i.e., candidate_address: %s)\n", candidate_address);

						InetSocketAddress? disco_address = new InetSocketAddress.from_string (candidate_address, 58783);
						if (disco_address == null) {
							printerr ("\tSkipping due to invalid address\n");
							continue;
						}

						var client = new SocketClient ();
						connection = yield client.connect_async (disco_address, cancellable);
					} catch (GLib.Error e) {
						printerr ("\tSkipping: %s\n", e.message);
						continue;
					}

					Tcp.enable_nodelay (connection.socket);

					try {
						var disco = yield DiscoveryService.open (connection, cancellable);

						printerr ("Connected through interface %s\n", service.interface_name);

						return new Device () {
							address = candidate_address,
							disco = disco,
						};
					} catch (Error e) {
						printerr ("\tSkipping: %s\n", e.message);
						continue;
					}
				}
			}
		}
		throw new Error.TRANSPORT ("Unable to connect to any of the services");
	}

	private class Device {
		public string address;
		public DiscoveryService disco;

		public async SocketConnection open_service (string service_name, Cancellable? cancellable) throws Error, IOError {
			SocketConnection connection;
			try {
				ServiceInfo service_info = disco.get_service (service_name);
				NetworkAddress service_address = NetworkAddress.parse (address, service_info.port);

				var client = new SocketClient ();
				connection = yield client.connect_async (service_address, cancellable);
			} catch (GLib.Error e) {
				throw new Error.TRANSPORT ("%s", e.message);
			}

			Tcp.enable_nodelay (connection.socket);

			return connection;
		}
	}

	private async void dump_service (PairingServiceDetails service) {
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
			desc.append_printf ("%02x%02x", b1, b2);
		}

		//var scope_id = (uint32 *) ((uint8 *) native + 8 + 16);

		return desc.str;
	}
}
