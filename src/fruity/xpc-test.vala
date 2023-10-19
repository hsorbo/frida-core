namespace Frida.XPC {
	private int main (string[] args) {
		var loop = new MainLoop ();
		test_xpc.begin ();
		loop.run ();

		return 0;
	}

	private async void test_xpc () {
		var connections = new Gee.HashMap<string, ServiceConnection> ();

		var browser = new PairingBrowser ();
		browser.service_discovered.connect ((name, host, port, txt_record) => {
			if (connections.has_key (name))
				return;

			printerr ("[*] service_discovered\n\tname=\"%s\"\n\thost=\"%s\"\n\tport=%u\n", name, host, port);
			var conn = new ServiceConnection (host, port);
			connections[name] = conn;
			init_connection.begin (conn);
		});

		yield;
	}

	private async void init_connection (ServiceConnection conn) {
		try {
			yield conn.init_async (Priority.DEFAULT, null);

			/*
			uint32 flags = 0x1; // TODO
			uint64 msg_id = 0;
			Bytes request = new RequestBuilder (flags, msg_id)
				.begin_dictionary ()
				.end_dictionary ()
				.build ();

			FileUtils.set_data ("/Users/oleavr/request.bin", request.get_data ());

			yield conn.submit_data (1, request);
			*/
		} catch (GLib.Error e) {
			printerr ("Oops: %s\n", e.message);
		}
	}
}
