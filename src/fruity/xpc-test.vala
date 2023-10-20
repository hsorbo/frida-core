namespace Frida.XPC {
	private int main (string[] args) {
		var loop = new MainLoop ();
		test_xpc.begin ();
		loop.run ();

		return 0;
	}

	private async void test_xpc () {
		var conn = new ServiceConnection ("[fd6b:2cfe:ec6d::1]", 52488);
		init_connection.begin (conn);

		yield;
	}

	private async void init_connection (ServiceConnection conn) {
		try {
			yield conn.init_async (Priority.DEFAULT, null);

			/*
			var source = new TimeoutSource (2000);
			source.set_callback (() => {
				init_connection.callback ();
				return Source.REMOVE;
			});
			source.attach (MainContext.get_thread_default ());
			printerr ("Before sleep\n");
			yield;
			printerr ("After sleep\n");
			*/

			uint32 flags = 0x1; // TODO
			uint64 msg_id = 0;
			Bytes request = new RequestBuilder (flags, msg_id)
				.begin_dictionary ()
				.end_dictionary ()
				.build ();

			FileUtils.set_data ("/Users/oleavr/request.bin", request.get_data ());

			yield conn.submit_data (request);
		} catch (GLib.Error e) {
			printerr ("Oops: %s\n", e.message);
		}
	}
}
