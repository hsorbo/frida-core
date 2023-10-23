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

			printerr ("Test finished... Running forever\n");
			yield;
			printerr ("Should not get here\n");

		} catch (GLib.Error e) {
			printerr ("init_connection() failed: %s\n", e.message);
		}
	}
}
