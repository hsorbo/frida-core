[CCode (gir_namespace = "FridaXPC", gir_version = "1.0")]
namespace Frida.XPC {
#if TEST
	private async void test_xpc () {
		Cancellable? cancellable = null;

		try {
			var usbmux = yield Fruity.UsbmuxClient.open (cancellable);
			Fruity.DeviceDetails? device = null;
			usbmux.device_attached.connect (d => {
				if (device == null) {
					device = d;
					test_xpc.callback ();
				}
			});
			yield usbmux.enable_listen_mode (cancellable);
			while (device == null)
				yield;
			yield usbmux.close (cancellable);

			printerr ("Using device: %s\n", device.udid.raw_value);

			usbmux = yield Fruity.UsbmuxClient.open (cancellable);
			yield usbmux.connect_to_port (device.id, 58783, cancellable);

			printerr ("Connected!\n");
		} catch (GLib.Error e) {
			printerr ("%s\n", e.message);
			Process.exit (1);
		}
	}

	private int main (string[] args) {
		var loop = new MainLoop ();
		test_xpc.begin ();
		loop.run ();
		return 0;
	}
#endif
}
