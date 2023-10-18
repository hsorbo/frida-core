[CCode (gir_namespace = "FridaXPC", gir_version = "1.0")]
namespace Frida.XPC {
	public class PairingBrowser : Object {
		public signal void service_discovered (string name, string host, uint16 port, Bytes txt_record);

		public void * _backend;

		construct {
			_backend = _create_backend (this);
		}

		~PairingBrowser () {
			_destroy_backend (_backend);
		}

		public void _on_match (string name, string host, uint16 port, Bytes txt_record) {
			service_discovered (name, host, port, txt_record);
		}

		public extern static void * _create_backend (PairingBrowser browser);
		public extern static void _destroy_backend (void * backend);
	}

	public class ServiceConnection : Object, AsyncInitable {
		public string host {
			get;
			construct;
		}

		public uint16 port {
			get;
			construct;
		}

		private SocketConnection connection;
		private InputStream input;
		private OutputStream output;
		private Cancellable io_cancellable = new Cancellable ();

		public void * session;

		private bool is_processing_messages;

		public ServiceConnection (string host, uint16 port) {
			Object (host: host, port: port);
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			try {
				var connectable = NetworkAddress.parse (host, port);

				var client = new SocketClient ();
				connection = yield client.connect_async (connectable, cancellable);

				printerr ("Connected to %s:%u\n", host, port);

				Tcp.enable_nodelay (connection.socket);

				input = connection.get_input_stream ();
				output = connection.get_output_stream ();

				is_processing_messages = true;

				process_incoming_messages.begin ();
			} catch (GLib.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}

			return true;
		}

		private async void process_incoming_messages () {
			_create_session ();

			while (is_processing_messages) {
				try {
					var buffer = new uint8[4096];

					ssize_t n = yield input.read_async (buffer, Priority.DEFAULT, io_cancellable);
					printerr ("read_async() => %zd\n", n);
					if (n == 0) {
						is_processing_messages = false;
						continue;
					}

					_on_recv (buffer[:n]);
				} catch (GLib.Error e) {
					printerr ("Oops: %s\n", e.message);
					is_processing_messages = false;
				}
			}

			_destroy_session ();
		}

		public extern void _create_session ();
		public extern void _destroy_session ();
		public extern void _on_recv (uint8[] data) throws Error;
	}

#if TEST
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
		} catch (GLib.Error e) {
			printerr ("Oops: %s\n", e.message);
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
