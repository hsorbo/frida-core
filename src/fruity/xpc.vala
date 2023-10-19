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

		public Nghttp2.Session session;

		private bool is_processing_messages;

		public ServiceConnection (string host, uint16 port) {
			Object (host: host, port: port);
		}

		construct {
			Nghttp2.SessionCallbacks callbacks;
			Nghttp2.SessionCallbacks.make (out callbacks);
			callbacks.set_send_callback (on_send);

			Nghttp2.Session.make_client (out session, callbacks, this);
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

		private async void submit_data (int stream_id, Bytes bytes) throws Error, IOError {
		}

		private async void process_incoming_messages () {
			while (is_processing_messages) {
				try {
					var buffer = new uint8[4096];

					ssize_t n = yield input.read_async (buffer, Priority.DEFAULT, io_cancellable);
					printerr ("read_async() => %zd\n", n);
					if (n == 0) {
						printerr ("EOF!\n");
						is_processing_messages = false;
						continue;
					}

					ssize_t result = session.mem_recv (buffer[:n]);
					if (result < 0)
						throw new Error.PROTOCOL ("%s", Nghttp2.strerror (result));
				} catch (GLib.Error e) {
					printerr ("Oops: %s\n", e.message);
					is_processing_messages = false;
				}
			}
		}

		private static ssize_t on_send (Nghttp2.Session session, uint8[] data, int flags, void * user_data) {
			printerr ("on_send() data.length=%zu\n", data.length);
			return data.length;
		}
	}
}
