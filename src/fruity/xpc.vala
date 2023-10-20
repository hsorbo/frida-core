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

		public NGHttp2.Session session;

		private bool is_processing_messages;

		private ByteArray? send_queue;
		private Source? send_source;

		public ServiceConnection (string host, uint16 port) {
			Object (host: host, port: port);
		}

		construct {
			NGHttp2.SessionCallbacks callbacks;
			NGHttp2.SessionCallbacks.make (out callbacks);

			// callbacks.set_before_frame_send_callback (on_before_frame_send);
			// callbacks.set_on_header_callback (on_header);
			// callbacks.set_on_begin_headers_callback (on_begin_headers);
			// callbacks.set_on_frame_recv_callback (on_frame_recv);
			// callbacks.set_on_data_chunk_recv_callback (on_data_chunk_recv);
			// callbacks.set_on_frame_send_callback (on_frame_send);
			// callbacks.set_send_data_callback (on_send_data);
			// callbacks.set_on_frame_not_send_callback (on_frame_not_send);
			// callbacks.set_on_invalid_frame_recv_callback (on_invalid_frame_recv);

			/* nghttp2.h:2158 */ callbacks.set_send_callback (on_send_wrapper);
			/* nghttp2.h:2237 */ callbacks.set_on_stream_close_callback (on_stream_close);
			/* nghttp2.h:2396 */ callbacks.set_error_callback (on_error);

			NGHttp2.Option option;
			NGHttp2.Option.make (out option);
			option.set_no_auto_window_update (true);
			option.set_peer_max_concurrent_streams (100);
			option.set_no_http_messaging (true);
			// option.set_no_http_semantics (true);
			option.set_no_closed_streams (true);

			NGHttp2.ClientSession.make (out session, callbacks, this, option);
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			try {
				var connectable = NetworkAddress.parse (host, port);

				var client = new SocketClient ();
				printerr ("Connecting to %s:%u...\n", host, port);
				connection = yield client.connect_async (connectable, cancellable);

				printerr ("Connected to %s:%u\n", host, port);

				Tcp.enable_nodelay (connection.socket);

				input = connection.get_input_stream ();
				output = connection.get_output_stream ();

				is_processing_messages = true;

				process_incoming_messages.begin ();

				int result = session.submit_settings (NGHttp2.Flag.NONE, {
					{ MAX_CONCURRENT_STREAMS, 100 },
					{ INITIAL_WINDOW_SIZE, 1048576 },
				});
				printerr ("submit_settings() => %d\n", result);

				result = session.set_local_window_size (NGHttp2.Flag.NONE, 0, 1048576);
				printerr ("set_local_window_size() => %d\n", result);

				//int32 reply_stream_id = session.submit_headers (NGHttp2.Flag.NONE, -1, null, {}, null);
				//printerr ("submit_headers() => reply_stream_id=%d\n", reply_stream_id);

				maybe_send_pending ();
			} catch (GLib.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}

			return true;
		}

		private void maybe_send_pending () {
			printerr ("[maybe_send_pending] >>>\n");
			while (session.want_write ()) {
				bool would_block = send_source != null && send_queue == null;
				if (would_block) {
					printerr ("[maybe_send_pending] would_block, so not doing anything\n");
					break;
				}

				printerr ("[maybe_send_pending] calling send()\n");
				int result = session.send ();
				printerr ("[maybe_send_pending] send() => %d\n", result);
			}
			printerr ("[maybe_send_pending] <<<\n");
		}

		public async void submit_data (Bytes bytes) throws Error, IOError {
			int32 stream_id = session.submit_headers (NGHttp2.Flag.NONE, -1, null, {}, null);
			printerr ("submit_headers() => stream_id=%d\n", stream_id);

			maybe_send_pending ();

			var op = new SubmitOperation (bytes, submit_data.callback);

			var data_prd = NGHttp2.DataProvider ();
			data_prd.source.ptr = op;
			data_prd.read_callback = on_data_provider_read;
			printerr (">>>\n");
			int result = session.submit_data (NGHttp2.DataFlag.NO_END_STREAM, stream_id, data_prd);
			printerr ("<<< yay, result=%d\n", result);
			if (result < 0)
				throw new Error.PROTOCOL ("%s", NGHttp2.strerror (result));

			while (op.cursor != bytes.get_size ()) {
				printerr (">>> yield\n");
				yield;
				printerr ("<<< yield\n");
			}
		}

		private static ssize_t on_data_provider_read (NGHttp2.Session session, int32 stream_id, uint8[] buf, ref uint32 data_flags,
				NGHttp2.DataSource source, void * user_data) {
			var op = (SubmitOperation) source.ptr;

			unowned uint8[] data = op.bytes.get_data ();
			printerr ("\t[*] on_data_provider_read() cursor=%u buf.length=%zu data.length=%d\n", op.cursor, buf.length, data.length);

			uint remaining = data.length - op.cursor;
			if (remaining == 0) {
				data_flags |= NGHttp2.DataFlag.EOF;
				op.callback ();
				return 0;
			}

			uint n = uint.min (remaining, buf.length);
			Memory.copy (buf, (uint8 *) data + op.cursor, n);
			printerr ("\t\t=> n=%u\n", n);

			op.cursor += n;

			return n;
		}

		private class SubmitOperation {
			public Bytes bytes;
			public SourceFunc callback;

			public uint cursor = 0;

			public SubmitOperation (Bytes bytes, owned SourceFunc callback) {
				this.bytes = bytes;
				this.callback = (owned) callback;
			}
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

					hexdump (buffer[:n]);

					ssize_t result = session.mem_recv (buffer[:n]);
					if (result < 0)
						throw new Error.PROTOCOL ("%s", NGHttp2.strerror (result));

					session.consume_connection (n);
				} catch (GLib.Error e) {
					printerr ("Oops: %s\n", e.message);
					is_processing_messages = false;
				}
			}
		}

		private static ssize_t on_send_wrapper (NGHttp2.Session session, [CCode (array_length_type = "size_t")] uint8[] data,
				int flags, void * user_data) {
			ServiceConnection * self = user_data;
			return self->on_send (data, flags);
		}

		private ssize_t on_send (uint8[] data, int flags) {
			printerr ("on_send() data.length=%zu flags=0x%x\n", data.length, flags);

			if (send_source == null) {
				send_queue = new ByteArray.sized (1024);

				var source = new IdleSource ();
				source.set_callback (() => {
					do_send.begin ();
					return Source.REMOVE;
				});
				source.attach (MainContext.get_thread_default ());
				send_source = source;
			}

			if (send_queue == null)
				return NGHttp2.ErrorCode.WOULDBLOCK;

			send_queue.append (data);
			return data.length;
		}

		private async void do_send () {
			uint8[] buffer = send_queue.steal ();
			send_queue = null;

			try {
				size_t bytes_written;
				yield output.write_all_async (buffer, Priority.DEFAULT, io_cancellable, out bytes_written);
			} catch (GLib.Error e) {
				printerr ("write_all_async() failed: %s\n", e.message);
			}

			send_source = null;

			printerr ("doing next send() here...\n");
			maybe_send_pending ();
		}

		private static int on_stream_close (NGHttp2.Session session, int32 stream_id, uint32 error_code, void * user_data) {
			printerr ("on_stream_close() stream_id=%d error_code=%u\n", stream_id, error_code);
			return 0;
		}

		private static int on_error (NGHttp2.Session session, NGHttp2.ErrorCode code,
				[CCode (array_length_type = "size_t")] char[] msg, void * user_data) {
			string m = ((string) msg).substring (0, msg.length);
			printerr ("on_error() code=%d msg=\"%s\"\n", code, m);
			return 0;
		}
	}

	public class RequestBuilder : ObjectBuilder {
		private const uint32 MAGIC = 0x29b00b92;

		private uint32 flags;
		private uint64 msg_id;

		public RequestBuilder (uint32 flags, uint64 msg_id) {
			this.flags = flags;
			this.msg_id = msg_id;
		}

		public override Bytes build () {
			Bytes body = base.build ();

			return new BufferBuilder (8, LITTLE_ENDIAN)
				.append_uint32 (MAGIC)
				.append_uint32 (flags)
				.append_uint64 (body.length)
				.append_uint64 (msg_id)
				.append_bytes (body)
				.build ();
		}
	}

	public class ObjectBuilder {
		private BufferBuilder builder = new BufferBuilder (8, LITTLE_ENDIAN);
		private Gee.Deque<Scope> scopes = new Gee.ArrayQueue<Scope> ();

		private const uint32 MAGIC = 0x42133742;
		private const uint32 VERSION = 5;

		public ObjectBuilder () {
			builder
				.append_uint32 (MAGIC)
				.append_uint32 (VERSION);
		}

		public unowned ObjectBuilder begin_dictionary () {
			builder.append_uint32 (ObjectType.DICTIONARY);

			size_t length_offset = builder.offset;
			builder.append_uint32 (0);

			size_t num_entries_offset = builder.offset;
			builder.append_uint32 (0);

			push_scope (new DictionaryScope (length_offset, num_entries_offset));

			return this;
		}

		public unowned ObjectBuilder end_dictionary () {
			DictionaryScope scope = pop_scope ();

			uint32 length = (uint32) (builder.offset - scope.num_entries_offset);
			builder.write_uint32 (scope.length_offset, length);

			builder.write_uint32 (scope.num_entries_offset, scope.num_entries);

			return this;
		}

		public unowned ObjectBuilder add_uint64 (uint64 val) {
			builder
				.append_uint32 (ObjectType.UINT64)
				.append_uint64 (val);
			return this;
		}

		public unowned ObjectBuilder add_string (string val) {
			var scope = peek_scope ();

			if (scope.kind != DICTIONARY)
				builder.append_uint32 (ObjectType.STRING);

			builder
				.append_string (val)
				.align (4);

			if (scope.kind == DICTIONARY)
				((DictionaryScope) scope).num_entries++;

			return this;
		}

		public virtual Bytes build () {
			return builder.build ();
		}

		private void push_scope (Scope scope) {
			scopes.offer_head (scope);
		}

		private Scope peek_scope () {
			return scopes.peek_head ();
		}

		private T pop_scope<T> () {
			return (T) scopes.poll_head ();
		}

		private class Scope {
			public Kind kind;

			public enum Kind {
				DICTIONARY,
			}

			protected Scope (Kind kind) {
				this.kind = kind;
			}
		}

		private class DictionaryScope : Scope {
			public size_t length_offset;
			public size_t num_entries_offset;

			public uint num_entries = 0;

			public DictionaryScope (size_t length_offset, size_t num_entries_offset) {
				base (DICTIONARY);
				this.length_offset = length_offset;
				this.num_entries_offset = num_entries_offset;
			}
		}
	}

	private enum ObjectType {
		UINT64     = 0x00004000,
		STRING     = 0x00009000,
		DICTIONARY = 0x0000f000,
	}

	// https://gist.github.com/phako/96b36b5070beaf7eee27
	private void hexdump (uint8[] data) {
		var builder = new StringBuilder.sized (16);
		var i = 0;

		foreach (var c in data) {
			if (i % 16 == 0)
				printerr ("%08x | ", i);

			printerr ("%02x ", c);

			if (((char) c).isprint ())
				builder.append_c ((char) c);
			else
				builder.append (".");

			i++;
			if (i % 16 == 0) {
				printerr ("| %s\n", builder.str);
				builder.erase ();
			}
		}

		if (i % 16 != 0)
			printerr ("%s| %s\n", string.nfill ((16 - (i % 16)) * 3, ' '), builder.str);
	}
}
