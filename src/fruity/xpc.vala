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

	public class DiscoveryService : ServiceConnection, AsyncInitable {
		private Promise<Variant> handshake_promise = new Promise<Variant> ();
		private Variant handshake_body;
		private Source? heartbeat_source;
		private uint64 next_heartbeat_seqno = 1;

		public static async DiscoveryService open (ServiceEndpoint ep, Cancellable? cancellable = null) throws Error, IOError {
			var service = new DiscoveryService (ep);

			try {
				yield service.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return service;
		}

		private DiscoveryService (ServiceEndpoint ep) {
			Object (endpoint: ep);
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			try {
				yield base.init_async (io_priority, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			handshake_body = yield handshake_promise.future.wait_async (cancellable);

			var source = new TimeoutSource.seconds (2);
			source.set_callback (() => {
				send_heartbeat.begin ();
				return Source.CONTINUE;
			});
			source.attach (MainContext.get_thread_default ());
			heartbeat_source = source;

			return true;
		}

		public ServiceEndpoint get_service (string identifier) throws Error {
			var reader = new ObjectReader (handshake_body);
			reader
				.read_member ("Services")
				.read_member (identifier);

			var port = (uint16) uint.parse (reader.read_member ("Port").get_string_value ());
			reader.end_member ();

			return new ServiceEndpoint (endpoint.host, port);
		}

		public override void on_disconnect () {
			if (heartbeat_source != null) {
				heartbeat_source.destroy ();
				heartbeat_source = null;
			}

			if (!handshake_promise.future.ready)
				handshake_promise.reject (new Error.TRANSPORT ("Connection closed while waiting for Handshake message"));
		}

		public override void on_message (Message msg) {
			if (msg.body == null)
				return;

			var reader = new ObjectReader (msg.body);
			try {
				reader.read_member ("MessageType");
				unowned string message_type = reader.get_string_value ();

				if (message_type == "Handshake")
					handshake_promise.resolve (msg.body);
			} catch (Error e) {
				printerr ("Oops: %s\n", e.message);
			}
		}

		private async void send_heartbeat () {
			try {
				yield request (new ObjectBuilder ()
							.begin_dictionary ()
								.set_member_name ("MessageType")
								.add_string_value ("Heartbeat")
								.set_member_name ("SequenceNumber")
								.add_uint64_value (next_heartbeat_seqno++)
							.end_dictionary ()
						.build (), io_cancellable);
			} catch (GLib.Error e) {
				printerr ("send_heartbeat() failed: %s\n", e.message);
			}
		}
	}

	public class AppService : ServiceConnection {
		public static async AppService open (ServiceEndpoint ep, Cancellable? cancellable = null) throws Error, IOError {
			var service = new AppService (ep);

			try {
				yield service.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return service;
		}

		private AppService (ServiceEndpoint ep) {
			Object (endpoint: ep);
		}
	}

	public class ServiceConnection : Object, AsyncInitable {
		public ServiceEndpoint endpoint {
			get;
			construct;
		}

		public State state {
			get {
				return _state;
			}
			private set {
				if (value == _state)
					return;
				_state = value;
				if (_state == DISCONNECTED)
					on_disconnect ();
			}
		}

		private SocketConnection connection;
		private InputStream input;
		private OutputStream output;
		protected Cancellable io_cancellable = new Cancellable ();

		private State _state = CREATED;

		private Gee.Map<uint64?, PendingResponse> pending_responses =
			new Gee.HashMap<uint64?, PendingResponse> (Numeric.uint64_hash, Numeric.uint64_equal);

		private NGHttp2.Session session;
		private Stream root_stream;
		private Stream reply_stream;
		private uint next_message_id = 1;

		private bool is_processing_messages;

		private ByteArray? send_queue;
		private Source? send_source;

		public enum State {
			CREATED,
			CONNECTING,
			CONNECTED,
			DISCONNECTED,
		}

		construct {
			NGHttp2.SessionCallbacks callbacks;
			NGHttp2.SessionCallbacks.make (out callbacks);

			callbacks.set_send_callback ((session, data, flags, user_data) => {
				ServiceConnection * self = user_data;
				return self->on_send (data, flags);
			});
			callbacks.set_on_frame_send_callback ((session, frame, user_data) => {
				ServiceConnection * self = user_data;
				return self->on_frame_send (frame);
			});
			callbacks.set_on_frame_not_send_callback ((session, frame, lib_error_code, user_data) => {
				ServiceConnection * self = user_data;
				return self->on_frame_not_send (frame, lib_error_code);
			});
			callbacks.set_on_data_chunk_recv_callback ((session, flags, stream_id, data, user_data) => {
				ServiceConnection * self = user_data;
				return self->on_data_chunk_recv (flags, stream_id, data);
			});
			callbacks.set_on_frame_recv_callback ((session, frame, user_data) => {
				ServiceConnection * self = user_data;
				return self->on_frame_recv (frame);
			});
			callbacks.set_on_stream_close_callback ((session, stream_id, error_code, user_data) => {
				ServiceConnection * self = user_data;
				return self->on_stream_close (stream_id, error_code);
			});
			callbacks.set_error_callback ((session, code, msg, user_data) => {
				ServiceConnection * self = user_data;
				return self->on_error (code, msg);
			});

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
				var connectable = NetworkAddress.parse (endpoint.host, endpoint.port);

				var client = new SocketClient ();
				printerr ("Connecting to %s:%u...\n", endpoint.host, endpoint.port);
				state = CONNECTING;
				connection = yield client.connect_async (connectable, cancellable);
				state = CONNECTED;

				printerr ("Connected to %s:%u\n", endpoint.host, endpoint.port);

				Tcp.enable_nodelay (connection.socket);

				input = connection.get_input_stream ();
				output = connection.get_output_stream ();

				is_processing_messages = true;

				process_incoming_messages.begin ();

				session.submit_settings (NGHttp2.Flag.NONE, {
					{ MAX_CONCURRENT_STREAMS, 100 },
					{ INITIAL_WINDOW_SIZE, 1048576 },
				});

				session.set_local_window_size (NGHttp2.Flag.NONE, 0, 1048576);

				root_stream = make_stream ();

				Bytes header_request = new MessageBuilder (HEADER)
					.add_body (new ObjectBuilder ()
						.begin_dictionary ()
						.end_dictionary ()
						.build ()
					)
					.build ();
				yield root_stream.submit_data (header_request, io_cancellable);

				Bytes ping_request = new MessageBuilder (PING)
					.build ();
				yield root_stream.submit_data (ping_request, io_cancellable);

				reply_stream = make_stream ();

				Bytes open_reply_channel_request = new MessageBuilder (HEADER)
					.add_flags (HEADER_OPENS_REPLY_CHANNEL)
					.build ();
				yield reply_stream.submit_data (open_reply_channel_request, io_cancellable);
			} catch (GLib.Error e) {
				state = DISCONNECTED;
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}

			return true;
		}

		public void close () {
			io_cancellable.cancel ();
		}

		public async Message request (Bytes body, Cancellable? cancellable = null) throws Error, IOError {
			uint64 request_id = make_message_id ();

			Bytes raw_request = new MessageBuilder (MSG)
				.add_flags (WANTS_REPLY)
				.add_id (request_id)
				.add_body (body)
				.build ();

			bool waiting = false;

			var pending = new PendingResponse (() => {
				if (waiting)
					request.callback ();
				return Source.REMOVE;
			});
			pending_responses[request_id] = pending;

			try {
				yield root_stream.submit_data (raw_request, cancellable);
			} catch (Error e) {
				if (pending_responses.unset (request_id))
					pending.complete_with_error (e);
			}

			if (!pending.completed) {
				var cancel_source = new CancellableSource (cancellable);
				cancel_source.set_callback (() => {
					if (pending_responses.unset (request_id))
						pending.complete_with_error (new IOError.CANCELLED ("Operation was cancelled"));
					return false;
				});
				cancel_source.attach (MainContext.get_thread_default ());

				waiting = true;
				yield;
				waiting = false;

				cancel_source.destroy ();
			}

			cancellable.set_error_if_cancelled ();

			if (pending.error != null)
				throw_api_error (pending.error);

			return pending.result;
		}

		private class PendingResponse {
			private SourceFunc? handler;

			public bool completed {
				get {
					return result != null || error != null;
				}
			}

			public Message? result {
				get;
				private set;
			}

			public GLib.Error? error {
				get;
				private set;
			}

			public PendingResponse (owned SourceFunc handler) {
				this.handler = (owned) handler;
			}

			public void complete_with_result (Message result) {
				this.result = result;
				handler ();
				handler = null;
			}

			public void complete_with_error (GLib.Error error) {
				this.error = error;
				handler ();
				handler = null;
			}
		}

		public virtual void on_disconnect () {
		}

		public virtual void on_message (Message msg) {
		}

		private void on_reply (Message msg, Stream sender) {
			if (sender != reply_stream)
				return;

			PendingResponse response;
			if (!pending_responses.unset (msg.id, out response))
				return;

			if (msg.body != null)
				response.complete_with_result (msg);
			else
				response.complete_with_error (new Error.NOT_SUPPORTED ("Request not supported"));
		}

		private void maybe_send_pending () {
			while (session.want_write ()) {
				bool would_block = send_source != null && send_queue == null;
				if (would_block)
					break;

				session.send ();
			}
		}

		private async void process_incoming_messages () {
			while (is_processing_messages) {
				try {
					var buffer = new uint8[4096];

					ssize_t n = yield input.read_async (buffer, Priority.DEFAULT, io_cancellable);
					if (n == 0) {
						is_processing_messages = false;
						continue;
					}

					ssize_t result = session.mem_recv (buffer[:n]);
					if (result < 0)
						throw new Error.PROTOCOL ("%s", NGHttp2.strerror (result));

					session.consume_connection (n);
				} catch (GLib.Error e) {
					printerr ("Oops: %s\n", e.message);
					is_processing_messages = false;
				}
			}

			state = DISCONNECTED;
		}

		private ssize_t on_send (uint8[] data, int flags) {
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

			maybe_send_pending ();
		}

		private int on_frame_send (NGHttp2.Frame frame) {
			if (frame.hd.type == DATA)
				find_stream_by_id (frame.hd.stream_id).on_data_frame_send ();
			return 0;
		}

		private int on_frame_not_send (NGHttp2.Frame frame, NGHttp2.ErrorCode lib_error_code) {
			if (frame.hd.type == DATA)
				find_stream_by_id (frame.hd.stream_id).on_data_frame_not_send (lib_error_code);
			return 0;
		}

		private int on_data_chunk_recv (uint8 flags, int32 stream_id, uint8[] data) {
			return find_stream_by_id (stream_id).on_data_frame_recv_chunk (data);
		}

		private int on_frame_recv (NGHttp2.Frame frame) {
			if (frame.hd.type == DATA)
				return find_stream_by_id (frame.hd.stream_id).on_data_frame_recv_end (frame);
			return 0;
		}

		private int on_stream_close (int32 stream_id, uint32 error_code) {
			printerr ("on_stream_close() stream_id=%d error_code=%u\n", stream_id, error_code);
			io_cancellable.cancel ();

			return 0;
		}

		private int on_error (NGHttp2.ErrorCode code, char[] msg) {
			string m = ((string) msg).substring (0, msg.length);
			printerr ("on_error() code=%d msg=\"%s\"\n", code, m);
			return 0;
		}

		private Stream make_stream () {
			int stream_id = session.submit_headers (NGHttp2.Flag.NONE, -1, null, {}, null);
			maybe_send_pending ();

			return new Stream (this, stream_id);
		}

		private Stream? find_stream_by_id (int32 id) {
			if (root_stream.id == id)
				return root_stream;
			if (reply_stream.id == id)
				return reply_stream;
			return null;
		}

		private uint make_message_id () {
			uint id = next_message_id;
			next_message_id += 2;
			return id;
		}

		private class Stream {
			public int32 id;

			private weak ServiceConnection parent;

			private Gee.Deque<SubmitOperation> submissions = new Gee.ArrayQueue<SubmitOperation> ();
			private SubmitOperation? current_submission = null;
			private ByteArray incoming_message = new ByteArray ();

			public Stream (ServiceConnection parent, int32 id) {
				this.parent = parent;
				this.id = id;
			}

			public async void submit_data (Bytes bytes, Cancellable? cancellable) throws Error, IOError {
				try {
					var msg = Message.parse (bytes.get_data ());
					printerr (">>> [stream_id=%d] %s\n", id, msg.to_string ());
				} catch (Error e) {
					printerr ("Failed to parse message: %s\n", e.message);
				}

				bool waiting = false;

				var op = new SubmitOperation (bytes, () => {
					if (waiting)
						submit_data.callback ();
					return Source.REMOVE;
				});

				var cancel_source = new CancellableSource (cancellable);
				cancel_source.set_callback (() => {
					op.state = CANCELLED;
					op.callback ();
					return Source.REMOVE;
				});
				cancel_source.attach (MainContext.get_thread_default ());

				submissions.offer_tail (op);
				maybe_submit_data ();

				if (op.state < SubmitOperation.State.SUBMITTED) {
					waiting = true;
					yield;
					waiting = false;
				}

				cancel_source.destroy ();

				if (op.state == CANCELLED && current_submission != op)
					submissions.remove (op);

				cancellable.set_error_if_cancelled ();

				if (op.state == ERROR)
					throw new Error.TRANSPORT ("%s", NGHttp2.strerror (op.error_code));
			}

			private void maybe_submit_data () {
				if (current_submission != null)
					return;

				SubmitOperation? op = submissions.peek_head ();
				if (op == null)
					return;
				current_submission = op;

				var data_prd = NGHttp2.DataProvider ();
				data_prd.source.ptr = op;
				data_prd.read_callback = on_data_provider_read;
				int result = parent.session.submit_data (NGHttp2.DataFlag.NO_END_STREAM, id, data_prd);
				if (result < 0) {
					while (true) {
						op = submissions.poll_head ();
						if (op == null)
							break;
						op.state = ERROR;
						op.error_code = (NGHttp2.ErrorCode) result;
						op.callback ();
					}
					current_submission = null;
					return;
				}

				parent.maybe_send_pending ();
			}

			private static ssize_t on_data_provider_read (NGHttp2.Session session, int32 stream_id, uint8[] buf,
					ref uint32 data_flags, NGHttp2.DataSource source, void * user_data) {
				var op = (SubmitOperation) source.ptr;

				unowned uint8[] data = op.bytes.get_data ();

				uint remaining = data.length - op.cursor;
				uint n = uint.min (remaining, buf.length);
				Memory.copy (buf, (uint8 *) data + op.cursor, n);

				op.cursor += n;

				if (op.cursor == data.length)
					data_flags |= NGHttp2.DataFlag.EOF;

				return n;
			}

			public void on_data_frame_send () {
				submissions.poll_head ().complete (SUBMITTED);
				current_submission = null;

				maybe_submit_data ();
			}

			public void on_data_frame_not_send (NGHttp2.ErrorCode lib_error_code) {
				submissions.poll_head ().complete (ERROR, lib_error_code);
				current_submission = null;

				maybe_submit_data ();
			}

			private class SubmitOperation {
				public Bytes bytes;
				public SourceFunc callback;

				public State state = PENDING;
				public NGHttp2.ErrorCode error_code;
				public uint cursor = 0;

				public enum State {
					PENDING,
					SUBMITTING,
					SUBMITTED,
					ERROR,
					CANCELLED,
				}

				public SubmitOperation (Bytes bytes, owned SourceFunc callback) {
					this.bytes = bytes;
					this.callback = (owned) callback;
				}

				public void complete (State new_state, NGHttp2.ErrorCode err = -1) {
					if (state != PENDING)
						return;
					state = new_state;
					error_code = err;
					callback ();
				}
			}

			public int on_data_frame_recv_chunk (uint8[] data) {
				incoming_message.append (data);
				return 0;
			}

			public int on_data_frame_recv_end (NGHttp2.Frame frame) {
				Message? msg;
				size_t size;
				try {
					msg = Message.try_parse (incoming_message.data, out size);
				} catch (Error e) {
					printerr ("Failed to parse message: %s\n", e.message);
					return -1;
				}
				if (msg == null)
					return 0;
				incoming_message.remove_range (0, (uint) size);

				printerr ("<<< [stream_id=%d] %s\n", frame.hd.stream_id, msg.to_string ());

				if (msg.type == MSG) {
					if ((msg.flags & MessageFlags.IS_REPLY) != 0)
						parent.on_reply (msg, this);
					else if ((msg.flags & (MessageFlags.WANTS_REPLY | MessageFlags.IS_REPLY)) == 0)
						parent.on_message (msg);
				}

				return 0;
			}
		}
	}

	public class ServiceEndpoint : Object {
		public string host {
			get;
			construct;
		}

		public uint16 port {
			get;
			construct;
		}

		public ServiceEndpoint (string host, uint16 port) {
			Object (host: host, port: port);
		}

		public string to_string () {
			return "ServiceEndpoint { host: \"%s\", port: %u }".printf (host, port);
		}
	}

	public class MessageBuilder {
		private MessageType message_type;
		private MessageFlags message_flags = NONE;
		private uint64 message_id = 0;
		private Bytes? body = null;

		public MessageBuilder (MessageType message_type) {
			this.message_type = message_type;
		}

		public unowned MessageBuilder add_flags (MessageFlags flags) {
			message_flags = flags;
			return this;
		}

		public unowned MessageBuilder add_id (uint64 id) {
			message_id = id;
			return this;
		}

		public unowned MessageBuilder add_body (Bytes b) {
			body = b;
			return this;
		}

		public Bytes build () {
			var builder = new BufferBuilder (8, LITTLE_ENDIAN)
				.append_uint32 (Message.MAGIC)
				.append_uint8 (Message.PROTOCOL_VERSION)
				.append_uint8 (message_type)
				.append_uint16 (message_flags)
				.append_uint64 ((body != null) ? body.length : 0)
				.append_uint64 (message_id);

			if (body != null)
				builder.append_bytes (body);

			return builder.build ();
		}
	}

	public class Message {
		public MessageType type;
		public MessageFlags flags;
		public uint64 id;
		public Variant? body;

		public const uint32 MAGIC = 0x29b00b92;
		public const uint8 PROTOCOL_VERSION = 1;
		public const size_t HEADER_SIZE = 24;
		public const size_t MAX_SIZE = (128 * 1024 * 1024) - 1;

		public static Message parse (uint8[] data) throws Error {
			size_t size;
			var msg = try_parse (data, out size);
			if (msg == null)
				throw new Error.INVALID_ARGUMENT ("Message is truncated");
			return msg;
		}

		public static Message? try_parse (uint8[] data, out size_t size) throws Error {
			if (data.length < HEADER_SIZE) {
				size = HEADER_SIZE;
				return null;
			}

			var buf = new Buffer (new Bytes.static (data), 8, LITTLE_ENDIAN);

			var magic = buf.read_uint32 (0);
			if (magic != MAGIC)
				throw new Error.INVALID_ARGUMENT ("Invalid message: bad magic (0x%08x)", magic);

			var protocol_version = buf.read_uint8 (4);
			if (protocol_version != PROTOCOL_VERSION)
				throw new Error.INVALID_ARGUMENT ("Invalid message: unsupported protocol version (%u)", protocol_version);

			var raw_message_type = buf.read_uint8 (5);
			var message_type_class = (EnumClass) typeof (MessageType).class_ref ();
			if (message_type_class.get_value (raw_message_type) == null)
				throw new Error.INVALID_ARGUMENT ("Invalid message: unsupported message type (0x%x)", raw_message_type);
			var message_type = (MessageType) raw_message_type;

			MessageFlags message_flags = (MessageFlags) buf.read_uint16 (6);

			Variant? body = null;
			uint64 message_size = buf.read_uint64 (8);
			size = HEADER_SIZE + (size_t) message_size;
			if (message_size != 0) {
				if (message_size > MAX_SIZE) {
					throw new Error.INVALID_ARGUMENT ("Invalid message: too large (%" + int64.FORMAT_MODIFIER + "u)",
						message_size);
				}
				if (data.length - HEADER_SIZE < message_size)
					return null;
				body = ObjectParser.parse (data[HEADER_SIZE:HEADER_SIZE + message_size]);
			}

			uint64 message_id = buf.read_uint64 (16);

			return new Message (message_type, message_flags, message_id, body);
		}

		private Message (MessageType type, MessageFlags flags, uint64 id, Variant? body) {
			this.type = type;
			this.flags = flags;
			this.id = id;
			this.body = body;
		}

		public string to_string () {
			var description = new StringBuilder.sized (128);

			description.append_printf (("Message {" +
					"\n\ttype: %s," +
					"\n\tflags: %s," +
					"\n\tid: %" + int64.FORMAT_MODIFIER + "u,"),
				type.to_nick ().up (),
				flags.print (),
				id);

			if (body != null) {
				description.append ("\n\tbody: ");
				print_variant (body, description, 1);
				description.append_c (',');
			}

			description.append ("\n}");

			return description.str;
		}

		private static void print_variant (Variant v, StringBuilder sink, uint depth = 0, bool initial = true) {
			VariantType type = v.get_type ();

			if (type.is_basic ()) {
				sink.append (v.print (false));
				return;
			}

			if (type.equal (VariantType.VARDICT)) {
				sink.append ("{\n");

				var iter = new VariantIter (v);
				string key;
				Variant val;
				while (iter.next ("{sv}", out key, out val)) {
					append_indent (depth + 1, sink);

					if ("." in key || "-" in key) {
						sink
							.append_c ('"')
							.append (key)
							.append_c ('"');
					} else {
						sink.append (key);
					}
					sink.append (": ");

					print_variant (val, sink, depth + 1, false);

					sink.append (",\n");
				}

				append_indent (depth, sink);
				sink.append ("}");
			} else if (type.is_array ()) {
				sink.append ("[\n");

				var iter = new VariantIter (v);
				Variant? val;
				while ((val = iter.next_value ()) != null) {
					append_indent (depth + 1, sink);
					print_variant (val, sink, depth + 1, false);
					sink.append (",\n");
				}

				append_indent (depth, sink);
				sink.append ("]");
			} else {
				sink.append (v.print (false));
			}
		}

		private static void append_indent (uint depth, StringBuilder sink) {
			for (uint i = 0; i != depth; i++)
				sink.append_c ('\t');
		}
	}

	public enum MessageType {
		HEADER,
		MSG,
		PING;

		public static MessageType from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<MessageType> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<MessageType> (this);
		}
	}

	[Flags]
	public enum MessageFlags {
		NONE				= 0,
		WANTS_REPLY			= (1 << 0),
		IS_REPLY			= (1 << 1),
		HEADER_OPENS_STREAM_TX		= (1 << 4),
		HEADER_OPENS_STREAM_RX		= (1 << 5),
		HEADER_OPENS_REPLY_CHANNEL	= (1 << 6);

		public string print () {
			uint remainder = this;
			if (remainder == 0)
				return "NONE";

			var result = new StringBuilder.sized (128);

			var klass = (FlagsClass) typeof (MessageFlags).class_ref ();
			foreach (FlagsValue fv in klass.values) {
				if ((remainder & fv.value) != 0) {
					if (result.len != 0)
						result.append (" | ");
					result.append (fv.value_nick.up ().replace ("-", "_"));
					remainder &= ~fv.value;
				}
			}

			if (remainder != 0) {
				if (result.len != 0)
					result.append (" | ");
				result.append_printf ("0x%04x", remainder);
			}

			return result.str;
		}
	}

	public class ObjectBuilder {
		private BufferBuilder builder = new BufferBuilder (8, LITTLE_ENDIAN);
		private Gee.Deque<Scope> scopes = new Gee.ArrayQueue<Scope> ();

		public ObjectBuilder () {
			builder
				.append_uint32 (SerializedObject.MAGIC)
				.append_uint32 (SerializedObject.VERSION);

			push_scope (new Scope (ROOT));
		}

		public unowned ObjectBuilder begin_dictionary () {
			begin_object (DICTIONARY);

			size_t size_offset = builder.offset;
			builder.append_uint32 (0);

			size_t num_entries_offset = builder.offset;
			builder.append_uint32 (0);

			push_scope (new DictionaryScope (size_offset, num_entries_offset));

			return this;
		}

		public unowned ObjectBuilder set_member_name (string name) {
			builder
				.append_string (name)
				.align (4);

			return this;
		}

		public unowned ObjectBuilder end_dictionary () {
			DictionaryScope scope = pop_scope ();

			uint32 size = (uint32) (builder.offset - scope.num_entries_offset);
			builder.write_uint32 (scope.size_offset, size);

			builder.write_uint32 (scope.num_entries_offset, scope.num_objects);

			return this;
		}

		public unowned ObjectBuilder begin_array () {
			begin_object (ARRAY);

			size_t size_offset = builder.offset;
			builder.append_uint32 (0);

			size_t num_elements_offset = builder.offset;
			builder.append_uint32 (0);

			push_scope (new ArrayScope (size_offset, num_elements_offset));

			return this;
		}

		public unowned ObjectBuilder end_array () {
			ArrayScope scope = pop_scope ();

			uint32 size = (uint32) (builder.offset - scope.num_elements_offset);
			builder.write_uint32 (scope.size_offset, size);

			builder.write_uint32 (scope.num_elements_offset, scope.num_objects);

			return this;
		}

		public unowned ObjectBuilder add_null_value () {
			begin_object (NULL);
			return this;
		}

		public unowned ObjectBuilder add_int64_value (int64 val) {
			begin_object (INT64).append_int64 (val);
			return this;
		}

		public unowned ObjectBuilder add_uint64_value (uint64 val) {
			begin_object (UINT64).append_uint64 (val);
			return this;
		}

		public unowned ObjectBuilder add_string_value (string val) {
			begin_object (STRING)
				.append_uint32 (val.length + 1)
				.append_string (val)
				.align (4);
			return this;
		}

		public unowned ObjectBuilder add_uuid_value (string val) {
			var uuid = new ByteArray.sized (16);
			int len = val.length;
			for (int i = 0; i != len;) {
				if (val[i] == '-') {
					i++;
					continue;
				}
				var byte = (uint8) uint.parse (val[i:i + 2], 16);
				uuid.append ({ byte });
				i += 2;
			}
			assert (uuid.len == 16);

			begin_object (UUID).append_data (uuid.data);
			return this;
		}

		private unowned BufferBuilder begin_object (ObjectType type) {
			peek_scope ().num_objects++;
			return builder.append_uint32 (type);
		}

		public Bytes build () {
			return builder.build ();
		}

		private void push_scope (Scope scope) {
			scopes.offer_tail (scope);
		}

		private Scope peek_scope () {
			return scopes.peek_tail ();
		}

		private T pop_scope<T> () {
			return (T) scopes.poll_tail ();
		}

		private class Scope {
			public Kind kind;
			public uint32 num_objects = 0;

			public enum Kind {
				ROOT,
				DICTIONARY,
				ARRAY,
			}

			public Scope (Kind kind) {
				this.kind = kind;
			}
		}

		private class DictionaryScope : Scope {
			public size_t size_offset;
			public size_t num_entries_offset;

			public DictionaryScope (size_t size_offset, size_t num_entries_offset) {
				base (DICTIONARY);
				this.size_offset = size_offset;
				this.num_entries_offset = num_entries_offset;
			}
		}

		private class ArrayScope : Scope {
			public size_t size_offset;
			public size_t num_elements_offset;

			public ArrayScope (size_t size_offset, size_t num_elements_offset) {
				base (DICTIONARY);
				this.size_offset = size_offset;
				this.num_elements_offset = num_elements_offset;
			}
		}
	}

	private enum ObjectType {
		NULL		= 0x1000,
		BOOL		= 0x2000,
		INT64		= 0x3000,
		UINT64		= 0x4000,
		DATA		= 0x8000,
		STRING		= 0x9000,
		UUID		= 0xa000,
		ARRAY		= 0xe000,
		DICTIONARY	= 0xf000,
	}

	private class ObjectParser {
		private Buffer buf;
		private size_t cursor;
		private EnumClass object_type_class;

		public static Variant parse (uint8[] data) throws Error {
			if (data.length < 12)
				throw new Error.INVALID_ARGUMENT ("Invalid xpc_object: truncated");

			var buf = new Buffer (new Bytes.static (data), 8, LITTLE_ENDIAN);

			var magic = buf.read_uint32 (0);
			if (magic != SerializedObject.MAGIC)
				throw new Error.INVALID_ARGUMENT ("Invalid xpc_object: bad magic (0x%08x)", magic);

			var version = buf.read_uint8 (4);
			if (version != SerializedObject.VERSION)
				throw new Error.INVALID_ARGUMENT ("Invalid xpc_object: unsupported version (%u)", version);

			var parser = new ObjectParser (buf, 8);
			return parser.read_object ();
		}

		private ObjectParser (Buffer buf, uint cursor) {
			this.buf = buf;
			this.cursor = cursor;
			this.object_type_class = (EnumClass) typeof (ObjectType).class_ref ();
		}

		public Variant read_object () throws Error {
			var raw_type = read_raw_uint32 ();
			if (object_type_class.get_value ((int) raw_type) == null)
				throw new Error.INVALID_ARGUMENT ("Invalid xpc_object: unsupported type (0x%x)", raw_type);
			var type = (ObjectType) raw_type;

			switch (type) {
				case NULL:
					return new Variant.maybe (VariantType.VARIANT, null);
				case BOOL:
					return new Variant.boolean (read_raw_uint32 () != 0);
				case INT64:
					return new Variant.int64 (read_raw_int64 ());
				case UINT64:
					return new Variant.uint64 (read_raw_uint64 ());
				case DATA:
					return read_data ();
				case STRING:
					return read_string ();
				case UUID:
					return read_uuid ();
				case ARRAY:
					return read_array ();
				case DICTIONARY:
					return read_dictionary ();
				default:
					assert_not_reached ();
			}
		}

		private Variant read_data () throws Error {
			var size = read_raw_uint32 ();

			var bytes = read_raw_bytes (size);
			align (4);

			return Variant.new_from_data (new VariantType ("ay"), bytes.get_data (), true, bytes);
		}

		private Variant read_string () throws Error {
			var size = read_raw_uint32 ();

			var str = buf.read_string (cursor);
			cursor += size;
			align (4);

			return new Variant.string (str);
		}

		private Variant read_uuid () throws Error {
			uint8[] uuid = read_raw_bytes (16).get_data ();
			return new Variant.string ("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X".printf (
				uuid[0], uuid[1], uuid[2], uuid[3],
				uuid[4], uuid[5],
				uuid[6], uuid[7],
				uuid[8], uuid[9],
				uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]));
		}

		private Variant read_array () throws Error {
			var builder = new VariantBuilder (new VariantType.array (VariantType.VARIANT));

			var size = read_raw_uint32 ();
			size_t num_elements_offset = cursor;
			var num_elements = read_raw_uint32 ();

			for (uint32 i = 0; i != num_elements; i++)
				builder.add ("v", read_object ());

			cursor = num_elements_offset;
			skip (size);

			return builder.end ();
		}

		private Variant read_dictionary () throws Error {
			var builder = new VariantBuilder (VariantType.VARDICT);

			var size = read_raw_uint32 ();
			size_t num_entries_offset = cursor;
			var num_entries = read_raw_uint32 ();

			for (uint32 i = 0; i != num_entries; i++) {
				string key = buf.read_string (cursor);
				skip (key.length + 1);
				align (4);

				Variant val = read_object ();

				builder.add ("{sv}", key, val);
			}

			cursor = num_entries_offset;
			skip (size);

			return builder.end ();
		}

		private uint32 read_raw_uint32 () throws Error {
			check_available (sizeof (uint32));
			var result = buf.read_uint32 (cursor);
			cursor += sizeof (uint32);
			return result;
		}

		private int64 read_raw_int64 () throws Error {
			check_available (sizeof (int64));
			var result = buf.read_int64 (cursor);
			cursor += sizeof (int64);
			return result;
		}

		private uint64 read_raw_uint64 () throws Error {
			check_available (sizeof (uint64));
			var result = buf.read_uint64 (cursor);
			cursor += sizeof (uint64);
			return result;
		}

		private Bytes read_raw_bytes (size_t n) throws Error {
			check_available (n);
			Bytes result = buf.bytes[cursor:cursor + n];
			cursor += n;
			return result;
		}

		private void skip (size_t n) throws Error {
			check_available (n);
			cursor += n;
		}

		private void align (size_t n) throws Error {
			size_t remainder = cursor % n;
			if (remainder != 0)
				skip (n - remainder);
		}

		private void check_available (size_t required) throws Error {
			size_t available = buf.bytes.get_size () - cursor;
			if (available < required)
				throw new Error.INVALID_ARGUMENT ("Invalid xpc_object: truncated");
		}
	}

	private class ObjectReader {
		private Gee.Deque<Scope> scopes = new Gee.ArrayQueue<Scope> ();

		public ObjectReader (Variant v) {
			push_scope (v);
		}

		public unowned ObjectReader read_member (string name) throws Error {
			var scope = peek_scope ();
			if (scope.dict == null)
				throw new Error.PROTOCOL ("Dictionary expected");

			Variant? v = scope.dict.lookup_value (name, null);
			if (v == null)
				throw new Error.PROTOCOL ("Key '%s' not found in dictionary", name);

			push_scope (v);

			return this;
		}

		public unowned ObjectReader end_member () {
			pop_scope ();

			return this;
		}

		public bool get_bool_value () throws Error {
			return peek_scope ().get_value (VariantType.BOOLEAN).get_boolean ();
		}

		public int64 get_int64_value () throws Error {
			return peek_scope ().get_value (VariantType.INT64).get_int64 ();
		}

		public uint64 get_uint64_value () throws Error {
			return peek_scope ().get_value (VariantType.UINT64).get_uint64 ();
		}

		public unowned string get_string_value () throws Error {
			return peek_scope ().get_value (VariantType.STRING).get_string ();
		}

		public unowned string get_uuid_value () throws Error {
			return peek_scope ().get_value (VariantType.STRING).get_string (); // TODO: Use a tuple to avoid ambiguity.
		}

		private void push_scope (Variant v) {
			scopes.offer_tail (new Scope (v));
		}

		private Scope peek_scope () {
			return scopes.peek_tail ();
		}

		private Scope pop_scope () {
			return scopes.poll_tail ();
		}

		private class Scope {
			public Variant val;
			public VariantDict? dict;

			public Scope (Variant v) {
				val = v;
				if (v.get_type ().equal (VariantType.VARDICT))
					dict = new VariantDict (v);
			}

			public Variant get_value (VariantType expected_type) throws Error {
				if (!val.get_type ().equal (expected_type)) {
					throw new Error.PROTOCOL ("Expected type '%s', got '%s'",
						(string) expected_type.peek_string (),
						(string) val.get_type ().peek_string ());
				}

				return val;
			}
		}
	}

	namespace SerializedObject {
		public const uint32 MAGIC = 0x42133742;
		public const uint32 VERSION = 5;
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
