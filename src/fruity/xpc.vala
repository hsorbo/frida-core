[CCode (gir_namespace = "FridaXPC", gir_version = "1.0")]
namespace Frida.XPC {
	using Darwin.DNSSD;
	using Darwin.GCD;
	using Darwin.Net;
	using OpenSSL.Envelope;

	private const string PAIRING_REGTYPE = "_remotepairing._tcp";
	private const string PAIRING_DOMAIN = "local.";

	public class PairingBrowser : Object {
		public signal void services_discovered (PairingService[] services);

		private MainContext main_context;
		private DispatchQueue dispatch_queue = new DispatchQueue ("re.frida.fruity.queue", DispatchQueueAttr.SERIAL);

		private DNSService dns_connection;
		private DNSService browse_session;
		private TaskQueue task_queue;

		private Gee.List<PairingService> current_batch = new Gee.ArrayList<PairingService> ();

		construct {
			main_context = MainContext.ref_thread_default ();

			dispatch_queue.dispatch_async (() => {
				DNSService.create_connection (out dns_connection);
				dns_connection.set_dispatch_queue (dispatch_queue);

				DNSService session = dns_connection;
				DNSService.browse (ref session, PrivateFive | ShareConnection, 0, PAIRING_REGTYPE, PAIRING_DOMAIN,
					on_browse_reply);
				browse_session = session;

				task_queue = new TaskQueue (this);
			});
		}

		~PairingBrowser () {
			dispatch_queue.dispatch_sync (() => {
				browse_session.deallocate ();
				dns_connection.deallocate ();
			});
		}

		private void on_browse_reply (DNSService sd_ref, DNSService.Flags flags, uint32 interface_index,
				DNSService.ErrorType error_code, string service_name, string regtype, string reply_domain) {
			if (error_code != NoError)
				return;

			var interface_name_buf = new char[IFNAMSIZ];
			unowned string interface_name = if_indextoname (interface_index, interface_name_buf);

			var service = new PairingService (service_name, interface_index, interface_name, task_queue);
			current_batch.add (service);

			if ((flags & DNSService.Flags.MoreComing) != 0)
				return;

			var services = current_batch;
			current_batch = new Gee.ArrayList<PairingService> ();

			schedule_on_frida_thread (() => {
				services_discovered (services.to_array ());
				return Source.REMOVE;
			});
		}

		private void schedule_on_frida_thread (owned SourceFunc function) {
			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (main_context);
		}

		private class TaskQueue : Object, DNSServiceProvider {
			private weak PairingBrowser parent;

			private DNSServiceTask? current = null;
			private Gee.Deque<DNSServiceTask> pending = new Gee.ArrayQueue<DNSServiceTask> ();

			public TaskQueue (PairingBrowser parent) {
				this.parent = parent;
			}

			private async T with_dns_service<T> (DNSServiceTask task, Cancellable? cancellable) throws Error, IOError {
				var promise = new Promise<Object> ();
				task.set_data ("promise", promise);
				pending.offer_tail (task);

				maybe_start_next ();

				return (T) yield promise.future.wait_async (cancellable);
			}

			private void maybe_start_next () {
				if (current != null)
					return;

				DNSServiceTask? task = pending.poll_head ();
				if (task == null)
					return;
				current = task;

				parent.dispatch_queue.dispatch_async (() => {
					current.dns_connection = parent.dns_connection;
					current.on_complete = on_complete;
					current.start ();
				});
			}

			private void on_complete (Object? result, Error? error) {
				parent.schedule_on_frida_thread (() => {
					Promise<Object> promise = current.steal_data ("promise");

					if (error != null)
						promise.reject (error);
					else
						promise.resolve (result);

					current = null;
					maybe_start_next ();

					return Source.REMOVE;
				});
			}
		}
	}

	private interface DNSServiceProvider : Object {
		public abstract async T with_dns_service<T> (DNSServiceTask task, Cancellable? cancellable) throws Error, IOError;
	}

	private abstract class DNSServiceTask : Object {
		internal DNSService? dns_connection;
		internal CompleteFunc? on_complete;

		protected DNSService? session;

		public delegate void CompleteFunc (Object? result, Error? error);

		public abstract void start ();

		protected void complete (Object? result, Error? error) {
			if (session != null && session != dns_connection) {
				session.deallocate ();
				session = null;
			}

			on_complete (result, error);
			on_complete = null;
		}
	}

	public class PairingService : Object {
		public string name {
			get;
			construct;
		}

		public uint interface_index {
			get;
			construct;
		}

		public string interface_name {
			get;
			construct;
		}

		private DNSServiceProvider dns;

		internal PairingService (string name, uint interface_index, string interface_name, DNSServiceProvider dns) {
			Object (
				name: name,
				interface_index: interface_index,
				interface_name: interface_name
			);
			this.dns = dns;
		}

		public async Gee.List<PairingServiceHost> resolve (Cancellable? cancellable = null) throws Error, IOError {
			var task = new ResolveTask (this);
			return yield dns.with_dns_service (task, cancellable);
		}

		private class ResolveTask : DNSServiceTask {
			private weak PairingService parent;

			private Gee.List<PairingServiceHost> hosts = new Gee.ArrayList<PairingServiceHost> ();

			public ResolveTask (PairingService parent) {
				this.parent = parent;
			}

			public override void start () {
				session = dns_connection;
				DNSService.resolve (ref session, PrivateFive | ShareConnection, parent.interface_index, parent.name,
					PAIRING_REGTYPE, PAIRING_DOMAIN, on_resolve_reply);
			}

			private void on_resolve_reply (DNSService sd_ref, DNSService.Flags flags, uint32 interface_index,
					DNSService.ErrorType error_code, string fullname, string hosttarget, uint16 port,
					uint8[] txt_record) {
				if (error_code != NoError) {
					complete (null,
						new Error.TRANSPORT ("Unable to resolve service '%s' on interface %s",
							parent.name, parent.interface_name));
					return;
				}

				hosts.add (new PairingServiceHost (parent, hosttarget, uint16.from_big_endian (port),
					new Bytes (txt_record), parent.dns));

				if ((flags & DNSService.Flags.MoreComing) == 0)
					complete (hosts, null);
			}
		}

		public string to_string () {
			return @"PairingService { name: \"$name\", interface_index: $interface_index," +
				@" interface_name: \"$interface_name\" }";
		}
	}

	public class PairingServiceHost : Object {
		public string name {
			get;
			construct;
		}

		public uint16 port {
			get;
			construct;
		}

		public Bytes txt_record {
			get;
			construct;
		}

		private PairingService service;
		private DNSServiceProvider dns;

		internal PairingServiceHost (PairingService service, string name, uint16 port, Bytes txt_record, DNSServiceProvider dns) {
			Object (
				name: name,
				port: port,
				txt_record: txt_record
			);
			this.service = service;
			this.dns = dns;
		}

		public async Gee.List<InetSocketAddress> resolve (Cancellable? cancellable = null) throws Error, IOError {
			var task = new ResolveTask (this);
			return yield dns.with_dns_service (task, cancellable);
		}

		private class ResolveTask : DNSServiceTask {
			private weak PairingServiceHost parent;

			private Gee.List<InetSocketAddress> addresses = new Gee.ArrayList<InetSocketAddress> ();

			public ResolveTask (PairingServiceHost parent) {
				this.parent = parent;
			}

			public override void start () {
				session = dns_connection;
				DNSService.get_addr_info (ref session, PrivateFive | ShareConnection, parent.service.interface_index, IPv6,
					parent.name, on_info_reply);
			}

			private void on_info_reply (DNSService sd_ref, DNSService.Flags flags, uint32 interface_index,
					DNSService.ErrorType error_code, string hostname, void * address, uint32 ttl) {
				if (error_code != NoError) {
					complete (null,
						new Error.TRANSPORT ("Unable to resolve host '%s' on interface %s",
							parent.name, parent.service.interface_name));
					return;
				}

				addresses.add ((InetSocketAddress) SocketAddress.from_native (address, sizeof (Posix.SockAddrIn6)));

				if ((flags & DNSService.Flags.MoreComing) == 0)
					complete (addresses, null);
			}
		}

		public string to_string () {
			return @"PairingServiceHost { name: \"$name\", port: $port, txt_record: <$(txt_record.length) bytes> }";
		}
	}

	public class DiscoveryService : Object, AsyncInitable {
		public IOStream stream {
			get;
			construct;
		}

		private Cancellable io_cancellable = new Cancellable ();

		private Connection connection;

		private Promise<Variant> handshake_promise = new Promise<Variant> ();
		private Variant handshake_body;
		private Source? heartbeat_source;
		private uint64 next_heartbeat_seqno = 1;

		public static async DiscoveryService open (IOStream stream, Cancellable? cancellable = null) throws Error, IOError {
			var service = new DiscoveryService (stream);

			try {
				yield service.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return service;
		}

		private DiscoveryService (IOStream stream) {
			Object (stream: stream);
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			connection = new Connection (stream);
			connection.close.connect (on_close);
			connection.message.connect (on_message);
			connection.activate ();

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

		public void close () {
			connection.cancel ();
		}

		public ServiceInfo get_service (string identifier) throws Error {
			var reader = new ObjectReader (handshake_body);
			reader
				.read_member ("Services")
				.read_member (identifier);

			var port = (uint16) uint.parse (reader.read_member ("Port").get_string_value ());

			return new ServiceInfo () {
				port = port,
			};
		}

		private void on_close (Error? error) {
			if (heartbeat_source != null) {
				heartbeat_source.destroy ();
				heartbeat_source = null;
			}

			if (!handshake_promise.future.ready) {
				handshake_promise.reject (
					(error != null)
						? error
						: new Error.TRANSPORT ("Connection closed while waiting for Handshake message"));
			}
		}

		private void on_message (Message msg) {
			if (msg.body == null)
				return;

			var reader = new ObjectReader (msg.body);
			try {
				reader.read_member ("MessageType");
				unowned string message_type = reader.get_string_value ();

				if (message_type == "Handshake")
					handshake_promise.resolve (msg.body);
			} catch (Error e) {
			}
		}

		private async void send_heartbeat () {
			try {
				yield connection.request (new BodyBuilder ()
							.begin_dictionary ()
								.set_member_name ("MessageType")
								.add_string_value ("Heartbeat")
								.set_member_name ("SequenceNumber")
								.add_uint64_value (next_heartbeat_seqno++)
							.end_dictionary ()
						.build (), io_cancellable);
			} catch (GLib.Error e) {
			}
		}
	}

	public class ServiceInfo {
		public uint16 port;
	}

	public class TunnelService : Object, AsyncInitable {
		public IOStream stream {
			get;
			construct;
		}

		private Connection connection;

		private Gee.Map<uint64?, Promise<ObjectReader>> plain_requests =
			new Gee.HashMap<uint64?, Promise<ObjectReader>> (Numeric.uint64_hash, Numeric.uint64_equal);
		private uint64 next_sequence_number = 0;

		private string host_identifier;
		private Key? pair_record_key;

		public static async TunnelService open (IOStream stream, Cancellable? cancellable = null) throws Error, IOError {
			var service = new TunnelService (stream);

			try {
				yield service.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return service;
		}

		private TunnelService (IOStream stream) {
			Object (stream: stream);
		}

		construct {
			host_identifier = "<...>";
			pair_record_key = new Key.from_raw_private_key (ED25519, null, {
				<...>
			});
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			connection = new Connection (stream);
			connection.close.connect (on_close);
			connection.message.connect (on_message);
			connection.activate ();

			yield connection.wait_until_ready (cancellable);

			return true;
		}

		public void close () {
			connection.cancel ();
		}

		public async ObjectReader attempt_pair_verify (Cancellable? cancellable = null) throws Error, IOError {
			Bytes payload = new ObjectBuilder ()
				.begin_dictionary ()
					.set_member_name ("request")
					.begin_dictionary ()
						.set_member_name ("_0")
						.begin_dictionary ()
							.set_member_name ("handshake")
							.begin_dictionary ()
								.set_member_name ("_0")
								.begin_dictionary ()
									.set_member_name ("wireProtocolVersion")
									.add_int64_value (19)
									.set_member_name ("hostOptions")
									.begin_dictionary ()
										.set_member_name ("attemptPairVerify")
										.add_bool_value (true)
									.end_dictionary ()
								.end_dictionary ()
							.end_dictionary ()
						.end_dictionary ()
					.end_dictionary ()
				.end_dictionary ()
				.build ();

			ObjectReader response = yield request_plain (payload, cancellable);

			response
				.read_member ("response")
				.read_member ("_1")
				.read_member ("handshake")
				.read_member ("_0");

			printerr ("attempt_pair_verify() got: %s\n", variant_to_pretty_string (response.current_object));

			return response;
		}

		public async bool verify_manual_pairing (Cancellable? cancellable = null) throws Error, IOError {
			Key host_keypair = make_x25519_keypair ();

			Bytes start_params = new PairingParamsBuilder ()
				.add_state (1)
				.add_public_key (host_keypair)
				.build ();

			Bytes start_payload = new ObjectBuilder ()
				.begin_dictionary ()
					.set_member_name ("kind")
					.add_string_value ("verifyManualPairing")
					.set_member_name ("startNewSession")
					.add_bool_value (true)
					.set_member_name ("data")
					.add_data_value (start_params)
				.end_dictionary ()
				.build ();

			var start_response = yield request_pairing_data (start_payload, cancellable);
			uint8[] raw_device_pubkey = start_response
				.read_member ("public-key")
				.get_data_value ().get_data ();
			var device_pubkey = new Key.from_raw_public_key (X25519, null, raw_device_pubkey);

			Bytes encryption_key = derive_shared_key (host_keypair, device_pubkey);

			Bytes derived_key = derive_chacha_key (encryption_key.get_data (),
				"Pair-Verify-Encrypt-Info",
				"Pair-Verify-Encrypt-Salt");

			var cipher_ctx = new CipherContext ();
			var cipher = Cipher.fetch (null, OpenSSL.ShortName.chacha20_poly1305);
			unowned string iv = "\x00\x00\x00\x00PV-Msg03";
			cipher_ctx.encrypt_init (cipher, derived_key.get_data (), iv.data[:12]);

			var mdc = new MessageDigestContext ();
			mdc.digest_sign_init (null, null, null, pair_record_key);
			var blob = new ByteArray.sized (100);
			blob.append (get_raw_public_key (host_keypair));
			blob.append (host_identifier.data);
			blob.append (raw_device_pubkey);
			size_t siglen = 0;
			mdc.digest_sign (null, ref siglen, blob.data);
			var signature = new uint8[siglen];
			mdc.digest_sign (signature, ref siglen, blob.data);

			Bytes inner_params = new PairingParamsBuilder ()
				.add_identifier (host_identifier)
				.add_signature (signature)
				.build ();
			size_t cleartext_size = inner_params.get_size ();
			size_t tag_size = 16;
			var encrypted_inner_params = new uint8[cleartext_size + tag_size];
			int encrypted_inner_params_size = (int) cleartext_size;
			cipher_ctx.encrypt_update (encrypted_inner_params, ref encrypted_inner_params_size, inner_params.get_data ());
			int extra_size = encrypted_inner_params.length - encrypted_inner_params_size;
			cipher_ctx.encrypt_final (encrypted_inner_params[encrypted_inner_params_size:], ref extra_size);
			assert (extra_size == 0);
			cipher_ctx.ctrl (AEAD_GET_TAG, (int) tag_size, (void *) encrypted_inner_params[encrypted_inner_params_size:]);

			Bytes outer_params = new PairingParamsBuilder ()
				.add_state (3)
				.add_encrypted_data (encrypted_inner_params)
				.build ();

			Bytes finish_payload = new ObjectBuilder ()
				.begin_dictionary ()
					.set_member_name ("kind")
					.add_string_value ("verifyManualPairing")
					.set_member_name ("startNewSession")
					.add_bool_value (false)
					.set_member_name ("data")
					.add_data_value (outer_params)
				.end_dictionary ()
				.build ();

			ObjectReader finish_response = yield request_pairing_data (finish_payload, cancellable);
			if (finish_response.has_member ("error")) {
				yield post_plain (new ObjectBuilder ()
					.begin_dictionary ()
						.set_member_name ("event")
						.begin_dictionary ()
							.set_member_name ("_0")
							.begin_dictionary ()
								.set_member_name ("pairVerifyFailed")
								.begin_dictionary ()
								.end_dictionary ()
							.end_dictionary ()
						.end_dictionary ()
					.end_dictionary ()
					.build (), cancellable);
				return false;
			}

			return true;
		}

		private async ObjectReader request_pairing_data (Bytes payload, Cancellable? cancellable = null) throws Error, IOError {
			Bytes wrapper = new ObjectBuilder ()
				.begin_dictionary ()
					.set_member_name ("event")
					.begin_dictionary ()
						.set_member_name ("_0")
						.begin_dictionary ()
							.set_member_name ("pairingData")
							.begin_dictionary ()
								.set_member_name ("_0")
								.add_raw_value (payload)
							.end_dictionary ()
						.end_dictionary ()
					.end_dictionary ()
				.end_dictionary ()
				.build ();

			ObjectReader response = yield request_plain (wrapper, cancellable);

			response
				.read_member ("event")
				.read_member ("_0");

			if (!response.has_member ("pairingData"))
				throw new Error.PROTOCOL ("Pairing request failed: %s", response.current_object.print (false));

			Bytes raw_data = response
				.read_member ("pairingData")
				.read_member ("_0")
				.read_member ("data")
				.get_data_value ();
			Variant data = PairingParamsParser.parse (raw_data.get_data ());
			return new ObjectReader (data);
		}

		private async ObjectReader request_plain (Bytes payload, Cancellable? cancellable = null) throws Error, IOError {
			uint64 seqno = next_sequence_number++;
			var promise = new Promise<ObjectReader> ();
			plain_requests[seqno] = promise;

			try {
				yield post_plain_with_sequence_number (seqno, payload);
			} catch (GLib.Error e) {
				if (plain_requests.unset (seqno))
					promise.reject (e);
			}

			return yield promise.future.wait_async (cancellable);
		}

		private async void post_plain (Bytes payload, Cancellable? cancellable = null) throws Error, IOError {
			uint64 seqno = next_sequence_number++;
			yield post_plain_with_sequence_number (seqno, payload, cancellable);
		}

		private async void post_plain_with_sequence_number (uint64 seqno, Bytes payload, Cancellable? cancellable = null)
				throws Error, IOError {
			yield connection.post (new BodyBuilder ()
				.begin_dictionary ()
					.set_member_name ("mangledTypeName")
					.add_string_value ("RemotePairing.ControlChannelMessageEnvelope")
					.set_member_name ("value")
					.begin_dictionary ()
						.set_member_name ("sequenceNumber")
						.add_uint64_value (seqno)
						.set_member_name ("originatedBy")
						.add_string_value ("host")
						.set_member_name ("message")
						.begin_dictionary ()
							.set_member_name ("plain")
							.begin_dictionary ()
								.set_member_name ("_0")
								.add_raw_value (payload)
							.end_dictionary ()
						.end_dictionary ()
					.end_dictionary ()
				.end_dictionary ()
				.build ());
		}

		private void on_close (Error? error) {
			var e = (error != null)
				? error
				: new Error.TRANSPORT ("Connection closed while waiting for response");
			foreach (Promise<ObjectReader> promise in plain_requests.values)
				promise.reject (e);
			plain_requests.clear ();
		}

		private void on_message (Message msg) {
			if (msg.body == null)
				return;

			var reader = new ObjectReader (msg.body);
			try {
				string type_name = reader
					.read_member ("mangledTypeName")
					.get_string_value ();
				if (type_name != "RemotePairingDevice.ControlChannelMessageEnvelope")
					return;
				reader.end_member ();

				reader.read_member ("value");

				string origin = reader
					.read_member ("originatedBy")
					.get_string_value ();
				if (origin != "device")
					return;
				reader.end_member ();

				uint64 seqno = reader
					.read_member ("sequenceNumber")
					.get_uint64_value ();
				reader.end_member ();

				reader.read_member ("message")
					.read_member ("plain")
					.read_member ("_0");

				Promise<ObjectReader> promise;
				if (!plain_requests.unset (seqno, out promise))
					return;

				promise.resolve (reader);
			} catch (Error e) {
			}
		}
	}

	private class PairingParamsBuilder {
		private BufferBuilder builder = new BufferBuilder (8, LITTLE_ENDIAN);

		public unowned PairingParamsBuilder add_identifier (string identifier) {
			begin_param (IDENTIFIER, identifier.data.length)
				.append_data (identifier.data);

			return this;
		}

		public unowned PairingParamsBuilder add_public_key (Key key) {
			uint8[] pubkey = get_raw_public_key (key);

			begin_param (PUBLIC_KEY, pubkey.length)
				.append_data (pubkey);

			return this;
		}

		public unowned PairingParamsBuilder add_encrypted_data (uint8[] data) {
			begin_param (ENCRYPTED_DATA, data.length)
				.append_data (data);

			return this;
		}

		public unowned PairingParamsBuilder add_state (uint8 state) {
			begin_param (STATE, 1)
				.append_uint8 (state);

			return this;
		}

		public unowned PairingParamsBuilder add_signature (uint8[] signature) {
			begin_param (SIGNATURE, signature.length)
				.append_data (signature);

			return this;
		}

		private unowned BufferBuilder begin_param (PairingParamType type, size_t size) {
			return builder
				.append_uint8 (type)
				.append_uint8 ((uint8) size);
		}

		public Bytes build () {
			return builder.build ();
		}
	}

	private class PairingParamsParser {
		private Buffer buf;
		private size_t cursor = 0;
		private EnumClass param_type_class;

		public static Variant parse (uint8[] data) throws Error {
			var parser = new PairingParamsParser (new Bytes.static (data));
			return parser.read_params ();
		}

		private PairingParamsParser (Bytes bytes) {
			this.buf = new Buffer (bytes, 8, LITTLE_ENDIAN);
			this.param_type_class = (EnumClass) typeof (PairingParamType).class_ref ();
		}

		private Variant read_params () throws Error {
			var builder = new VariantBuilder (VariantType.VARDICT);

			var byte_array = new VariantType.array (VariantType.BYTE);

			size_t size = buf.bytes.get_size ();
			while (cursor != size) {
				var raw_type = read_raw_uint8 ();
				unowned EnumValue? type_enum_val = param_type_class.get_value (raw_type);
				if (type_enum_val == null)
					throw new Error.INVALID_ARGUMENT ("Unsupported pairing parameter type (0x%x)", raw_type);
				var type = (PairingParamType) raw_type;
				unowned string key = type_enum_val.value_nick;

				var val_size = read_raw_uint8 ();
				Bytes val_bytes = read_raw_bytes (val_size);

				Variant val;
				switch (type) {
					case STATE:
						if (val_bytes.length != 1)
							throw new Error.INVALID_ARGUMENT ("Invalid state value");
						val = new Variant.byte (val_bytes[0]);
						break;
					case ERROR:
						if (val_bytes.length != 1)
							throw new Error.INVALID_ARGUMENT ("Invalid error value");
						val = new Variant.byte (val_bytes[0]);
						break;
					default:
						val = Variant.new_from_data (byte_array, val_bytes.get_data (), true, val_bytes);
						break;
				}

				builder.add ("{sv}", key, val);
			}

			return builder.end ();
		}

		private uint8 read_raw_uint8 () throws Error {
			check_available (sizeof (uint8));
			var result = buf.read_uint8 (cursor);
			cursor += sizeof (uint8);
			return result;
		}

		private Bytes read_raw_bytes (size_t n) throws Error {
			check_available (n);
			Bytes result = buf.bytes[cursor:cursor + n];
			cursor += n;
			return result;
		}

		private void check_available (size_t required) throws Error {
			size_t available = buf.bytes.get_size () - cursor;
			if (available < required)
				throw new Error.INVALID_ARGUMENT ("Invalid pairing parameters: truncated");
		}
	}

	private enum PairingParamType {
		IDENTIFIER	= 1,
		PUBLIC_KEY	= 3,
		ENCRYPTED_DATA	= 5,
		STATE		= 6,
		ERROR		= 7,
		SIGNATURE	= 10,
	}

	public class AppService : TrustedService {
		public static async AppService open (IOStream stream, Cancellable? cancellable = null) throws Error, IOError {
			var service = new AppService (stream);

			try {
				yield service.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return service;
		}

		private AppService (IOStream stream) {
			Object (stream: stream);
		}

		public async Gee.List<ApplicationInfo> enumerate_applications (Cancellable? cancellable = null) throws Error, IOError {
			Bytes input = new ObjectBuilder ()
				.begin_dictionary ()
					.set_member_name ("includeDefaultApps")
					.add_bool_value (true)
					.set_member_name ("includeRemovableApps")
					.add_bool_value (true)
					.set_member_name ("includeInternalApps")
					.add_bool_value (true)
					.set_member_name ("includeHiddenApps")
					.add_bool_value (true)
					.set_member_name ("includeAppClips")
					.add_bool_value (true)
				.end_dictionary ()
				.build ();
			var response = yield invoke ("com.apple.coredevice.feature.listapps", input, cancellable);

			var applications = new Gee.ArrayList<ApplicationInfo> ();
			uint n = response.count_elements ();
			for (uint i = 0; i != n; i++) {
				response.read_element (i);

				string bundle_identifier = response
					.read_member ("bundleIdentifier")
					.get_string_value ();
				response.end_member ();

				string? bundle_version = null;
				if (response.has_member ("bundleVersion")) {
					bundle_version = response
						.read_member ("bundleVersion")
						.get_string_value ();
					response.end_member ();
				}

				string name = response
					.read_member ("name")
					.get_string_value ();
				response.end_member ();

				string? version = null;
				if (response.has_member ("version")) {
					version = response
						.read_member ("version")
						.get_string_value ();
					response.end_member ();
				}

				string path = response
					.read_member ("path")
					.get_string_value ();
				response.end_member ();

				bool is_first_party = response
					.read_member ("isFirstParty")
					.get_bool_value ();
				response.end_member ();

				bool is_developer_app = response
					.read_member ("isDeveloperApp")
					.get_bool_value ();
				response.end_member ();

				bool is_removable = response
					.read_member ("isRemovable")
					.get_bool_value ();
				response.end_member ();

				bool is_internal = response
					.read_member ("isInternal")
					.get_bool_value ();
				response.end_member ();

				bool is_hidden = response
					.read_member ("isHidden")
					.get_bool_value ();
				response.end_member ();

				bool is_app_clip = response
					.read_member ("isAppClip")
					.get_bool_value ();
				response.end_member ();

				applications.add (new ApplicationInfo () {
					bundle_identifier = bundle_identifier,
					bundle_version = bundle_version,
					name = name,
					version = version,
					path = path,
					is_first_party = is_first_party,
					is_developer_app = is_developer_app,
					is_removable = is_removable,
					is_internal = is_internal,
					is_hidden = is_hidden,
					is_app_clip = is_app_clip,
				});

				response.end_element ();
			}

			return applications;
		}

		public async Gee.List<ProcessInfo> enumerate_processes (Cancellable? cancellable = null) throws Error, IOError {
			var response = yield invoke ("com.apple.coredevice.feature.listprocesses", null, cancellable);

			var processes = new Gee.ArrayList<ProcessInfo> ();
			uint n = response
				.read_member ("processTokens")
				.count_elements ();
			for (uint i = 0; i != n; i++) {
				response.read_element (i);

				int64 pid = response
					.read_member ("processIdentifier")
					.get_int64_value ();
				response.end_member ();

				string url = response
					.read_member ("executableURL")
					.read_member ("relative")
					.get_string_value ();
				response
					.end_member ()
					.end_member ();

				if (!url.has_prefix ("file://"))
					throw new Error.PROTOCOL ("Unsupported URL: %s", url);

				string path = url[7:];

				processes.add (new ProcessInfo () {
					pid = (uint) pid,
					path = path,
				});

				response.end_element ();
			}

			return processes;
		}
	}

	public class ApplicationInfo {
		public string bundle_identifier;
		public string? bundle_version;
		public string name;
		public string? version;
		public string path;
		public bool is_first_party;
		public bool is_developer_app;
		public bool is_removable;
		public bool is_internal;
		public bool is_hidden;
		public bool is_app_clip;

		public string to_string () {
			var summary = new StringBuilder.sized (128);

			summary
				.append ("ApplicationInfo {")
				.append (@"\n\tbundle_identifier: \"$bundle_identifier\",");
			if (bundle_version != null)
				summary.append (@"\n\tbundle_version: \"$bundle_version\",");
			summary.append (@"\n\tname: \"$name\",");
			if (version != null)
				summary.append (@"\n\tversion: \"$version\",");
			summary
				.append (@"\n\tpath: \"$path\",")
				.append (@"\n\tis_first_party: $is_first_party,")
				.append (@"\n\tis_developer_app: $is_developer_app,")
				.append (@"\n\tis_removable: $is_removable,")
				.append (@"\n\tis_internal: $is_internal,")
				.append (@"\n\tis_hidden: $is_hidden,")
				.append (@"\n\tis_app_clip: $is_app_clip,")
				.append ("\n}");

			return summary.str;
		}
	}

	public class ProcessInfo {
		public uint pid;
		public string path;

		public string to_string () {
			return "ProcessInfo { pid: %u, path: \"%s\" }".printf (pid, path);
		}
	}

	public abstract class TrustedService : Object, AsyncInitable {
		public IOStream stream {
			get;
			construct;
		}

		private Connection connection;

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			connection = new Connection (stream);
			connection.activate ();

			return true;
		}

		public void close () {
			connection.cancel ();
		}

		protected async ObjectReader invoke (string feature_identifier, Bytes? input = null, Cancellable? cancellable)
				throws Error, IOError {
			var request = new BodyBuilder ()
				.begin_dictionary ()
					.set_member_name ("CoreDevice.featureIdentifier")
					.add_string_value (feature_identifier)
					.set_member_name ("CoreDevice.action")
					.begin_dictionary ()
					.end_dictionary ()
					.set_member_name ("CoreDevice.input");

			if (input != null)
				request.add_raw_value (input);
			else
				request.add_null_value ();

			request
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
				.end_dictionary ();

			Message raw_response = yield connection.request (request.build (), cancellable);

			var response = new ObjectReader (raw_response.body);
			response.read_member ("CoreDevice.output");
			return response;
		}
	}

	public sealed class Connection : Object {
		public signal void close (Error? error);
		public signal void message (Message msg);

		public IOStream stream {
			get;
			construct;
		}

		public State state {
			get;
			private set;
			default = INACTIVE;
		}

		private Cancellable io_cancellable = new Cancellable ();

		private Error? pending_error;

		private Promise<bool> ready = new Promise<bool> ();
		private Message? root_helo;
		private Message? reply_helo;
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
			INACTIVE,
			ACTIVE,
			CLOSED,
		}

		public Connection (IOStream stream) {
			Object (stream: stream);
		}

		construct {
			NGHttp2.SessionCallbacks callbacks;
			NGHttp2.SessionCallbacks.make (out callbacks);

			callbacks.set_send_callback ((session, data, flags, user_data) => {
				Connection * self = user_data;
				return self->on_send (data, flags);
			});
			callbacks.set_on_frame_send_callback ((session, frame, user_data) => {
				Connection * self = user_data;
				return self->on_frame_send (frame);
			});
			callbacks.set_on_frame_not_send_callback ((session, frame, lib_error_code, user_data) => {
				Connection * self = user_data;
				return self->on_frame_not_send (frame, lib_error_code);
			});
			callbacks.set_on_data_chunk_recv_callback ((session, flags, stream_id, data, user_data) => {
				Connection * self = user_data;
				return self->on_data_chunk_recv (flags, stream_id, data);
			});
			callbacks.set_on_frame_recv_callback ((session, frame, user_data) => {
				Connection * self = user_data;
				return self->on_frame_recv (frame);
			});
			callbacks.set_on_stream_close_callback ((session, stream_id, error_code, user_data) => {
				Connection * self = user_data;
				return self->on_stream_close (stream_id, error_code);
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

		public void activate () {
			do_activate.begin ();
		}

		private async void do_activate () {
			try {
				is_processing_messages = true;
				process_incoming_messages.begin ();

				session.submit_settings (NGHttp2.Flag.NONE, {
					{ MAX_CONCURRENT_STREAMS, 100 },
					{ INITIAL_WINDOW_SIZE, 1048576 },
				});

				session.set_local_window_size (NGHttp2.Flag.NONE, 0, 1048576);

				root_stream = make_stream ();

				Bytes header_request = new MessageBuilder (HEADER)
					.add_body (new BodyBuilder ()
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
				if (e is Error && pending_error == null)
					pending_error = (Error) e;
				cancel ();
			}
		}

		public void cancel () {
			io_cancellable.cancel ();
		}

		public async PeerInfo wait_until_ready (Cancellable? cancellable = null) throws Error, IOError {
			yield ready.future.wait_async (cancellable);

			return new PeerInfo () {
				metadata = root_helo.body,
			};
		}

		public async Message request (Bytes body, Cancellable? cancellable = null) throws Error, IOError {
			uint64 request_id = make_message_id ();

			Bytes raw_request = new MessageBuilder (MSG)
				.add_flags (WANTS_REPLY)
				.add_id (request_id)
				.add_body (body)
				.build ();

			printerr ("\n>>> %s\n", Message.parse (raw_request.get_data ()).to_string ());

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
				if (completed)
					return;
				this.result = result;
				handler ();
				handler = null;
			}

			public void complete_with_error (GLib.Error error) {
				if (completed)
					return;
				this.error = error;
				handler ();
				handler = null;
			}
		}

		public async void post (Bytes body, Cancellable? cancellable = null) throws Error, IOError {
			Bytes raw_request = new MessageBuilder (MSG)
				.add_id (make_message_id ())
				.add_body (body)
				.build ();

			printerr ("\n>>> %s\n", Message.parse (raw_request.get_data ()).to_string ());

			yield root_stream.submit_data (raw_request, cancellable);
		}

		private void on_header (Message msg, Stream sender) {
			if (sender == root_stream) {
				if (root_helo == null)
					root_helo = msg;
			} else if (sender == reply_stream) {
				if (reply_helo == null)
					reply_helo = msg;
			}

			if (!ready.future.ready && root_helo != null && reply_helo != null)
				ready.resolve (true);
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
			InputStream input = stream.get_input_stream ();

			var buffer = new uint8[4096];

			while (is_processing_messages) {
				try {
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
					if (e is Error && pending_error == null)
						pending_error = (Error) e;
					is_processing_messages = false;
				}
			}

			Error error = (pending_error != null)
				? pending_error
				: new Error.TRANSPORT ("Connection closed");

			foreach (var r in pending_responses.values.to_array ())
				r.complete_with_error (error);
			pending_responses.clear ();

			if (!ready.future.ready)
				ready.reject (error);

			state = CLOSED;

			close (pending_error);
			pending_error = null;
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
				yield stream.get_output_stream ().write_all_async (buffer, Priority.DEFAULT, io_cancellable,
					out bytes_written);
			} catch (GLib.Error e) {
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
			io_cancellable.cancel ();
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

			private weak Connection parent;

			private Gee.Deque<SubmitOperation> submissions = new Gee.ArrayQueue<SubmitOperation> ();
			private SubmitOperation? current_submission = null;
			private ByteArray incoming_message = new ByteArray ();

			public Stream (Connection parent, int32 id) {
				this.parent = parent;
				this.id = id;
			}

			public async void submit_data (Bytes bytes, Cancellable? cancellable) throws Error, IOError {
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

				printerr ("\n<<< [stream_id=%d] %s\n", id, msg.to_string ());

				switch (msg.type) {
					case HEADER:
						parent.on_header (msg, this);
						break;
					case MSG:
						if ((msg.flags & MessageFlags.IS_REPLY) != 0)
							parent.on_reply (msg, this);
						else if ((msg.flags & (MessageFlags.WANTS_REPLY | MessageFlags.IS_REPLY)) == 0)
							parent.message (msg);
						break;
					case PING:
						break;
				}

				return 0;
			}
		}
	}

	public class PeerInfo {
		public Variant? metadata;
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

	public class BodyBuilder : ObjectBuilder {
		public BodyBuilder () {
			base ();

			builder
				.append_uint32 (SerializedObject.MAGIC)
				.append_uint32 (SerializedObject.VERSION);
		}
	}

	public class ObjectBuilder {
		protected BufferBuilder builder = new BufferBuilder (8, LITTLE_ENDIAN);
		private Gee.Deque<Scope> scopes = new Gee.ArrayQueue<Scope> ();

		public ObjectBuilder () {
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

		public unowned ObjectBuilder add_bool_value (bool val) {
			begin_object (BOOL).append_uint32 ((uint32) val);
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

		public unowned ObjectBuilder add_data_value (Bytes val) {
			begin_object (DATA)
				.append_uint32 (val.length)
				.append_bytes (val)
				.align (4);
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

		public unowned ObjectBuilder add_raw_value (Bytes val) {
			peek_scope ().num_objects++;
			builder.append_bytes (val);
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

			return Variant.new_from_data (new VariantType.array (VariantType.BYTE), bytes.get_data (), true, bytes);
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

	public class ObjectReader {
		public Variant root_object {
			get {
				return scopes.peek_head ().val;
			}
		}

		public Variant current_object {
			get {
				return scopes.peek_tail ().val;
			}
		}

		private Gee.Deque<Scope> scopes = new Gee.ArrayQueue<Scope> ();

		public ObjectReader (Variant v) {
			push_scope (v);
		}

		public bool has_member (string name) throws Error {
			var scope = peek_scope ();
			if (scope.dict == null)
				throw new Error.PROTOCOL ("Dictionary expected, but at %s", scope.val.print (true));
			return scope.dict.contains (name);
		}

		public unowned ObjectReader read_member (string name) throws Error {
			var scope = peek_scope ();
			if (scope.dict == null)
				throw new Error.PROTOCOL ("Dictionary expected, but at %s", scope.val.print (true));

			Variant? v = scope.dict.lookup_value (name, null);
			if (v == null)
				throw new Error.PROTOCOL ("Key '%s' not found in dictionary: %s", name, scope.val.print (true));

			push_scope (v);

			return this;
		}

		public unowned ObjectReader end_member () {
			pop_scope ();

			return this;
		}

		public uint count_elements () throws Error {
			var scope = peek_scope ();
			scope.check_array ();
			return (uint) scope.val.n_children ();
		}

		public unowned ObjectReader read_element (uint index) throws Error {
			var scope = peek_scope ();
			scope.check_array ();
			push_scope (scope.val.get_child_value (index).get_variant ());

			return this;
		}

		public unowned ObjectReader end_element () throws Error {
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

		public Bytes get_data_value () throws Error {
			return peek_scope ().get_value (new VariantType.array (VariantType.BYTE)).get_data_as_bytes ();
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
			public bool is_array = false;

			public Scope (Variant v) {
				val = v;

				VariantType t = v.get_type ();
				if (t.equal (VariantType.VARDICT))
					dict = new VariantDict (v);
				else if (t.is_subtype_of (VariantType.ARRAY))
					is_array = true;
			}

			public Variant get_value (VariantType expected_type) throws Error {
				if (!val.get_type ().equal (expected_type)) {
					throw new Error.PROTOCOL ("Expected type '%s', got '%s'",
						(string) expected_type.peek_string (),
						(string) val.get_type ().peek_string ());
				}

				return val;
			}

			public void check_array () throws Error {
				if (!is_array)
					throw new Error.PROTOCOL ("Array expected, but at %s", val.print (true));
			}
		}
	}

	namespace SerializedObject {
		public const uint32 MAGIC = 0x42133742;
		public const uint32 VERSION = 5;
	}

	private uint8[] get_raw_public_key (Key key) {
		size_t size = 0;
		key.get_raw_public_key (null, ref size);
		var pubkey = new uint8[size];
		key.get_raw_public_key (pubkey, ref size);
		return pubkey;
	}

	private Key make_x25519_keypair () {
		var ctx = new KeyContext.for_key_type (X25519);
		ctx.keygen_init ();

		Key? keypair = null;
		ctx.keygen (ref keypair);

		return keypair;
	}

	private Bytes derive_shared_key (Key local_keypair, Key remote_pubkey) {
		var ctx = new KeyContext.for_key (local_keypair);
		ctx.derive_init ();
		ctx.derive_set_peer (remote_pubkey);

		size_t key_size = 0;
		ctx.derive (null, ref key_size);

		var shared_key = new uint8[key_size];
		ctx.derive (shared_key, ref key_size);

		return new Bytes.take ((owned) shared_key);
	}

	private Bytes derive_chacha_key (uint8[] shared_key, string info, string? salt = null) {
		var kdf = KeyDerivationFunction.fetch (null, KeyDerivationAlgorithm.HKDF);

		var kdf_ctx = new KeyDerivationContext (kdf);

		size_t return_size = OpenSSL.ParamReturnSize.UNMODIFIED;

		var kdf_params = new OpenSSL.Param[] {
			{ KeyDerivationParameter.DIGEST, UTF8_STRING, OpenSSL.ShortName.sha512.data, return_size },
			{ KeyDerivationParameter.KEY, OCTET_STRING, shared_key, return_size },
			{ KeyDerivationParameter.INFO, OCTET_STRING, info.data, return_size },
		};

		if (salt != null) {
			OpenSSL.Param p = { KeyDerivationParameter.SALT, OCTET_STRING, salt.data, return_size };
			kdf_params += p;
		}

		OpenSSL.Param terminator = { null, INTEGER, null, return_size };
		kdf_params += terminator;

		var derived_key = new uint8[32];
		kdf_ctx.derive (derived_key, kdf_params);

		return new Bytes.take ((owned) derived_key);
	}

	// https://gist.github.com/phako/96b36b5070beaf7eee27
	public void hexdump (uint8[] data) {
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

	private string variant_to_pretty_string (Variant v) {
		var sink = new StringBuilder.sized (128);
		print_variant (v, sink);
		return (owned) sink.str;
	}

	private void print_variant (Variant v, StringBuilder sink, uint depth = 0, bool initial = true) {
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
		} else if (type.is_array () && !type.equal (new VariantType.array (VariantType.BYTE))) {
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

	private void append_indent (uint depth, StringBuilder sink) {
		for (uint i = 0; i != depth; i++)
			sink.append_c ('\t');
	}
}
