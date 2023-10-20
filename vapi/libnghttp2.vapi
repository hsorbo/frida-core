[CCode (cheader_filename = "nghttp2/nghttp2.h", cprefix = "nghttp2_", gir_namespace = "NGHttp2", gir_version = "1.0")]
namespace NGHttp2 {
	[Compact]
	[CCode (cname = "nghttp2_session", cprefix = "nghttp2_session_", free_function = "nghttp2_session_del")]
	public class Session {
		[CCode (cname = "nghttp2_submit_settings")]
		public int submit_settings (uint8 flags, SettingsEntry[] entries);

		[CCode (cname = "nghttp2_submit_window_update")]
		public int submit_window_update (uint8 flags, int32 stream_id, int32 window_size_increment);

		public int set_local_window_size (uint8 flags, int32 stream_id, int32 window_size);

		[CCode (cname = "nghttp2_submit_request")]
		public int32 submit_request (PrioritySpec? pri_spec, NV[] nvs, DataProvider? data_prd, void * stream_user_data);

		[CCode (cname = "nghttp2_submit_headers")]
		public int32 submit_headers (uint8 flags, int32 stream_id, PrioritySpec? pri_spec, NV[] nvs, void * stream_user_data);

		[CCode (cname = "nghttp2_submit_data")]
		public int submit_data (uint8 flags, int32 stream_id, DataProvider data_prd);

		public int send ();

		public ssize_t mem_recv (uint8[] input);

		public bool want_read ();

		public bool want_write ();

		public int consume_connection (size_t size);
	}

	[Compact]
	[CCode (cname = "nghttp2_session", cprefix = "nghttp2_session_", free_function = "nghttp2_session_del")]
	public class ClientSession : Session {
		[CCode (cname = "nghttp2_session_client_new2")]
		public static int make (out ClientSession session, SessionCallbacks callbacks, void * user_data, Option? option = null);
	}

	[Compact]
	[CCode (cname = "nghttp2_session_callbacks", cprefix = "nghttp2_session_callbacks_",
		free_function = "nghttp2_session_callbacks_del")]
	public class SessionCallbacks {
		[CCode (cname = "nghttp2_session_callbacks_new")]
		public static int make (out SessionCallbacks callbacks);

		public void set_send_callback (SendCallback callback);
		public void set_on_data_chunk_recv_callback (OnDataChunkRecvCallback callback);
		public void set_on_stream_close_callback (OnStreamCloseCallback callback);
		[CCode (cname = "nghttp2_session_callbacks_set_error_callback2")]
		public void set_error_callback (ErrorCallback callback);
	}

	[CCode (cname = "nghttp2_send_callback", has_target = false)]
	public delegate ssize_t SendCallback (Session session, [CCode (array_length_type = "size_t")] uint8[] data, int flags,
		void * user_data);

	[CCode (cname = "nghttp2_on_data_chunk_recv_callback", has_target = false)]
	public delegate int OnDataChunkRecvCallback (Session session, uint8 flags, int32 stream_id,
		[CCode (array_length_type = "size_t")] uint8[] data, void * user_data);

	[CCode (cname = "nghttp2_on_stream_close_callback", has_target = false)]
	public delegate int OnStreamCloseCallback (Session session, int32 stream_id, uint32 error_code, void * user_data);

	[CCode (cname = "nghttp2_error_callback2", has_target = false)]
	public delegate int ErrorCallback (Session session, ErrorCode code, [CCode (array_length_type = "size_t")] char[] msg,
		void * user_data);

	[Compact]
	[CCode (cname = "nghttp2_option", cprefix = "nghttp2_option_", free_function = "nghttp2_option_del")]
	public class Option {
		[CCode (cname = "nghttp2_option_new")]
		public static int make (out Option option);

		public void set_no_auto_window_update (bool val);
		public void set_peer_max_concurrent_streams (uint32 val);
		public void set_no_recv_client_magic (bool val);
		public void set_no_http_messaging (bool val);
		public void set_no_http_semantics (bool val);
		public void set_max_reserved_remote_streams (uint32 val);
		public void set_user_recv_extension_type (uint8 type);
		public void set_builtin_recv_extension_type (uint8 type);
		public void set_no_auto_ping_ack (bool val);
		public void set_max_send_header_block_length (size_t val);
		public void set_max_deflate_dynamic_table_size (size_t val);
		public void set_no_closed_streams (bool val);
		public void set_max_outbound_ack (size_t val);
		public void set_max_settings (size_t val);
		public void set_server_fallback_rfc7540_priorities (bool val);
		public void set_no_rfc9113_leading_and_trailing_ws_validation (bool val);
	}

	[CCode (cname = "nghttp2_settings_entry")]
	public struct SettingsEntry {
		public SettingsId settings_id;
		public uint32 value;
	}

	[CCode (cname = "nghttp2_settings_id", cprefix = "NGHTTP2_SETTINGS_", has_type_id = false)]
	public enum SettingsId {
		HEADER_TABLE_SIZE,
		ENABLE_PUSH,
		MAX_CONCURRENT_STREAMS,
		INITIAL_WINDOW_SIZE,
		MAX_FRAME_SIZE,
		MAX_HEADER_LIST_SIZE,
		ENABLE_CONNECT_PROTOCOL,
		NO_RFC7540_PRIORITIES,
	}

	[CCode (cname = "nghttp2_priority_spec")]
	public struct PrioritySpec {
		public int32 stream_id;
		public int32 weight;
		public uint8 exclusive;
	}

	[CCode (cname = "nghttp2_nv")]
	public struct NV {
		public uint8 * name;
		public uint8 * value;
		public size_t namelen;
		public size_t valuelen;
		public NVFlag flags;
	}

	[CCode (cname = "nghttp2_nv_flag", cprefix = "NGHTTP2_NV_FLAG_", has_type_id = false)]
	[Flags]
	public enum NVFlag {
		NONE,
		NO_INDEX,
		NO_COPY_NAME,
		NO_COPY_VALUE,
	}

	[CCode (cname = "nghttp2_data_provider")]
	public struct DataProvider {
		public DataSource source;
		public DataSourceReadCallback read_callback;
	}

	[CCode (cname = "nghttp2_data_source")]
	public struct DataSource {
		public void * ptr;
	}

	[CCode (cname = "nghttp2_data_source_read_callback", has_target = false)]
	public delegate ssize_t DataSourceReadCallback (Session session, int32 stream_id,
		[CCode (array_length_type = "size_t")] uint8[] buf, ref uint32 data_flags, DataSource source, void * user_data);

	[CCode (cname = "nghttp2_strerror")]
	public unowned string strerror (ssize_t result);

	[CCode (cname = "nghttp2_error", cprefix = "NGHTTP2_ERR_", has_type_id = false)]
	public enum ErrorCode {
		INVALID_ARGUMENT,
		BUFFER_ERROR,
		UNSUPPORTED_VERSION,
		WOULDBLOCK,
		PROTO,
		INVALID_FRAME,
		EOF,
		DEFERRED,
		STREAM_ID_NOT_AVAILABLE,
		STREAM_CLOSED,
		STREAM_CLOSING,
		STREAM_SHUT_WR,
		INVALID_STREAM_ID,
		INVALID_STREAM_STATE,
		DEFERRED_DATA_EXIST,
		START_STREAM_NOT_ALLOWED,
		GOAWAY_ALREADY_SENT,
		INVALID_HEADER_BLOCK,
		INVALID_STATE,
		TEMPORAL_CALLBACK_FAILURE,
		FRAME_SIZE_ERROR,
		HEADER_COMP,
		FLOW_CONTROL,
		INSUFF_BUFSIZE,
		PAUSE,
		TOO_MANY_INFLIGHT_SETTINGS,
		PUSH_DISABLED,
		DATA_EXIST,
		SESSION_CLOSING,
		HTTP_HEADER,
		HTTP_MESSAGING,
		REFUSED_STREAM,
		INTERNAL,
		CANCEL,
		SETTINGS_EXPECTED,
		TOO_MANY_SETTINGS,
		FATAL,
		NOMEM,
		CALLBACK_FAILURE,
		BAD_CLIENT_MAGIC,
		FLOODED,
	}

	[CCode (cname = "nghttp2_flag", cprefix = "NGHTTP2_FLAG_", has_type_id = false)]
	[Flags]
	public enum Flag {
		NONE,
		END_STREAM,
		END_HEADERS,
		ACK,
		PADDED,
		PRIORITY,
	}

	[CCode (cname = "nghttp2_data_flag", cprefix = "NGHTTP2_DATA_FLAG_", has_type_id = false)]
	[Flags]
	public enum DataFlag {
		NONE,
		EOF,
		NO_END_STREAM,
		NO_COPY,
	}
}
