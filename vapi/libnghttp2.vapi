[CCode (cheader_filename = "nghttp2/nghttp2.h", gir_namespace = "Nghttp2", gir_version = "1.0")]
namespace Nghttp2 {
	[Compact]
	[CCode (cname = "nghttp2_session", free_function = "nghttp2_session_del")]
	public class Session {
		[CCode (cname = "nghttp2_session_client_new")]
		public static void make_client (out Session session, SessionCallbacks callbacks, void * user_data);

		public ssize_t mem_recv ([CCode (array_length_type = "size_t")] uint8[] input);
	}

	[Compact]
	[CCode (cname = "nghttp2_session_callbacks", free_function = "nghttp2_session_callbacks_del")]
	public class SessionCallbacks {
		[CCode (cname = "nghttp2_session_callbacks_new")]
		public static void make (out SessionCallbacks callbacks);

		public void set_send_callback (SendCallback callback);
	}

	[CCode (cname = "nghttp2_send_callback", has_target = false)]
	public delegate ssize_t SendCallback (Session session, [CCode (array_length_type = "size_t")] uint8[] data, int flags,
		void * user_data);

	public unowned string strerror (ssize_t result);

	[CCode (cprefix = "NGHTTP2_ERR_", has_type_id = false)]
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
}
