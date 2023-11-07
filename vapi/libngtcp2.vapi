[CCode (cheader_filename = "ngtcp2/ngtcp2.h", cprefix = "ngtcp2_", gir_namespace = "NGTcp2", gir_version = "1.0")]
namespace NGTCP2 {
	[Compact]
	[CCode (cname = "ngtcp2_conn", cprefix = "ngtcp2_conn_", free_function = "ngtcp2_conn_del")]
	public class Connection {
		[CCode (cname = "ngtcp2_conn_client_new_versioned")]
		public static int make_client (out Connection conn, ConnectionID dcid, ConnectionID scid, Path path,
			ProtocolVersion client_chosen_version, CallbacksVersion callbacks_version, Callbacks callbacks,
			SettingsVersion settings_version, Settings settings, TransportParamsVersion transport_params_version,
			TransportParams params, MemoryAllocator mem, void * user_data);
	}

	[CCode (cname = "ngtcp2_cid")]
	public struct ConnectionID {
		[CCode (array_length_cname = "datalen")]
		public uint8[] data;
	}

	[CCode (cname = "ngtcp2_path")]
	public struct Path {
		public Address local;
		public Address remote;
		public void * user_data;
	}

	[CCode (cname = "ngtcp2_addr")]
	public struct Address {
		public SocketAddress? addr;
		public SocketLength addrlen;
	}

	[CCode (cname = "ngtcp2_sockaddr")]
	public struct SocketAddress {
		public SocketAddressFamily sa_family;
		public uint8 sa_data[14];
	}

	[CCode (cname = "ngtcp2_sa_family", cprefix = "NGTCP2_AF_", has_type_id = false)]
	public enum SocketAddressFamily {
		INET,
		INET6,
	}

	[CCode (cname = "ngtcp2_socklen")]
	public struct SocketLength : uint32 {
	}

	[CCode (cname = "uint32_t", cprefix = "NGTCP2_PROTO_VER_", has_type_id = false)]
	public enum ProtocolVersion {
		V1,
		V2,
		MIN,
		MAX,
	}

	[CCode (cname = "int", cprefix = "NGTCP2_CALLBACKS_", has_type_id = false)]
	public enum CallbacksVersion {
		[CCode (cname = "NGTCP2_CALLBACKS_VERSION")]
		DEFAULT,
		V1,
	}

	[CCode (cname = "ngtcp2_callbacks")]
	public struct Callbacks {
		public ClientInitial? client_initial;
		public RecvClientInitial? recv_client_initial;
		public RecvCryptoData recv_crypto_data;
		public HandshakeCompleted? handshake_completed;
		public RecvVersionNegotiation? recv_version_negotiation;
		public Encrypt encrypt;
		public Decrypt decrypt;
		public HpMask hp_mask;
		public RecvStreamData? recv_stream_data;
		public AckedStreamDataOffset? acked_stream_data_offset;
		public StreamOpen? stream_open;
		public StreamClose? stream_close;
		public RecvStatelessReset? recv_stateless_reset;
		public RecvRetry? recv_retry;
		public ExtendMaxStreams? extend_max_local_streams_bidi;
		public ExtendMaxStreams? extend_max_local_streams_uni;
		public Rand? rand;
		public GetNewConnectionId get_new_connection_id;
		public RemoveConnectionId? remove_connection_id;
		public UpdateKey update_key;
		public PathValidation? path_validation;
		public SelectPreferredAddr? select_preferred_addr;
		public StreamReset? stream_reset;
		public ExtendMaxStreams? extend_max_remote_streams_bidi;
		public ExtendMaxStreams? extend_max_remote_streams_uni;
		public ExtendMaxStreamData? extend_max_stream_data;
		public ConnectionIdStatus? dcid_status;
		public HandshakeConfirmed? handshake_confirmed;
		public RecvNewToken? recv_new_token;
		public DeleteCryptoAeadCtx delete_crypto_aead_ctx;
		public DeleteCryptoCipherCtx delete_crypto_cipher_ctx;
		public RecvDatagram? recv_datagram;
		public AckDatagram? ack_datagram;
		public LostDatagram? lost_datagram;
		public GetPathChallengeData get_path_challenge_data;
		public StreamStopSending? stream_stop_sending;
		public VersionNegotiation version_negotiation;
		public RecvKey recv_rx_key;
		public RecvKey recv_tx_key;
		public TlsEarlyDataRejected? tls_early_data_rejected;
	}

	[CCode (cname = "ngtcp2_client_initial", has_target = false)]
	public delegate int ClientInitial (Connection conn, void * user_data);
	[CCode (cname = "ngtcp2_recv_client_initial", has_target = false)]
	public delegate int RecvClientInitial (Connection conn, Cid dcid, void * user_data);
	[CCode (cname = "ngtcp2_recv_crypto_data", has_target = false)]
	public delegate int RecvCryptoData (Connection conn, EncryptionLevel encryption_level, uint64 offset,
		[CCode (array_length_type = "size_t")] uint8_t[] data, void * user_data);
	[CCode (cname = "ngtcp2_handshake_completed", has_target = false)]
	public delegate int HandshakeCompleted (Connection conn, void * user_data);
	[CCode (cname = "ngtcp2_recv_version_negotiation", has_target = false)]
	public delegate int RecvVersionNegotiation (Connection conn, PacketHeader hd, [CCode (array_length_type = "size_t")] uint32[] sv,
		void * user_data);
	[CCode (cname = "ngtcp2_encrypt", has_target = false)]
	public delegate int Encrypt ([CCode (array_length = false)] uint8[] dest, CryptoAead aead, CryptoAeadCtx aead_ctx,
		[CCode (array_length_type = "size_t")] uint8[] plaintext,
		[CCode (array_length_type = "size_t")] uint8[] nonce,
		[CCode (array_length_type = "size_t")] uint8[] aad);
	[CCode (cname = "ngtcp2_decrypt", has_target = false)]
	public delegate int Decrypt ([CCode (array_length = false)] uint8[] dest, CryptoAead aead, CryptoAeadCtx aead_ctx,
		[CCode (array_length_type = "size_t")] uint8[] ciphertext,
		[CCode (array_length_type = "size_t")] uint8[] nonce,
		[CCode (array_length_type = "size_t")] uint8[] aad);
	[CCode (cname = "ngtcp2_hp_mask", has_target = false)]
	public delegate int HpMask ([CCode (array_length = false)] uint8_t[] dest, CryptoCipher hp, CryptoCipherCtx hp_ctx,
		[CCode (array_length = false)] uint8_t[] sample);
	[CCode (cname = "ngtcp2_recv_stream_data", has_target = false)]
	public delegate int RecvStreamData (Connection conn, uint32 flags, int64 stream_id, uint64 offset,
		[CCode (array_length_type = "size_t")] uint8[] data, void * user_data, void * stream_user_data);
	[CCode (cname = "ngtcp2_acked_stream_data_offset", has_target = false)]
	public delegate int AckedStreamDataOffset (Connection conn, int64 stream_id, uint64 offset, uint64 datalen, void * user_data,
		void * stream_user_data);
	[CCode (cname = "ngtcp2_stream_open", has_target = false)]
	public delegate int StreamOpen (Connection conn, int64 stream_id, void * user_data);
	[CCode (cname = "ngtcp2_stream_close", has_target = false)]
	public delegate int StreamClose (Connection conn, uint32 flags, int64 stream_id, uint64 app_error_code, void * user_data,
		void * stream_user_data);
	[CCode (cname = "ngtcp2_recv_stateless_reset", has_target = false)]
	public delegate int RecvStatelessReset (Connection conn, PacketStatelessReset sr, void * user_data);
	[CCode (cname = "ngtcp2_recv_retry", has_target = false)]
	public delegate int RecvRetry (Connection conn, PacketHeader hd, void * user_data);
	[CCode (cname = "ngtcp2_extend_max_streams", has_target = false)]
	public delegate int ExtendMaxStreams (Connection conn, uint64 max_streams, void * user_data);
	[CCode (cname = "ngtcp2_extend_max_stream_data", has_target = false)]
	public delegate int ExtendMaxStreamData (Connection conn, int64 stream_id, uint64 max_data, void * user_data,
		void * stream_user_data);
	[CCode (cname = "ngtcp2_rand", has_target = false)]
	public delegate void Rand ([CCode (array_length_type = "size_t")] uint8[] dest, RandCtx rand_ctx);
	[CCode (cname = "ngtcp2_get_new_connection_id", has_target = false)]
	public delegate int GetNewConnectionId (Connection conn, Cid cid, [CCode (array_length = false)] uint8_t[] token, size_t cidlen,
		void * user_data);
	[CCode (cname = "ngtcp2_remove_connection_id", has_target = false)]
	public delegate int RemoveConnectionId (Connection conn, Cid cid, void * user_data);
	[CCode (cname = "ngtcp2_update_key", has_target = false)]
	public delegate int UpdateKey (Connection conn,
		[CCode (array_length = false)] uint8[] rx_secret,
		[CCode (array_length = false)] uint8[] tx_secret,
		CryptoAeadCtx rx_aead_ctx, [CCode (array_length = false)] uint8[] rx_iv,
		CryptoAeadCtx tx_aead_ctx, [CCode (array_length = false)] uint8[] tx_iv,
		[CCode (array_length_pos = 9.1)] uint8[] current_rx_secret,
		[CCode (array_length_pos = 9.1)] uint8[] current_tx_secret,
		void * user_data);
	[CCode (cname = "ngtcp2_path_validation", has_target = false)]
	public delegate int PathValidation (Connection conn, uint32 flags, Path path, Path old_path, PathValidationResult res,
		void * user_data);
	[CCode (cname = "ngtcp2_select_preferred_addr", has_target = false)]
	public delegate int SelectPreferredAddr (Connection conn, Path dest, PreferredAddr paddr, void * user_data);
	[CCode (cname = "ngtcp2_stream_reset", has_target = false)]
	public delegate int StreamReset (Connection conn, int64 stream_id, uint64 final_size, uint64 app_error_code, void * user_data,
		void * stream_user_data);
	[CCode (cname = "ngtcp2_connection_id_status", has_target = false)]
	public delegate int ConnectionIdStatus (Connection conn, ConnectionIdStatusType type, uint64 seq, Cid cid,
		[CCode (array_length = false)] uint8[] token, void * user_data);
	[CCode (cname = "ngtcp2_handshake_confirmed", has_target = false)]
	public delegate int HandshakeConfirmed (Connection conn, void * user_data);
	[CCode (cname = "ngtcp2_recv_new_token", has_target = false)]
	public delegate int RecvNewToken (Connection conn, [CCode (array_length_type = "size_t")] uint8[] token, void * user_data);
	[CCode (cname = "ngtcp2_delete_crypto_aead_ctx", has_target = false)]
	public delegate void DeleteCryptoAeadCtx (Connection conn, CryptoAeadCtx aead_ctx, void * user_data);
	[CCode (cname = "ngtcp2_delete_crypto_cipher_ctx", has_target = false)]
	public delegate void DeleteCryptoCipherCtx (Connection conn, CryptoCipherCtx cipher_ctx, void * user_data);
	[CCode (cname = "ngtcp2_recv_datagram", has_target = false)]
	public delegate int RecvDatagram (Connection conn, uint32 flags, [CCode (array_length_type = "size_t")] uint8[] data,
		void * user_data);
	[CCode (cname = "ngtcp2_ack_datagram", has_target = false)]
	public delegate int AckDatagram (Connection conn, uint64 dgram_id, void * user_data);
	[CCode (cname = "ngtcp2_lost_datagram", has_target = false)]
	public delegate int LostDatagram (Connection conn, uint64 dgram_id, void * user_data);
	[CCode (cname = "ngtcp2_get_path_challenge_data", has_target = false)]
	public delegate int GetPathChallengeData (Connection conn, [CCode (array_length = false)] uint8[] data, void * user_data);
	[CCode (cname = "ngtcp2_stream_stop_sending", has_target = false)]
	public delegate int StreamStopSending (Connection conn, int64 stream_id, uint64 app_error_code, void * user_data,
		void * stream_user_data);
	[CCode (cname = "ngtcp2_version_negotiation", has_target = false)]
	public delegate int VersionNegotiation (Connection conn, uint32 version, Cid client_dcid, void * user_data);
	[CCode (cname = "ngtcp2_recv_key", has_target = false)]
	public delegate int RecvKey (Connection conn, EncryptionLevel level, void * user_data);
	[CCode (cname = "ngtcp2_tls_early_data_rejected", has_target = false)]
	public delegate int TlsEarlyDataRejected (Connection conn, void * user_data);
}
