[CCode (cheader_filename = "ngtcp2/ngtcp2_crypto.h", lower_case_cprefix = "ngtcp2_crypto_", gir_namespace = "NGTcp2Crypto", gir_version = "1.0")]
namespace NGTcp2.Crypto {
	public ClientInitial client_initial_cb;
	public RecvCryptoData recv_crypto_data_cb;
	public Encrypt encrypt_cb;
	public Decrypt decrypt_cb;
	public HpMask hp_mask_cb;
	public RecvRetry recv_retry_cb;
	public UpdateKey update_key_cb;
	public DeleteCryptoAeadCtx delete_crypto_aead_ctx_cb;
	public DeleteCryptoCipherCtx delete_crypto_cipher_ctx_cb;
	public GetPathChallengeData get_path_challenge_data_cb;
	public VersionNegotiation version_negotiation_cb;
}
