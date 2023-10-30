namespace OpenSSL {
	[Compact]
	[CCode (cheader_filename = "openssl/evp.h", cname = "EVP_PKEY_CTX", cprefix = "EVP_PKEY_", free_function = "EVP_PKEY_CTX_free")]
	public class PrivateKeyContext {
		[CCode (cname = "EVP_PKEY_CTX_new_id")]
		public PrivateKeyContext.from_id (PrivateKeyType id, Engine? engine = null);

		public int keygen_init ();
		public int keygen (ref PrivateKey pkey);
	}

	[Compact]
	[CCode (cheader_filename = "openssl/evp.h", cname = "EVP_PKEY", cprefix = "EVP_PKEY_", free_function = "EVP_PKEY_free")]
	public class PrivateKey {
		public int get_raw_public_key (uint8 * pub, ref size_t len);
		public int get_raw_private_key (uint8 * priv, ref size_t len);
	}

	[CCode (cheader_filename = "openssl/evp.h", cname = "int", cprefix = "EVP_PKEY_", has_type_id = false)]
	public enum PrivateKeyType {
		NONE,
		RSA,
		RSA2,
		RSA_PSS,
		DSA,
		DSA1,
		DSA2,
		DSA3,
		DSA4,
		DH,
		DHX,
		EC,
		SM2,
		HMAC,
		CMAC,
		SCRYPT,
		TLS1_PRF,
		HKDF,
		POLY1305,
		SIPHASH,
		X25519,
		ED25519,
		X448,
		ED448,
		KEYMGMT,
	}

	[Compact]
	[CCode (cheader_filename = "openssl/engine.h", cname = "ENGINE")]
	public class Engine {
	}
}
