[CCode (gir_namespace = "OpenSSL", gir_version = "1.0")]
namespace OpenSSL {
	[CCode (cheader_filename = "openssl/evp.h")]
	namespace Envelope {
		[Compact]
		[CCode (cname = "EVP_PKEY_CTX", cprefix = "EVP_PKEY_", free_function = "EVP_PKEY_CTX_free")]
		public class KeyContext {
			[CCode (cname = "EVP_PKEY_CTX_new")]
			public KeyContext.for_key (Key key, Engine? engine = null);
			[CCode (cname = "EVP_PKEY_CTX_new_id")]
			public KeyContext.for_key_type (KeyType type, Engine? engine = null);

			public int keygen_init ();
			public int keygen (ref Key pkey);

			public int derive_init ();
			public int derive_set_peer (Key peer);
			public int derive (uint8 * key, ref size_t keylen);
		}

		[Compact]
		[CCode (cname = "EVP_PKEY", cprefix = "EVP_PKEY_", free_function = "EVP_PKEY_free")]
		public class Key {
			[CCode (cname = "EVP_PKEY_new_raw_public_key")]
			public Key.from_raw_public_key (KeyType type, Engine? engine, uint8[] pub);

			public int get_raw_public_key (uint8 * pub, ref size_t len);
			public int get_raw_private_key (uint8 * priv, ref size_t len);
		}

		[CCode (cname = "int", cprefix = "EVP_PKEY_", has_type_id = false)]
		public enum KeyType {
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
		[CCode (cheader_filename = "openssl/kdf.h", cname = "EVP_KDF", cprefix = "EVP_KDF_", free_function = "EVP_KDF_free")]
		public class KeyDerivationFunction {
			public static KeyDerivationFunction? fetch (LibraryContext? ctx, string algorithm, string? properties = null);
		}

		[Compact]
		[CCode (cheader_filename = "openssl/kdf.h", cname = "EVP_KDF_CTX", cprefix = "EVP_KDF_", free_function = "EVP_KDF_CTX_free")]
		public class KeyDerivationContext {
			[CCode (cname = "EVP_KDF_CTX_new")]
			public KeyDerivationContext (KeyDerivationFunction kdf);

			public int derive (uint8[] key, [CCode (array_length = false)] Param[] params);
		}

		[CCode (cheader_filename = "openssl/core_names.h", lower_case_cprefix = "OSSL_KDF_NAME_")]
		namespace KeyDerivationAlgorithm {
			public const string HKDF;
			public const string TLS1_3_KDF;
			public const string PBKDF1;
			public const string PBKDF2;
			public const string SCRYPT;
			public const string SSHKDF;
			public const string SSKDF;
			public const string TLS1_PRF;
			public const string X942KDF_ASN1;
			public const string X942KDF_CONCAT;
			public const string X963KDF;
			public const string KBKDF;
			public const string KRB5KDF;
		}

		[CCode (cheader_filename = "openssl/core_names.h", lower_case_cprefix = "OSSL_KDF_PARAM_")]
		namespace KeyDerivationParameter {
			public const string SECRET;
			public const string KEY;
			public const string SALT;
			public const string PASSWORD;
			public const string PREFIX;
			public const string LABEL;
			public const string DATA;
			public const string DIGEST;
			public const string CIPHER;
			public const string MAC;
			public const string MAC_SIZE;
			public const string PROPERTIES;
			public const string ITER;
			public const string MODE;
			public const string PKCS5;
			public const string UKM;
			public const string CEK_ALG;
			public const string SCRYPT_N;
			public const string SCRYPT_R;
			public const string SCRYPT_P;
			public const string SCRYPT_MAXMEM;
			public const string INFO;
			public const string SEED;
			public const string SSHKDF_XCGHASH;
			public const string SSHKDF_SESSION_ID;
			public const string SSHKDF_TYPE;
			public const string SIZE;
			public const string CONSTANT;
			public const string PKCS12_ID;
			public const string KBKDF_USE_L;
			public const string KBKDF_USE_SEPARATOR;
			public const string X942_ACVPINFO;
			public const string X942_PARTYUINFO;
			public const string X942_PARTYVINFO;
			public const string X942_SUPP_PUBINFO;
			public const string X942_SUPP_PRIVINFO;
			public const string X942_USE_KEYBITS;
		}

		[Compact]
		[CCode (cname = "EVP_CIPHER_CTX", cprefix = "EVP_CIPHER_CTX_")]
		public class CipherContext {
			public CipherContext ();

			public int reset ();

			[CCode (cname = "EVP_EncryptInit")]
			public int encrypt_init (Cipher cipher,
				[CCode (array_length = false)] uint8[] key,
				[CCode (array_length = false)] uint8[] iv);
		}

		[Compact]
		[CCode (cname = "EVP_CIPHER", cprefix = "EVP_CIPHER_")]
		public class Cipher {
			public Cipher? fetch (LibraryContext ctx, string algorithm, string? properties = null);
		}
	}

	[Compact]
	[CCode (cheader_filename = "openssl/engine.h", cname = "ENGINE")]
	public class Engine {
	}

	[Compact]
	[CCode (cheader_filename = "openssl/types.h", cname = "OSSL_LIB_CTX")]
	public class LibraryContext {
	}

	[CCode (cheader_filename = "openssl/core.h", cname = "OSSL_PARAM", destroy_function = "")]
	public struct Param {
		public string? key;
		public ParamDataType data_type;
		[CCode (array_length_cname = "data_size")]
		public uint8[]? data;
		public size_t return_size;
	}

	[CCode (cheader_filename = "openssl/core.h", cname = "guint", cprefix = "OSSL_PARAM_", has_type_id = false)]
	public enum ParamDataType {
		INTEGER,
		UNSIGNED_INTEGER,
		REAL,
		UTF8_STRING,
		OCTET_STRING,
		UTF8_PTR,
		OCTET_PTR,
	}

	[CCode (cheader_filename = "openssl/core.h", cname = "size_t", cprefix = "OSSL_PARAM_", has_type_id = false)]
	public enum ParamReturnSize {
		UNMODIFIED,
	}

	[CCode (cheader_filename = "openssl/objects.h", lower_case_cprefix = "SN_")]
	namespace ShortName {
		public const string sha256;
		public const string sha384;
		public const string sha512;
	}
}
