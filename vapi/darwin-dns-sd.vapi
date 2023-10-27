[CCode (cprefix = "", gir_namespace = "Darwin", gir_version = "1.0")]
namespace Darwin {
	[CCode (cheader_filename = "dns_sd.h", cname = "DNSServiceRef", ref_function = "", unref_function = "")]
	public class DNSService {
		[CCode (cname = "DNSServiceCreateConnection")]
		public static ErrorType create_connection (out DNSService service);

		[CCode (cname = "DNSServiceRefDeallocate")]
		public void deallocate ();

		[CCode (cname = "DNSServiceSetDispatchQueue")]
		public ErrorType set_dispatch_queue (DispatchQueue queue);

		[CCode (cname = "DNSServiceBrowse")]
		public static ErrorType browse (ref DNSService sd_ref, Flags flags, uint32 interface_index, string regtype, string? domain,
			BrowseReply callback);

		[CCode (cname = "DNSServiceResolve")]
		public static ErrorType resolve (ref DNSService sd_ref, Flags flags, uint32 interface_index, string name, string regtype,
			string domain, ResolveReply callback);

		[CCode (cname = "DNSServiceBrowseReply")]
		public delegate void BrowseReply (DNSService sd_ref, Flags flags, uint32 interface_index, ErrorType error_code,
			string service_name, string regtype, string reply_domain);

		[CCode (cname = "DNSServiceResolveReply")]
		public delegate void ResolveReply (DNSService sd_ref, Flags flags, uint32 interface_index, ErrorType error_code,
			string fullname, string hosttarget, uint16 port, uint16 txt_len, char * txt_record);

		[CCode (cname = "DNSServiceErrorType", cprefix = "kDNSServiceErr_", has_type_id = false)]
		public enum ErrorType {
			NoError,
			Unknown,
			NoSuchName,
			NoMemory,
			BadParam,
			BadReference,
			BadState,
			BadFlags,
			Unsupported,
			NotInitialized,
			AlreadyRegistered,
			NameConflict,
			Invalid,
			Firewall,
			Incompatible,
			BadInterfaceIndex,
			Refused,
			NoSuchRecord,
			NoAuth,
			NoSuchKey,
			NATTraversal,
			DoubleNAT,
			BadTime,
			BadSig,
			BadKey,
			Transient,
			ServiceNotRunning,
			NATPortMappingUnsupported,
			NATPortMappingDisabled,
			NoRouter,
			PollingMode,
			Timeout,
			DefunctConnection,
			PolicyDenied,
			NotPermitted,
		}

		[CCode (cname = "DNSServiceFlags", cprefix = "kDNSServiceFlags", has_type_id = false)]
		[Flags]
		public enum Flags {
			MoreComing,
			QueueRequest,
			AutoTrigger,
			Add,
			Default,
			NoAutoRename,
			Shared,
			Unique,
			BrowseDomains,
			RegistrationDomains,
			LongLivedQuery,
			AllowRemoteQuery,
			ForceMulticast,
			Force,
			KnownUnique,
			ReturnIntermediates,
			ShareConnection,
			SuppressUnusable,
			Timeout,
			IncludeP2P,
			WakeOnResolve,
			BackgroundTrafficClass,
			IncludeAWDL,
			EnableDNSSEC,
			Validate,
			Secure,
			Insecure,
			Bogus,
			Indeterminate,
			UnicastResponse,
			ValidateOptional,
			WakeOnlyService,
			ThresholdOne,
			ThresholdFinder,
			ThresholdReached,
			PrivateOne,
			PrivateTwo,
			PrivateThree,
			PrivateFour,
			PrivateFive,
			[CCode (cname = "kDNSServiceFlagAnsweredFromCache")]
			AnsweredFromCache,
			AllowExpiredAnswers,
			ExpiredAnswer,
		}
	}
}
