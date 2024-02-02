namespace Darwin.Xnu {
	[CCode (cname = "kern_return_t", cheader_filename = "mach/mach_error.h", cprefix = "KERN_", has_type_id = false)]
	public enum KernReturn {
		SUCCESS,
		INVALID_ADDRESS,
		PROTECTION_FAILURE,
		NO_SPACE,
		INVALID_ARGUMENT,
		FAILURE,
		RESOURCE_SHORTAGE,
		NOT_RECEIVER,
		NO_ACCESS,
		MEMORY_FAILURE,
		MEMORY_ERROR,
		ALREADY_IN_SET,
		NOT_IN_SET,
		NAME_EXISTS,
		ABORTED,
		INVALID_NAME,
		INVALID_TASK,
		INVALID_RIGHT,
		INVALID_VALUE,
		UREFS_OVERFLOW,
		INVALID_CAPABILITY,
		RIGHT_EXISTS,
		INVALID_HOST,
		MEMORY_PRESENT,
		MEMORY_DATA_MOVED,
		MEMORY_RESTART_COPY,
		INVALID_PROCESSOR_SET,
		POLICY_LIMIT,
		INVALID_POLICY,
		INVALID_OBJECT,
		ALREADY_WAITING,
		DEFAULT_SET,
		EXCEPTION_PROTECTED,
		INVALID_LEDGER,
		INVALID_MEMORY_CONTROL,
		INVALID_SECURITY,
		NOT_DEPRESSED,
		TERMINATED,
		LOCK_SET_DESTROYED,
		LOCK_UNSTABLE,
		LOCK_OWNED,
		LOCK_OWNED_SELF,
		SEMAPHORE_DESTROYED,
		RPC_SERVER_TERMINATED,
		RPC_TERMINATE_ORPHAN,
		RPC_CONTINUE_ORPHAN,
		NOT_SUPPORTED,
		NODE_DOWN,
		NOT_WAITING,
		OPERATION_TIMED_OUT,
		CODESIGN_ERROR,
		POLICY_STATIC,
		INSUFFICIENT_BUFFER_SIZE,
		DENIED,
		MISSING_KC,
		INVALID_KC,
		NOT_FOUND,
		RETURN_MAX = 0x100
	}

	[CCode (cname = "mach_error_string", cheader_filename = "mach/mach_error.h")]
	public static unowned string mach_error_string (KernReturn kr);

	static void kern_assert (KernReturn result) throws GLib.IOError {
		if (result != KernReturn.SUCCESS) {
			throw new GLib.IOError.FAILED (mach_error_string (result));
		}
	}
	
	[CCode (cname = "mach_port_t", has_type_id = false)]
	public struct MachPort : uint {
		[CCode (cname = "MACH_PORT_NULL")]
		public const MachPort NULL;
	}
	
}