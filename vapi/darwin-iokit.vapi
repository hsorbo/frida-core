[CCode (cheader_filename = "IOKit/IOKitLib.h", gir_namespace = "Darwin", gir_version = "1.0")]
namespace Darwin.IOKit {
	using CoreFoundation;
	//https://opensource.apple.com/source/xnu/xnu-1228.0.2/osfmk/mach/kern_return.h
	[CCode (cname = "kern_return_t",  cprefix = "KERN_", has_type_id = false)]
	public enum KernReturn {
		SUCCESS,                    //0
		INVALID_ADDRESS,            //1
		PROTECTION_FAILURE,         //2
		NO_SPACE,                   //3
		INVALID_ARGUMENT,           //4
		FAILURE,                    //5
		RESOURCE_SHORTAGE,          //6
		NOT_RECEIVER,               //7
		NO_ACCESS,                  //8
		MEMORY_FAILURE,             //9
		MEMORY_ERROR,               //10
		ALREADY_IN_SET,             //11
		NOT_IN_SET,                 //12
		NAME_EXISTS,                //13
		ABORTED,                    //14
		INVALID_NAME,               //15
		INVALID_TASK,               //16
		INVALID_RIGHT,              //17
		INVALID_VALUE,              //18
		UREFS_OVERFLOW,             //19
		INVALID_CAPABILITY,         //20
		RIGHT_EXISTS,               //21
		INVALID_HOST,               //22
		MEMORY_PRESENT,             //23
		MEMORY_DATA_MOVED,          //24
		MEMORY_RESTART_COPY,        //25
		INVALID_PROCESSOR_SET,      //26
		POLICY_LIMIT,               //27
		INVALID_POLICY,             //28
		INVALID_OBJECT,             //29
		ALREADY_WAITING,            //30
		DEFAULT_SET,                //31
		EXCEPTION_PROTECTED,        //32
		INVALID_LEDGER,             //33
		INVALID_MEMORY_CONTROL,     //34
		INVALID_SECURITY,           //35
		NOT_DEPRESSED,              //36
		TERMINATED,                 //37
		LOCK_SET_DESTROYED,         //38
		LOCK_UNSTABLE,              //39
		LOCK_OWNED,                 //40
		LOCK_OWNED_SELF,            //41
		SEMAPHORE_DESTROYED,        //42
		RPC_SERVER_TERMINATED,      //43
		RPC_TERMINATE_ORPHAN,       //44
		RPC_CONTINUE_ORPHAN,        //45
		NOT_SUPPORTED,              //46
		NODE_DOWN,                  //47
		NOT_WAITING,                //48
		OPERATION_TIMED_OUT,        //49
		CODESIGN_ERROR,             //50
		POLICY_STATIC,              //51
		INSUFFICIENT_BUFFER_SIZE,   //52
		DENIED,                     //53
		MISSING_KC,                 //54
		INVALID_KC,                 //55
		NOT_FOUND,                  //56
		RETURN_MAX,                 //0x100
	}

	//  errordomain IOKitError {
	//      KernReturn
	//  }


	[CCode (cname = "mach_error_string", cheader_filename = "mach/mach_error.h")]
	public static unowned string mach_error_string(KernReturn kr);
	
	//https://developer.apple.com/documentation/kernel/io_name_t?language=objc
	//typedef char io_name_t[128];

	[CCode (cname = "mach_port_t", has_type_id = false)]
	public struct MachPort : uint {
		[CCode (cname = "MACH_PORT_NULL")]
		public const MachPort NULL;
	}
	
	[CCode (cname = "io_object_t", destroy_function= "IOObjectRelease",  has_type_id = false)]
	[Compact]
	public struct IOObject : MachPort {
		
		[CCode (cname = "IO_OBJECT_NULL")]
		public const IOObject NULL;
	}

	[CCode (cname = "io_service_t",  destroy_function= "IOObjectRelease", has_type_id = false)]
	[Compact]
	public struct IoService : IOObject {
	}

	[CCode (cname = "io_registry_entry_t",  destroy_function= "IOObjectRelease", has_type_id = false)]
	[Compact]
	public struct IORegistryEntry : IOObject {
		[CCode (cname = "IORegistryEntryCreateCFProperties")]
		public KernReturn create_properties(out MutableDictionary properties, Allocator? allocator, uint options);

		[CCode (cname = "IORegistryEntryCreateCFProperty")]
		public CoreFoundation.Type create_property(String key, Allocator? allocator, uint options);
		
		public string? get_string_property(string key){
			var result = (String)create_property(String.from_string(key), null, 0);
			return result != null ? result.to_string() : null;
		}
		[CCode (cname = "IORegistryEntryGetParentEntry")]
		public KernReturn parent(string plane, out IORegistryEntry parent);

	}

	[CCode (cname = "io_iterator_t", destroy_function = "IOObjectRelease")]
	[Compact]
	public struct IoIterator : MachPort {
		[CCode (cname = "IOIteratorNext")]
		public IOObject next();
		[CCode (cname = "IOIteratorReset")]
		public void reset();
		[CCode (cname = "IOIteratorIsValid")]
		public bool is_valid();
	}

	public class IOKit {
		[CCode (cname = "IOMainPort")]
		public static KernReturn main_port(MachPort bootstrapPort, out MachPort masterPort);
		
		[CCode (cname = "IOServiceMatching")]
		public static MutableDictionary service_matching(string name);
		
		[CCode (cname = "IOServiceGetMatchingServices")]
		public static KernReturn matching_services(MachPort masterPort, owned MutableDictionary matchingDict, out IoIterator iterator);
		
		[CCode (cname = "kIOEthernetInterfaceClass", cheader_filename = "IOKit/network/IOEthernetInterface.h")]
		public const string kIOEthernetInterfaceClass;

		[CCode (cname = "kIOBSDNameKey", cheader_filename = "IOKit/IOBSD.h")]
		public const string kIOBSDNameKey;
	}
}