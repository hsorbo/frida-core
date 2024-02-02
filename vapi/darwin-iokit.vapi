[CCode (cheader_filename = "IOKit/IOKitLib.h", gir_namespace = "Darwin", gir_version = "1.0")]
namespace Darwin.IOKit {
	using CoreFoundation;
	using Darwin.Xnu;
		
	public class IOKit {

		public static MachPort main_port(MachPort bootstrapPort) throws GLib.IOError {
			MachPort masterPort;
			kern_assert(main_port_impl(bootstrapPort, out masterPort));
			return masterPort;
		}

		public static IoIterator matching_services(MachPort masterPort, owned MutableDictionary matchingDict) throws GLib.IOError {
			IoIterator iterator;
			kern_assert(matching_services_impl(masterPort, matchingDict, out iterator));
			return iterator;
		}

		[CCode (cname = "IOMainPort")]
		private static KernReturn main_port_impl(MachPort bootstrapPort, out MachPort masterPort);

		[CCode (cname = "IOServiceMatching")]
		public static MutableDictionary service_matching(string name);
		
		[CCode (cname = "IOServiceGetMatchingServices")]
		private static KernReturn matching_services_impl(MachPort masterPort, owned MutableDictionary matchingDict, out IoIterator iterator);
		
		[CCode (cname = "kIOEthernetInterfaceClass", cheader_filename = "IOKit/network/IOEthernetInterface.h")]
		public const string ETHERNET_INTERFACE_CLASS;

		[CCode (cname = "kIOBSDNameKey", cheader_filename = "IOKit/IOBSD.h")]
		public const string BSD_NAME_KEY;

		[CCode (cname = "kIOServicePlane", cheader_filename = "IOKit/IOKitKeys.h")]
		public const string IOSERVICE_PLANE;
	}

	[CCode (cname = "io_registry_entry_t",  destroy_function= "IOObjectRelease", has_type_id = false)]
	[Compact]
	public struct IORegistryEntry : IOObject {

		public MutableDictionary get_properties () throws GLib.IOError {
			MutableDictionary properties;
			kern_assert (create_properties_impl (out properties, null, 0));
			return properties;
		}
		
		public string? get_string_property (string key){
			var result = (String)create_property (String.from_string (key), null, 0);
			return result != null ? result.to_string () : null;
		}

		public IORegistryEntry parent (string plane) throws GLib.IOError {
			IORegistryEntry parent;
			kern_assert (parent_impl (plane, out parent));
			return parent;
		}

		[CCode (cname = "IORegistryEntryCreateCFProperties")]
		private KernReturn create_properties_impl (out MutableDictionary properties, Allocator? allocator, uint options);

		[CCode (cname = "IORegistryEntryGetParentEntry")]
		private KernReturn parent_impl (string plane, out IORegistryEntry parent);

		[CCode (cname = "IORegistryEntryCreateCFProperty")]
		public CoreFoundation.Type create_property (String key, Allocator? allocator, uint options);
	}

	[CCode (cname = "io_iterator_t", destroy_function = "IOObjectRelease")]
	[Compact]
	public struct IoIterator : MachPort {
		[CCode (cname = "IOIteratorNext")]
		public IOObject next ();
		[CCode (cname = "IOIteratorReset")]
		public void reset ();
		[CCode (cname = "IOIteratorIsValid")]
		public bool is_valid ();
	}

	[CCode (cname = "io_service_t",  destroy_function= "IOObjectRelease", has_type_id = false)]
	[Compact]
	public struct IoService : IOObject {
	}

	[CCode (cname = "io_object_t", destroy_function= "IOObjectRelease",  has_type_id = false)]
	[Compact]
	public struct IOObject : MachPort {
		
		[CCode (cname = "IO_OBJECT_NULL")]
		public const IOObject NULL;
	}
}