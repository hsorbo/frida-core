[CCode (cheader_filename = "xpc/xpc.h", lower_case_cprefix = "xpc_", gir_namespace = "Darwin", gir_version = "1.0")]
namespace Darwin.XPC {
	[Compact]
	[CCode (cname = "gpointer", ref_function = "xpc_retain", unref_function = "xpc_release")]
	public class Connection {
		public static Connection? create (string? name, GCD.DispatchQueue targetq);

		[CCode (cname = "_frida_xpc_connection_set_event_handler", cheader_filename = "frida-xpc.h")]
		public void set_event_handler (Handler handler);

		public void activate ();
	}

	[CCode (cname = "FridaXpcHandler")]
	public delegate void Handler (Object object);

	[Compact]
	[CCode (cname = "gpointer", ref_function = "xpc_retain", unref_function = "xpc_release")]
	public class Object {
		[CCode (cname = "_frida_xpc_object_to_string", cheader_filename = "frida-xpc.h")]
		public string to_string ();
	}
}
