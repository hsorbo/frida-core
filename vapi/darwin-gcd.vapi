[CCode (cheader_filename = "dispatch/dispatch.h", cprefix = "", gir_namespace = "Darwin", gir_version = "1.0")]
namespace Darwin {
	[Compact]
	[CCode (cname = "struct dispatch_object_s", ref_function = "dispatch_retain", unref_function = "dispatch_release")]
	public class DispatchQueue {
		[CCode (cname = "dispatch_queue_create")]
		public DispatchQueue (string label, DispatchQueueAttr attr);

		[CCode (cname = "dispatch_async_f")]
		public void schedule ([CCode (delegate_target_pos = 0.9)] DispatchFunction work);

		[CCode (cname = "dispatch_sync_f")]
		public void invoke ([CCode (delegate_target_pos = 0.9)] DispatchFunction work);
	}

	[CCode (cname = "dispatch_function_t")]
	public delegate void DispatchFunction ();

	[Compact]
	[CCode (cname = "dispatch_queue_attr_t", cprefix = "DISPATCH_QUEUE_")]
	public class DispatchQueueAttr {
		public static DispatchQueueAttr SERIAL;
		public static DispatchQueueAttr SERIAL_INACTIVE;
		public static DispatchQueueAttr CONCURRENT;
		public static DispatchQueueAttr CONCURRENT_INACTIVE;
		public static DispatchQueueAttr SERIAL_WITH_AUTORELEASE_POOL;
		public static DispatchQueueAttr CONCURRENT_WITH_AUTORELEASE_POOL;
	}
}
