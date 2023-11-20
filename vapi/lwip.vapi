[CCode (gir_namespace = "LWIP", gir_version = "1.0")]
namespace LWIP {
	[CCode (cheader_filename = "lwip/tcpip.h", lower_case_cprefix = "tcpip_")]
	namespace Tcp {
		public void init (InitDoneFunc init_done);

		[CCode (cname = "tcpip_init_done_fn")]
		public delegate void InitDoneFunc ();
	}
}
