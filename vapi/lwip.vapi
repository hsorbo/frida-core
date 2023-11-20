[CCode (gir_namespace = "LWIP", gir_version = "1.0")]
namespace LWIP {
	[CCode (cheader_filename = "lwip/tcpip.h")]
	namespace Tcp {
		public void init (InitDoneFunc init_done);

		public delegate void InitDoneFunc ();
	}
}
