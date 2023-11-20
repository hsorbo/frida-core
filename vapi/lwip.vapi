[CCode (gir_namespace = "LWIP", gir_version = "1.0")]
namespace LWIP {
	[CCode (cheader_filename = "lwip/tcpip.h", lower_case_cprefix = "tcpip_")]
	namespace Tcp {
		public void init (InitDoneFunc init_done);

		[CCode (cname = "tcpip_callback")]
		public Result schedule (WorkFunc work);

		[CCode (cname = "tcpip_init_done_fn")]
		public delegate void InitDoneFunc ();

		[CCode (cname = "tcpip_callback_fn")]
		public delegate void WorkFunc ();
	}

	[Compact]
	[CCode (cheader_filename = "lwip/netif.h", cname = "struct netif", cprefix = "netif_")]
	public struct NetworkInterface {
		public static void add_noaddr (ref NetworkInterface netif, void * state, NetworkInterfaceInitFunc init,
			NetworkInterfaceInputFunc input);
	}

	[CCode (cname = "netif_init_fn", has_target = false)]
	public delegate Result NetworkInterfaceInitFunc (NetworkInterface netif);

	[CCode (cname = "netif_input_fn", has_target = false)]
	public delegate Result NetworkInterfaceInputFunc (void * pbuf, NetworkInterface netif);

	[CCode (cheader_filename = "lwip/err.h", cname = "err_t", cprefix = "ERR_", has_type_id = false)]
	public enum Result {
		OK,
		MEM,
		BUF,
		TIMEOUT,
		RTE,
		INPROGRESS,
		VAL,
		WOULDBLOCK,
		USE,
		ALREADY,
		ISCONN,
		CONN,
		IF,
		ABRT,
		RST,
		CLSD,
		ARG,
	}
}
