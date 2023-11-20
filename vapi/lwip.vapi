[CCode (gir_namespace = "LWIP", gir_version = "1.0")]
namespace LWIP {
	[CCode (cheader_filename = "lwip/tcpip.h", lower_case_cprefix = "tcpip_")]
	namespace Runtime {
		public void init (InitDoneFunc init_done);

		[CCode (cname = "tcpip_callback")]
		public Result schedule (WorkFunc work);

		[CCode (cname = "tcpip_init_done_fn")]
		public delegate void InitDoneFunc ();

		[CCode (cname = "tcpip_callback_fn")]
		public delegate void WorkFunc ();
	}

	[CCode (cheader_filename = "lwip/netif.h", cname = "struct netif", cprefix = "netif_")]
	public struct NetworkInterface {
		public static void add_noaddr (ref NetworkInterface netif, void * state, NetworkInterfaceInitFunc init,
			NetworkInterfaceInputFunc input);
		public Result add_ip6_address (IP6Address addr, int8 * chosen_idx = null);

		public void * state;
	}

	[CCode (cname = "netif_init_fn", has_target = false)]
	public delegate Result NetworkInterfaceInitFunc (NetworkInterface netif);

	[CCode (cname = "netif_input_fn", has_target = false)]
	public delegate Result NetworkInterfaceInputFunc (void * pbuf, NetworkInterface netif);

	[CCode (cheader_filename = "lwip/ip_addr.h", cname = "ip_addr_t", cprefix = "ip_addr_")]
	public struct IPAddress {
		[CCode (cname = "u_addr.ip6")]
		public IP6Address ip6;
		public IPAddressType type;
	}

	[CCode (cheader_filename = "lwip/ip6_addr.h", cname = "ip6_addr_t", cprefix = "ip6_addr_")]
	public struct IP6Address {
		[CCode (cname = "ip6addr_aton")]
		public static IP6Address parse (string str);
	}

	[CCode (cheader_filename = "lwip/ip_addr.h", cname = "u8_t", cprefix = "IPADDR_TYPE_", has_type_id = false)]
	public enum IPAddressType {
		V4,
		V6,
		ANY,
	}

	[Compact]
	[CCode (cheader_filename = "lwip/tcp.h", cname = "struct tcp_pcb", cprefix = "tcp_", free_function = "")]
	public class TcpPcb {
		[CCode (cname = "tcp_new_ip_type")]
		public TcpPcb (IPAddressType type);

		public void bind_netif (NetworkInterface? netif);

		public Result connect (IPAddress address, uint16 port, ConnectedFunc connected);

		[CCode (cname = "tcp_connected_fn", has_target = false)]
		public delegate Result ConnectedFunc (void * arg, TcpPcb pcb, Result res);
	}

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
