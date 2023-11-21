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
			NetworkInterfaceInputFunc input = NetworkInterface.default_input_handler);

		public void set_up ();
		public void set_down ();

		public void ip6_addr_set (int8 addr_idx, IP6Address address);
		public Result add_ip6_address (IP6Address address, int8 * chosen_index = null);
		public void ip6_addr_set_state (int8 addr_index, IP6AddressState state);

		[CCode (cname = "netif_input")]
		public static Result default_input_handler (PacketBuffer pbuf, NetworkInterface netif);

		public NetworkInterfaceInputFunc input;
		public NetworkInterfaceOutputIP6Func output_ip6;

		public void * state;

		public uint16 mtu;
	}

	[CCode (cname = "netif_init_fn", has_target = false)]
	public delegate Result NetworkInterfaceInitFunc (NetworkInterface netif);

	[CCode (cname = "netif_input_fn", has_target = false)]
	public delegate Result NetworkInterfaceInputFunc (PacketBuffer pbuf, NetworkInterface netif);

	[CCode (cname = "netif_output_ip6_fn", has_target = false)]
	public delegate Result NetworkInterfaceOutputIP6Func (NetworkInterface netif, PacketBuffer pbuf, IP6Address address);

	[CCode (cheader_filename = "lwip/ip6_addr.h", cname = "ip6_addr_t", cprefix = "ip6_addr_")]
	public struct IP6Address {
		[CCode (cname = "ip6addr_aton")]
		public static IP6Address parse (string str);
	}

	[Flags]
	[CCode (cheader_filename = "lwip/ip6_addr.h", cname = "u8_t", cprefix = "IP6_ADDR_", has_type_id = false)]
	public enum IP6AddressState {
		INVALID,
		TENTATIVE,
		TENTATIVE_1,
		TENTATIVE_2,
		TENTATIVE_3,
		TENTATIVE_4,
		TENTATIVE_5,
		TENTATIVE_6,
		TENTATIVE_7,
		VALID,
		PREFERRED,
		DEPRECATED,
		DUPLICATED,
	}

	[CCode (cheader_filename = "lwip/ip_addr.h", cname = "u8_t", cprefix = "IPADDR_TYPE_", has_type_id = false)]
	public enum IPAddressType {
		V4,
		V6,
		ANY,
	}

	[Compact]
	[CCode (cheader_filename = "lwip/pbuf.h", cname = "struct pbuf", cprefix = "pbuf_", free_function = "")]
	public class PacketBuffer {
		public static PacketBuffer alloc (Layer layer, uint16 length, Type type);

		public PacketBuffer next;
		[CCode (array_length_cname = "len")]
		public uint8[] payload;
		public uint16 tot_len;

		[CCode (array_length = false)]
		public unowned uint8[] get_contiguous (uint8[] buffer, uint16 len, uint16 offset = 0);

		public Result take (uint8[] data);

		[CCode (cname = "pbuf_layer", cprefix = "PBUF_", has_type_id = false)]
		public enum Layer {
			TRANSPORT,
			IP,
			LINK,
			RAW_TX,
			RAW,
		}

		[CCode (cname = "pbuf_type", cprefix = "PBUF_", has_type_id = false)]
		public enum Type {
			RAM,
			ROM,
			REF,
			POOL,
		}
	}

	[Compact]
	[CCode (cheader_filename = "lwip/tcp.h", cname = "struct tcp_pcb", cprefix = "tcp_", free_function = "")]
	public class TcpPcb {
		[CCode (cname = "tcp_new_ip_type")]
		public TcpPcb (IPAddressType type);

		public void bind_netif (NetworkInterface? netif);

		public Result connect (IP6Address address, uint16 port, ConnectedFunc connected);

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
