#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

#include <unistd.h>
#include <time.h>

/* used to manage a queue of incoming packets, 
 * which are read in get_raw_packet( BSD ) from bpf */
#include <wrappers.h>
#include <memmgmt.h>
#include <queue.h>

#include <hack_helpers.h>

#if defined( _LINUX_ )
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>

#define DEFAULT_IFACE "eth0"
#endif

#if defined( _FreeBSD_ ) || defined( _OpenBSD_ ) || defined( _NetBSD_ )
#if defined( _FreeBSD_ )
#include <sys/fcntl.h>
#include <sys/errno.h>

#define DEFAULT_IFACE "xl0"
#endif

#if defined( _OpenBSD_ )
#include <sys/param.h>

#define DEFAULT_IFACE "sis0"
#endif

#if defined( _NetBSD_ )
#include <sys/param.h>

#define DEFAULT_IFACE "sip0"
#endif

#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <net/bpf.h>
#include <sys/sysctl.h>

#endif

#ifndef __RAW_INET_H
#define   __RAW_INET_H

#define DEFAULT_MTU   1500

#define MAC_ADDR_SIZE 0x06
#define IP_ADDR_SIZE  0x04

struct eth_header
{
	uint8_t
		dest_addr[ MAC_ADDR_SIZE ],
		orig_addr[ MAC_ADDR_SIZE ];
	uint16_t	
		type;
};

#define ARP_TYPE  0x0806
#define RARP_TYPE 0x8035
#define IP_TYPE   0x0800

struct arp_header /* RFC 826 */
{
	uint16_t
		hw_proto,
		net_proto;
	uint8_t
		hw_len,
		net_len;
	uint16_t
		operation;
	uint8_t
		orig_hw_addr[ MAC_ADDR_SIZE ],
		orig_net_addr[ IP_ADDR_SIZE ],
		dest_hw_addr[ MAC_ADDR_SIZE ],
		dest_net_addr[ IP_ADDR_SIZE ];
};

#define ARP_REQUEST 0x0001
#define ARP_REPLY   0x0002

struct ip_header /* RFC 791 */
{
	uint8_t	
		ver_ihl,
		tos;
	uint16_t
		length,
		id,
		flags_fr_off;
	uint8_t
		ttl,
		proto;
	uint16_t
		checksum;
	uint8_t	
		orig_addr[ IP_ADDR_SIZE ],
		dest_addr[ IP_ADDR_SIZE ];
};

#define IP_TOS_MIN_DELAY       0x10
#define IP_TOS_MAX_THROUGHPUT  0x08
#define IP_TOS_MAX_RELIABILITY 0x04

#define ip_tos( header ) ( (header)->tos >> 0x05 )
#define ip_tos_delay( header ) \
	( (header)->tos & IP_TOS_MIN_DELAY )
#define ip_tos_throughput( header ) \
	( (header)->tos & IP_TOS_MAX_THROUGHPUT )
#define ip_tos_reliability( header ) \
	( (header)->tos & IP_TOS_MAX_RELIABILITY )

#define set_ip_tos_flag( header, flag ) \
	( (header)->tos |= flag )

#define IP_FLAG_DF 0x4000
#define IP_FLAG_MF 0x2000

#define ip_version( header )( (header)->ver_ihl >> 0x04 )
#define ip_ihl( header )    ( (header)->ver_ihl  & 0x0f )
#define ip_flags( header )  ( ntohs( (header)->flags_fr_off ) & 0xe000 )
#define ip_fr_off( header ) ( ntohs( (header)->flags_fr_off ) & 0x1fff )

#define set_ip_version( header, ver ) \
	( (header)->ver_ihl = ip_ihl( header ) | (ver << 0x04) )
#define set_ip_ihl( header, ihl ) \
	( (header)->ver_ihl |= ihl & 0x0f )
#define set_ip_flag( header, flag ) \
	( (header)->flags_fr_off |= htons( flag ) )
#define set_fragment_offset( header, fr_off ) \
	( (header)->flags_fr_off = htons( ip_flags( header ) | fr_off ) )

#define ICMP_PROTO 0x01
#define IGMP_PROTO 0x02
#define TCP_PROTO  0x06
#define UDP_PROTO  0x11

struct tcp_header /* RFC 793 */
{
	uint16_t
		orig_port,
		dest_port;
	uint32_t
		seq_num,
		ack_num;
	uint8_t
		data_off,
		flags;
	uint16_t
		window,
		checksum,
		urg_pointer;
};

#define tcp_URG 0x20
#define tcp_ACK 0x10
#define tcp_PSH 0x08
#define tcp_RST 0x04
#define tcp_SYN 0x02
#define tcp_FIN 0x01

#define FTP_PORT      21
#define SSH_PORT      22
#define TELNET_PORT   23
#define SMTP_PORT     25
#define HTTP_PORT     80
#define POP3_PORT     110

#define tcp_URG_set( header ) ( (header)->flags & tcp_URG )
#define tcp_ACK_set( header ) ( (header)->flags & tcp_ACK )
#define tcp_PSH_set( header ) ( (header)->flags & tcp_PSH )
#define tcp_RST_set( header ) ( (header)->flags & tcp_RST )
#define tcp_SYN_set( header ) ( (header)->flags & tcp_SYN )
#define tcp_FIN_set( header ) ( (header)->flags & tcp_FIN )

#define tcp_data_offset( header ) ( (header)->data_off >> 0x04 )

struct udp_header /* RFC 768 */
{
	uint16_t
		orig_port,
		dest_port,
		length,
		checksum;
};

#define DNS_PORT      53

struct icmp_header /* RFC 792 */
{
	uint8_t
		type,
		code;
	uint16_t
		checksum;
};

/* custom structs */
struct interface_t
{
	char	*name;
	size_t	mtu;
	uint8_t
		hw_address[ MAC_ADDR_SIZE ],
		inet_address[ IP_ADDR_SIZE ],
		inet_netmask[ IP_ADDR_SIZE ];
};

struct packet_t
{
	uint8_t	
		*data;
	size_t	size;
#if defined( _LINUX_ )
	/* to avoid filling again and again the same
	 * structure, we put it here - it's filled
	 * the first time this is structure is passed to 
	 * send_raw_packet() */
	struct sockaddr_ll
		sll;
#endif
};

/**/

#define SEND_SEC_WAIT  0
#define SEND_NANO_WAIT 1e5

int  get_interface_info( struct interface_t* );
int  set_non_blocking( int sd, int set );

/* OS-dependant */
int  get_hw_addr( struct interface_t* );
int  get_raw_socket( struct interface_t* );
int  prepare_raw_to_receive( struct interface_t* );
int  get_raw_packet( int, char*, int );
int send_raw_packet( int, struct packet_t*, struct interface_t* );
/**/

#endif
