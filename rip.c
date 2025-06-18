#include <stdio.h>
#include <stdlib.h>

#include <raw_inet.h>
#include <inet_conv.h>
#include <wrappers.h>

/* RIP - Routing Information Protocol
 * v1: RFC 1058 
 */

struct rip_header
{
	uint8_t
		command,
		version;
	uint16_t
		must_be_zero;
};

struct rip_entry
{
	uint16_t
		afi,
		must_be_zero_1;
	uint8_t
		ip_address[ 4 ];
	uint32_t
		must_be_zero_2,
		must_be_zero_3,
		metric;
};

#define RIP_PORT	520
#define RIP_REQUEST	0x01
#define RIP_VERSION	0x01
#define RIP_INET_AFI	0x02
#define RIP_INFINITY	0x10

void build_ip_checksum( struct ip_header *header )
{
	uint16_t
		*raw = ( uint16_t* ) header;
	uint32_t	
		sum = 0x00000000;
	int	len = 4 * ip_ihl( header );
	
	header->checksum = 0x0000;

	while( len > 1 ){
		sum += *raw++;
		len -= sizeof( uint16_t );
	}

	if( len > 0 )
		sum += *raw;

	sum  = ( sum >> 16 ) + ( sum & 0xffff );
	sum += ( sum >> 16 );

#if 0
	printf( "%8.8x %8.8x %4.4x %4.4x \n",
		 sum, ~sum, ( uint16_t ) sum, ( uint16_t ) ~sum );
#endif

	header->checksum = ( uint16_t ) ~sum;
}

int set_lengths_checksums( struct packet_t* packet )
{
	struct ip_header
		*ih = ( struct ip_header* ) 
			( packet->data + sizeof( struct eth_header ) );
	struct udp_header
		*uh = ( struct udp_header* ) 
			( (uint8_t*) ih + sizeof( struct ip_header ) );
	
	ih->length = htons ( packet->size -
			     sizeof( struct eth_header ) );

	build_ip_checksum( ih );

	uh->length = htons ( packet->size - 
			     sizeof( struct eth_header ) - 
			     sizeof( struct ip_header ) );
	
	uh->checksum = 0x0000;

	return( 0 );
}

size_t build_rip_request( uint8_t *packet )
{
	struct rip_header
		*header = ( struct rip_header* ) packet;
	struct rip_entry
		*entry = ( struct rip_entry* ) 
			( packet + sizeof( struct rip_header ) );

	header->command = RIP_REQUEST;
	header->version = RIP_VERSION;

	entry->afi = htons( RIP_INET_AFI );
	entry->metric = htonl( RIP_INFINITY );

	return( sizeof( struct rip_header ) + 
		sizeof( struct rip_entry ) );
}

size_t build_udp_header( uint8_t *packet )
{
	struct udp_header
		*header = ( struct udp_header* ) packet;

	header->orig_port = 
	header->dest_port = htons( RIP_PORT );

	return( sizeof( struct udp_header ) );
}

size_t build_ip_header( uint8_t *packet,
			struct interface_t* iface,
			char *dest,
			char *orig )
{
	struct ip_header
		*header = ( struct ip_header* ) packet;

	set_ip_version( header, 4 );
	set_ip_ihl( header, 5 );
	set_ip_tos_flag( header, IP_TOS_MIN_DELAY );
	header->id = 0xffff;
	set_ip_flag( header, IP_FLAG_DF );
	header->ttl = 0x40;
	header->proto = UDP_PROTO;

	if( orig ){
		if( str_to_inetaddr( orig, 
				header->orig_addr, IP_ADDR_SIZE ) < 0 )
			return( -1 );
	}else
		memcpy( header->orig_addr, 
			iface->inet_address, IP_ADDR_SIZE );

	if( str_to_inetaddr( dest, header->dest_addr, IP_ADDR_SIZE ) < 0 )
		return( -1 );

	return( sizeof( struct ip_header ) );
}

size_t build_eth_header( uint8_t *packet,
			 struct interface_t* iface,
			 char *dest,
			 char *gw )
{
	struct eth_header
		*header = ( struct eth_header* ) packet;

	memcpy( header->orig_addr, iface->hw_address, MAC_ADDR_SIZE );

	// XXX from cmdline (-g gateway) ARP req -> get router info
	memcpy( header->dest_addr, "\x00\xe0\x7d\x00\x5e\xd0", MAC_ADDR_SIZE );

	header->type = htons( IP_TYPE );

	return( sizeof( struct eth_header ) );
}

int send_packet( struct packet_t *packet,
		 struct interface_t  *iface )
{
	int	sd;

	if( (sd = get_raw_socket( iface )) < 0 )
		return( -1 );

	return( send_raw_packet( sd, packet, iface ) );
}

int build_packet( struct packet_t *packet,
		   struct interface_t *iface,
		   char *dest,
		   char *orig,
		   char* gw )
{
	uint8_t
		*data = packet->data;
	size_t	size = 0;
	
	size = build_eth_header( data, iface, dest, gw );
	packet->size += size;
	data += size;

	if( (size = build_ip_header( data, iface, dest, orig )) < 0 )
		return( -1 );

	packet->size += size;
	data += size;

	size = build_udp_header( data );
	packet->size += size;
	data += size;
	
	size = build_rip_request( data );
	packet->size += size;
	data += size;

	return( set_lengths_checksums( packet ) );
}

int main( int argc, char *argv[] )
{
	uint8_t
		buffer[ DEFAULT_MTU ];
	struct packet_t
		packet = {
			.data = buffer,
			.size = 0 };
	struct interface_t
		iface = { DEFAULT_IFACE };
	char	opt,
		*dest = NULL,
		*orig = NULL,
		*gw   = NULL;

	while( (opt = getopt( argc, argv, "d:s:g:" )) > 0 )
		switch( opt ){
			case( 'd' ):
				dest = optarg;
				break;
			case( 's' ):
				orig = optarg;
				break;
			case( 'g' ):
				gw = optarg;
				break;
		}

	if( !dest ){
		printf( "destination not given \n" );
		exit( 1 );
	}
	
	if( get_interface_info( &iface ) < 0 )
		exit( 1 );
	
	clear_area( buffer, DEFAULT_MTU );
	build_packet( &packet, &iface, dest, orig, gw );
	send_packet( &packet, &iface );

	return( 0 );
}

