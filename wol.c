#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <raw_inet.h>
#include <wrappers.h>
#include <inet_conv.h>

int make_wol_packet( int sd, 
		     struct packet_t* packet, 
		     struct interface_t *interface, 
		     char *address )
{
	uint8_t
		hwaddr[ MAC_ADDR_SIZE ];
	int	i;
#if defined( _LINUX_ )
	int	one = 1;
#endif
	struct eth_header
		*header;

	if( str_to_hwaddr( address, hwaddr, MAC_ADDR_SIZE ) < 0 )
		return( -1 );

	/* droping root privileges??? * /
	setuid( getuid() ); */

	header = ( struct eth_header* ) packet->data;
	
	memcpy( header->dest_addr, hwaddr, MAC_ADDR_SIZE );
	memcpy( header->orig_addr, interface->hw_address, MAC_ADDR_SIZE );
	header->type = htons( 0x0842 ); /* 0x0806 for ARP; 0x8035 for RARP */
	packet->size = sizeof( struct eth_header );

	memset( packet->data + packet->size, 0xff, MAC_ADDR_SIZE );
	packet->size += MAC_ADDR_SIZE;

	for( i = 0; i < 16; i++ ){
		memcpy( packet->data + packet->size, hwaddr, MAC_ADDR_SIZE );
		packet->size += MAC_ADDR_SIZE;
	}
#if defined( _LINUX_ )
	if( setsockopt( sd, SOL_SOCKET, SO_BROADCAST, 
			(char*)&one, sizeof( int ) ) < 0 ){
		perror( __FILE__ ": setsockopt()" );
		return( -1 );
	}
#endif
	return( 1 );
}

int init( struct packet_t *packet,
	  struct interface_t *interface )
{
	int	sd;

	if( (sd = get_raw_socket( interface ) ) < 0 )
		return( -1 );

	if( get_interface_info( interface ) < 0 )
		return( -1 );

	memset( packet, 0x00, sizeof( struct packet_t ) );
	packet->data = ( uint8_t* ) allocate( interface->mtu );

	return( sd );
}

int main( int argc, char *argv[] )
{
	struct packet_t
		packet;
	struct interface_t
		interface = { DEFAULT_IFACE };

	char	*address,
		c;
	int	verbose = 0,
		sd;

	while( ( c = getopt( argc, argv, "vi:") ) > 0 )
		switch( c ){
			case( 'v' ):
				verbose++;
				break;
			case( 'i' ):
				interface.name = optarg;
				break;
		}

	if( optind < argc )
		address = argv[ optind ];
	else
		exit( fprintf( stderr, __FILE__ 
				       ": target address missing \n" ) );
	
	if( (sd = init( &packet, &interface ) ) < 0 )
		exit( 1 );
	
	if( make_wol_packet( sd, &packet, &interface, address ) < 0 )
		exit( 1 );
	
	if( verbose )
		hexdump( packet.data, packet.size );

	send_raw_packet( sd, &packet, &interface );

	exit( 0 );
}
