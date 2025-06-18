#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <raw_inet.h>
#include <wrappers.h>
#include <inet_conv.h>
#include <raw_operations.h>

#define inet_to_long( inet ) ( ntohl( *( uint32_t* )( &(inet) ) ) )

extern uint8_t
	zeroed_mac[],
	broadcast_mac[];

int do_netmap( struct packet_t *packet,
	       struct interface_t *interface )
{
	char	buf_hw_addr[ ADDR_BUFFER_LEN ],
		buf_inet_addr[ ADDR_BUFFER_LEN ],
		buf_inet_mask[ ADDR_BUFFER_LEN ];
	uint8_t	reply_address[ MAC_ADDR_SIZE ],
		dest_address[ IP_ADDR_SIZE ];
	unsigned long
		net_addr,
		last_host,
		host = 1,
		dest;
	int	sd;

	printf( "interface: %s [%s] (%s/%s) \n",
		interface->name, 
		hwaddr_to_str( interface->hw_address, buf_hw_addr, 
				 ADDR_BUFFER_LEN ),
		inetaddr_to_str( interface->inet_address, buf_inet_addr, 
				 ADDR_BUFFER_LEN ), 
		inetaddr_to_str( interface->inet_netmask, buf_inet_mask, 
				 ADDR_BUFFER_LEN ) );

	if( (sd = prepare_raw_to_receive( interface )) < 0 )
		return( -1 );

	if( set_non_blocking( sd, 1 ) < 0 )
		return( -1 );
	
	net_addr = inet_to_long( interface->inet_address ) &
		   inet_to_long( interface->inet_netmask );
	last_host = ~(inet_to_long( interface->inet_netmask ));

	while( host < last_host ){
		dest = htonl( net_addr ) | htonl( host++ );
		memcpy( dest_address, &dest, IP_ADDR_SIZE );
	
		if( !memcmp( dest_address, interface->inet_address,
			     IP_ADDR_SIZE ) )
			continue;

		if( do_arp_request( interface, dest_address,
					   reply_address, packet, sd ) < 0 )
			return( -1 );
		
		if( memcmp( reply_address, zeroed_mac, MAC_ADDR_SIZE ) )
			printf( "ip %s hw %s\n",
				inetaddr_to_str( dest_address, buf_inet_addr,
						 ADDR_BUFFER_LEN ),
				  hwaddr_to_str( reply_address,
					         buf_hw_addr,
					         ADDR_BUFFER_LEN ) );
	}

	return( 1 );
}

int prepare_spoofed_arp( struct packet_t *packet, 
			 char *prg_args[], 
			 int opt_base )
{
	uint8_t	orig_mac[ MAC_ADDR_SIZE ],
		dest_eth[ MAC_ADDR_SIZE ],
		dest_arp_mac[ MAC_ADDR_SIZE ],
		orig_inetaddr[ IP_ADDR_SIZE ],
		dest_inetaddr[ IP_ADDR_SIZE ];
	struct arp_params
		params = {
			.operation = atoi( prg_args[ opt_base + 4 ] )
		};

	if( str_to_hwaddr( prg_args[ opt_base ], orig_mac, 
			   MAC_ADDR_SIZE ) < 0 )
		return( -1 );

	if( params.operation == ARP_REQUEST ){
		memcpy( dest_eth, broadcast_mac, MAC_ADDR_SIZE );
		if( str_to_hwaddr( prg_args[ opt_base + 1 ], dest_arp_mac,
				   MAC_ADDR_SIZE ) < 0 )
			return( -1 );
	}else{
		if( str_to_hwaddr( prg_args[ opt_base + 1 ], dest_eth,
				   MAC_ADDR_SIZE ) < 0 )
			return( -1 );
		memcpy( dest_arp_mac, dest_eth, MAC_ADDR_SIZE );
	}

	if( str_to_inetaddr( prg_args[ opt_base + 2 ], orig_inetaddr,
			     IP_ADDR_SIZE ) < 0 )
		return( -1 );

	if( str_to_inetaddr( prg_args[ opt_base + 3 ], dest_inetaddr,
			     IP_ADDR_SIZE ) < 0 )
		return( -1 );

	params.eth_orig = orig_mac;
	params.eth_dest = dest_eth;
	params.arp_hw_orig = orig_mac;
	params.arp_hw_dest = dest_arp_mac;
	params.arp_inet_orig = orig_inetaddr;
	params.arp_inet_dest = dest_inetaddr;

	make_arp_packet( &params, packet );	
	
	return( 1 );
}

int init( struct packet_t *packet,
	  struct interface_t *interface )
{
	if( get_interface_info( interface ) < 0 )
		return( -1 );

	memset( packet, 0x00, sizeof( struct packet_t ) );
	packet->data = ( uint8_t* ) allocate( interface->mtu );

	return( 1 );
}

int usage( char *name )
{
	return( printf( "usage: \n"
			"\t%s [-m] || [src_hw dest_hw src_inet dest_inet op] "
			"\n\n\t-m\tmap the network \n", name ) );
}

int main( int argc, char *argv[] )
{
	struct packet_t
		packet;
	struct interface_t
		interface = { DEFAULT_IFACE };
	char	opt;
	int	verbose = 0,
		netmap = 0,
		sd;

	while( ( opt = getopt( argc, argv, "mvi:") ) > 0 )
		switch( opt ){
			case( 'm' ):
				netmap++;
				break;
			case( 'v' ):
				verbose++;
				break;
			case( 'i' ):
				interface.name = optarg;
				break;
		}

	if( !netmap && (argc - optind) != 5 )
		exit( usage( argv[ 0 ] ) );
			
	if( init( &packet, &interface ) < 0 )
		exit( 1 );
	
	if( netmap ){
		if( do_netmap( &packet, &interface ) < 0 )
			exit( 1 );
	}else{
		if( prepare_spoofed_arp( &packet, argv, optind ) < 0 )
			exit( 1 );

		if( verbose )
			hexdump( packet.data, packet.size );

		if( (sd = get_raw_socket( &interface )) < 0 )
			exit( 1 );

		send_raw_packet( sd, &packet, &interface );

		close( sd );
	}

	exit( 0 );
}
