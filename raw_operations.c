#include <raw_operations.h>

uint8_t	broadcast_mac[]  = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
	zeroed_mac[]     = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	broadcast_inet[] = { 0xff, 0xff, 0xff, 0xff },
	zeroed_inet[]    = { 0x00, 0x00, 0x00, 0x00 };

void make_arp_packet( struct arp_params *params,
		      struct packet_t *packet )
{
	struct eth_header
		*e_header;
	struct arp_header
		*a_header;

	e_header = ( struct eth_header* ) packet->data;
	a_header = ( struct arp_header* ) 
			( packet->data + sizeof( struct eth_header ) );

	/* ethernet header */
	memcpy( e_header->orig_addr, params->eth_orig, MAC_ADDR_SIZE );
	memcpy( e_header->dest_addr, params->eth_dest, MAC_ADDR_SIZE );
	
	e_header->type = htons( ARP_TYPE );
	
	/* arp header */
	a_header->hw_proto = htons( 0x001 );
	a_header->net_proto = htons( IP_TYPE );
	a_header->hw_len = MAC_ADDR_SIZE;
	a_header->net_len = IP_ADDR_SIZE;
	a_header->operation = htons( params->operation );
	
	memcpy( a_header->orig_hw_addr, 
		  params->arp_hw_orig, MAC_ADDR_SIZE );
	memcpy( a_header->dest_hw_addr, 
		  params->arp_hw_dest, MAC_ADDR_SIZE );
	memcpy( a_header->orig_net_addr, 
		  params->arp_inet_orig, IP_ADDR_SIZE );
	memcpy( a_header->dest_net_addr, 
		  params->arp_inet_dest, IP_ADDR_SIZE );

	packet->size = sizeof( struct eth_header ) +
		       sizeof( struct arp_header );
}

/* we can't compare the data we've just received with the
 * packet we've just created, since in BSD get_raw_packet() 
 * enqueues incoming packets (because of bpf inner working)
 * so, we can get a reply from host 'A' after sending queries
 * to 'A', 'B', and 'C', for example, so we would be comparing
 * the addresses of 'A' and 'C' */

static struct arp_header* is_arp_reply( 	
		struct interface_t *interface,
		uint8_t *data,
		int len )
{
	struct eth_header
		*e_header = ( struct eth_header* ) data;
	struct arp_header
		*a_header = ( struct arp_header* )
			( data + sizeof( struct eth_header ) );

	return(( !(len < (sizeof( struct eth_header ) + 
			 sizeof( struct arp_header ) )) && /* valid length */
		!memcmp( interface->hw_address, e_header->dest_addr,
			 MAC_ADDR_SIZE ) &&  /* is this frame for us? */
		e_header->type == htons( ARP_TYPE ) &&
		a_header->operation == htons( ARP_REPLY ) &&
		/* the reply is for us */
		!memcmp( interface->inet_address,
			  a_header->dest_net_addr, IP_ADDR_SIZE ) )
		? a_header : NULL );
}

int do_arp_request( struct interface_t *interface,
		    uint8_t *dest_inet,
		    uint8_t *dest_hw,
		    struct packet_t *packet,
		    int sd )
{
	struct timespec
		time = { 0, 2500000 };
	uint8_t	buffer[ interface->mtu ];
	int	len;
	struct arp_params
		params = {
			.eth_orig =	 interface->hw_address,
			.eth_dest = 	 broadcast_mac,
			.arp_hw_orig = 	 interface->hw_address,
			.arp_hw_dest =	 zeroed_mac,
			.arp_inet_orig = interface->inet_address,
			.arp_inet_dest = dest_inet,
			.operation =	 ARP_REQUEST
		};
	struct arp_header
		*header;
	
	clear_area( dest_hw, MAC_ADDR_SIZE );
	make_arp_packet( &params, packet );

	if( send_raw_packet( sd, packet, interface ) < 0 )
		return( -1 );

	nanosleep( &time, NULL );

	if( (len = get_raw_packet( sd, buffer, interface->mtu )) < 0 )
		return( -1 );
	
	if( len > 0 ) /* len could be 0 (sd set as a non-blocking socket) */
		if( (header = is_arp_reply( interface, buffer, len )) ){
			copy_mac( dest_hw, header->orig_hw_addr );
			copy_ip( dest_inet, header->orig_net_addr );
		}
	
	return( 0 );
}
