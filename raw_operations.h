#include <raw_inet.h>

#ifndef __RAW_OPERATIONS_H
#define   __RAW_OPERATIONS_H

struct arp_params
{
	uint8_t	*eth_orig,
		*eth_dest,
		*arp_hw_orig,
		*arp_hw_dest,
		*arp_inet_orig,
		*arp_inet_dest;
	uint16_t operation;
};

void make_arp_packet( struct arp_params*, struct packet_t* );
int do_arp_request( struct interface_t*, uint8_t *dest_inet,
		    uint8_t *dest_hw, struct packet_t*, int sd );

#define	copy_mac( d, o ) memcpy( d, o, MAC_ADDR_SIZE )
#define  copy_ip( d, o ) memcpy( d, o, IP_ADDR_SIZE )

#endif
