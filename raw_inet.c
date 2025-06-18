#include <raw_inet.h>

#define p_std_error( s ) \
	fprintf( stderr, \
		"%s[%i]: %s: %s\n", \
		__FILE__, __LINE__, s, strerror( errno ) )
#define p_error( s ) \
	fprintf( stderr, \
		"%s[%i]: %s\n", \
		__FILE__, __LINE__, s )

/* this is the same for linux and BSD */
int get_interface_info( struct interface_t *iface )
{
	struct ifreq
		if_inetaddr;
	int	sd;

	memset( &if_inetaddr, 0x00, sizeof( struct ifreq ) );
	strncpy( if_inetaddr.ifr_name, iface->name, 
		 sizeof( if_inetaddr.ifr_name ) );

	if( get_hw_addr( iface ) < 0 )
		return( -1 );
	
	if( (sd = socket( PF_INET, SOCK_DGRAM, 0 )) < 0 ){
		p_std_error( "socket( PF_INET, SOCK_DGRAM )" );
		return( -1 );
	}

	if( ioctl( sd, SIOCGIFADDR, &if_inetaddr ) < 0 ){
		p_std_error( "ioctl( SIOCGIFADDR )" );
		close( sd );
		return( -1 );
	}else
		memcpy( iface->inet_address, 
			if_inetaddr.ifr_addr.sa_data + 2, 
			IP_ADDR_SIZE );
	
	if( ioctl( sd, SIOCGIFNETMASK, &if_inetaddr ) < 0 ){
		p_std_error( "ioctl( SIOCGIFNETMASK )" );
		close( sd );
		return( -1 );
	}else
		memcpy( iface->inet_netmask, 
			if_inetaddr.ifr_addr.sa_data + 2, 
			IP_ADDR_SIZE );
	
	if( ioctl( sd, SIOCGIFMTU, &if_inetaddr ) < 0 ){
		p_std_error( "ioctl( SIOCGIFMTU )" );
		fprintf( stderr, "assuming MTU == %i \n", 
				 DEFAULT_MTU );
		iface->mtu = DEFAULT_MTU;
	}else
		iface->mtu = if_inetaddr.ifr_mtu; 
	
	close( sd );

	return( 1 );
}

int set_non_blocking( int sd, int set )
{
	int	flags;

	if( (flags = fcntl( sd, F_GETFL, 0 )) < 0 ){
		p_std_error( "fcntl( F_GETFL )" );
		return( -1 );
	}

	if( set ) flags |=  O_NONBLOCK;
	else	  flags &= ~O_NONBLOCK;
	
	if( fcntl( sd, F_SETFL, flags ) < 0 ){
		p_std_error( "fcntl( F_SETFL )" );
		return( -1 );
	}

	return( sd );
}

#if defined( _LINUX_ )
int get_hw_addr( struct interface_t *iface )
{
	struct ifreq
		if_hwaddr;
	int	sd;

	memset( &if_hwaddr, 0x00, sizeof( struct ifreq ) );	
	strncpy( if_hwaddr.ifr_name, iface->name, 
		 sizeof( if_hwaddr.ifr_name ) );

	if( (sd = socket( PF_INET, SOCK_DGRAM, 0 )) < 0 ){
		p_std_error( "socket()" );
		return( -1 );
	}
	
	if( ioctl( sd, SIOCGIFHWADDR, &if_hwaddr ) < 0 ){
		p_std_error( "ioctl( SIOCGIFHWADDR )" );
		close( sd );
		return( -1 );
	}else
		memcpy( iface->hw_address, if_hwaddr.ifr_hwaddr.sa_data, 
			 MAC_ADDR_SIZE );

	close( sd );		

	return( 1 );
}

int get_raw_socket( struct interface_t *unused )
{
	int	sd;

	if( (sd = socket( PF_PACKET, SOCK_RAW, htons( ETH_P_ALL ) ) ) < 0 ){
		p_std_error( "socket( PF_PACKET, SOCK_RAW )" );
		return( -1 );
	}

	return( sd );
}

int prepare_raw_to_receive( struct interface_t *iface )
{
	int	sd;
	struct	sockaddr_ll
		sa_ll;
	struct	ifreq
		ifr;

	if( (sd = get_raw_socket( iface ) ) < 0 )
		return( -1 );
	
	memset( &ifr, 0x00, sizeof( struct ifreq ) );
	strncpy( ifr.ifr_name, iface->name, sizeof( ifr.ifr_name ) );

	if( ioctl( sd, SIOCGIFINDEX, &ifr ) < 0 ){
		p_std_error( "ioctl( SIOCGIFINDEX )" );
		close( sd );
		return( -1 );
	}
	
	memset( &sa_ll, 0x00, sizeof( struct sockaddr ) );
	sa_ll.sll_family = AF_PACKET;
	sa_ll.sll_ifindex = ifr.ifr_ifindex;
	sa_ll.sll_protocol = htons( ETH_P_ALL );
	
	if( bind( sd, ( struct sockaddr* ) &sa_ll, 
	    sizeof( struct sockaddr_ll ) ) < 0 ){
		p_std_error( "bind()" );
		close( sd );
		return( -1 );
	}

	return( sd );
}

int get_raw_packet( int sd, char *buffer, int max_len )
{
	struct sockaddr
		from;
	socklen_t
		from_len = sizeof( struct sockaddr );
	int	len;

_recv:	if( (len = recvfrom( sd, buffer, max_len,
			MSG_TRUNC, &from, &from_len )) < 0 ){
		if( errno == EAGAIN ) /* maybe sd is marked non-blocking */
			return( 0x00 );
		if( errno == EINTR ) /* a signal interrupted us */
			goto _recv;
		else
			p_std_error( "recvfrom()" );
	}

	return( len );
}

int send_raw_packet( int sd, 
		     struct packet_t *packet, 
		     struct interface_t *iface )
{
	struct ifreq
		ifr;
	struct timespec
		time = { SEND_SEC_WAIT, SEND_NANO_WAIT };
	int	sent;

	/* we fill this only the first time */
	if( packet->sll.sll_family != AF_PACKET ){
		memset( &ifr, 0x00, sizeof( struct ifreq ) );
		strncpy( ifr.ifr_name, iface->name, sizeof( ifr.ifr_name ) );

		if( ioctl( sd, SIOCGIFINDEX, &ifr ) < 0 ){
			p_std_error( "ioctl( SIOCGIFINDEX )" );
			return( -1 );
		}
	
		packet->sll.sll_family = AF_PACKET;
		packet->sll.sll_ifindex = ifr.ifr_ifindex;
		packet->sll.sll_protocol = htons( ETH_P_ALL );
	}
	
	do{
		if( (sent = sendto( sd, packet->data, packet->size, 0x00,
			    ( struct sockaddr* ) &packet->sll, 
	    		    sizeof( struct sockaddr_ll ) )) < 0 )
			p_std_error( "sendto()" );
	}while( sent < packet->size && 
		errno == ENOBUFS && 
		nanosleep( &time, NULL ) );

	return( sent );
}
#endif

#if defined( _FreeBSD_ ) || defined( _OpenBSD_ ) || defined( _NetBSD_ )

int 	size; /* this has to be declared global, in order to be set by 
	       * get_raw_socket() [ioctl(BIOCSBLEN)] and used in 
	       * get_raw_packet() [read()] */
_queue_t
	incoming_queue = QUEUE_INITIALIZER;

int get_hw_addr( struct interface_t *iface )
{
	size_t	len;
	char	*data,
		*next;
	struct if_msghdr
		*ifmsg;
	struct sockaddr_dl
		*sa_dl;
	int	info[ 6 ] = { CTL_NET, AF_ROUTE, 0,
			   AF_LINK, NET_RT_IFLIST, 0 };
	
	if( sysctl( info, 6, NULL, &len, NULL, 0 ) < 0 ){
		p_std_error( "sysctl()" );
		return( -1 );
	}

	if( !(data = (char*)malloc( len )) ){
		p_std_error( "malloc()" );
		return( -1 );
	}

	if( sysctl( info, 6, data, &len, NULL, 0 ) < 0 ){
		p_std_error( "sysctl()" );
		return( -1 );
	}

	for( next = data; next < data + len; next += ifmsg->ifm_msglen ){
		ifmsg = (struct if_msghdr*) next;
		if( ifmsg->ifm_type == RTM_IFINFO ){
			sa_dl = (struct sockaddr_dl*)( ifmsg + 1 );
			if( !strncmp( &sa_dl->sdl_data[ 0 ], 
					iface->name, sa_dl->sdl_len ) ){
				memcpy( iface->hw_address, 
					LLADDR( sa_dl ), MAC_ADDR_SIZE );
				break;
			}
		}
	}

	free( data );

	return( 1 );
}

/* this has been taken from ettercap source (src/OS/ec_inet_BSD.c) */
int get_raw_socket( struct interface_t *iface )
{
	int	fd = -1,
		type,
		i = 0,
		n = 0;
	char	device[ sizeof( "/dev/bpfxxxx" ) ];
	struct	bpf_version
		bpfv;
	struct ifreq
		ifr;

	struct bpf_insn insns[] = {
		BPF_STMT( BPF_LD  + BPF_H + BPF_ABS, MAC_ADDR_SIZE + 0x04 ),
		BPF_JUMP( BPF_JMP + BPF_JEQ + BPF_K, 0x00, 0x00, 0x04 ),
		BPF_STMT( BPF_LD  + BPF_H + BPF_ABS, MAC_ADDR_SIZE + 0x02 ),
		BPF_JUMP( BPF_JMP + BPF_JEQ + BPF_K, 0x00, 0x00, 0x02 ),
		BPF_STMT( BPF_LD  + BPF_H + BPF_ABS, MAC_ADDR_SIZE + 0x04 ),
		BPF_JUMP( BPF_JMP + BPF_JEQ + BPF_K, 0x00, 0x01, 0x00 ),
		BPF_STMT( BPF_RET | BPF_K, (u_int) -1 ),
		BPF_STMT( BPF_RET | BPF_K, 0x00 )
	};

	struct bpf_program filter = {
		( sizeof( insns ) / sizeof( struct bpf_insn ) ),
		insns
	};
	
	/* put our interface's MAC in the filter */
	for( i = 0; i < MAC_ADDR_SIZE; i += 2 )
		insns[ i + 1 ].k = 
			htons( *( short* )( iface->hw_address + i ) );

	do{
		sprintf( device, "/dev/bpf%i", n++);
		fd = open( device, O_RDWR );
	}while( fd < 0 && errno == EBUSY );

	if( fd < 0 ){
		p_error( "couldn't find an available bpf device" );
		return( -1 );
	}

	/* bpf version */
	if( ioctl( fd, BIOCVERSION, (caddr_t) &bpfv ) < 0 )
		p_std_error( "ioctl( BIOCVERSION )" );
	else
		if( bpfv.bv_major != BPF_MAJOR_VERSION || 
		    bpfv.bv_minor < BPF_MINOR_VERSION ){
			p_error( "bpf too old" );
			close( fd );
			return( -1 );
		}
	
	for( size = 32768; size; size >>= 1 ){
		ioctl( fd, BIOCSBLEN, (caddr_t) &size );

		strncpy( ifr.ifr_name, iface->name, sizeof( ifr.ifr_name ) );
		if( !(ioctl( fd, BIOCSETIF, (caddr_t) &ifr ) < 0) )
			break; 
	}
	
	if( !size ){
		p_error( "couldn't find a buffer size that worked" );
		close( fd );
		return( -1 );
	}

	if( ioctl( fd, BIOCGBLEN, (caddr_t) &size ) < 0 ){
		p_std_error( "ioctl( BIOCGBLEN )" );
		close( fd );
		return( -1 );
	}

	/* check data link layer type - gotta be ethernet */
	if( ioctl( fd, BIOCGDLT, (caddr_t) &type ) < 0 )
		p_std_error( "ioctl( BIOCGDLT )" );
	else
		if( type != DLT_EN10MB ){
			p_error( "data link type not supported" );
			close( fd );
			return( -1 );
		}
	
	if( (i = 1) && ioctl( fd, BIOCIMMEDIATE, (caddr_t) &i ) < 0 ){
		p_std_error( "ioctl( BIOCIMMEDIATE )" );
		return( -1 );
	}
	
	if( ioctl( fd, BIOCSETF, (caddr_t) &filter ) < 0 ){
		p_std_error( "ioctl( BIOCSETF )" );
		return( -1 );
	}
	
	return( fd );
}

int prepare_raw_to_receive( struct interface_t *iface )
{
	return( get_raw_socket( iface ) );
}

#ifndef min
#define min( a, b ) ( (a) < (b) ? (a) : (b) )
#endif

int get_raw_packet( int sd, char *buffer, int max_len )
{
	int	len;
	char	local_buffer[ size ],
		*p = local_buffer;
	unsigned int
		ret_size = -1,
		caplen,
		hdrlen;
	struct packet_t
		*packet = NULL;

	if( !queue_empty( &incoming_queue ) ){
		queue_extract(  packet, &incoming_queue, 
				struct packet_t* );
		memcpy( buffer, packet->data, 
			(ret_size = min( packet->size, max_len )) );
		release( packet->data );
		release( packet );
		
		return( ret_size );
	}

	if( (len = read( sd, local_buffer, size )) < 0 )
		p_std_error( "read()" );
	
	while( p < ( local_buffer + len ) ){
		caplen = ((struct bpf_hdr*)p)->bh_caplen;
		hdrlen = ((struct bpf_hdr*)p)->bh_hdrlen;
		
		if( !packet ){
			ret_size = min( caplen, max_len );
			memcpy( buffer, p + hdrlen, ret_size );
			packet = ( void* ) 0x01; /* use it as flag */
		}else{ /* the buffer given as argument has already
		        * been used - we need to enqueue this packet */
			packet = ( struct packet_t* )
				 allocate( sizeof( struct packet_t ) );
			packet->data = ( uint8_t* ) allocate( caplen );
			memcpy( packet->data, p + hdrlen, caplen );
			packet->size = caplen;
			queue_insert( packet, &incoming_queue );
		}
		p += BPF_WORDALIGN( hdrlen + caplen );
	}

	return( ret_size );
}

int send_raw_packet( int sd,
		     struct packet_t *packet,
		     struct interface_t *iface )
{
	int	sent,
		i;
	struct timespec
		time = { SEND_SEC_WAIT, SEND_NANO_WAIT };
	do{
		if( (sent = write( sd, packet->data, packet->size )) < 0 )
			p_std_error( "write()" );
	}while( sent < packet->size && errno == ENOBUFS &&
		nanosleep( &time, NULL ) );

	return( sent );
}
#endif
