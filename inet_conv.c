#include <inet_conv.h>

static int split_address( char *, char );

int str_to_hwaddr( char *address,
		   uint8_t *buffer,
		   int buf_len )
{
	char	*p;
	int	addr[ MAC_ADDR_SIZE ],
		count,
		i;
	
	memset( buffer, 0x00, buf_len );
	
	for( p = address; *p; p++ )
		if( *p != ':' && !isxdigit( *p ) ){
			fprintf( stderr, 
				 __FILE__ 
				 ": str_to_hwaddr()"
				 ": invalid digits present in address"
				 " (%c in %s) \n", *p, address );
			return( -1 );
		}
	
	if( (count = split_address( address, ':' )) != MAC_ADDR_SIZE ){
		fprintf( stderr, __FILE__
				": str_to_hwaddr()"
				": mac address size invalid \n" );
		return( -1 );
	}
	
	for( i = 0; i < buf_len && i < MAC_ADDR_SIZE; i++ ){
		addr[ i ] = strtol( address, NULL, 16 );
		address += strlen( address ) + 1;

		if( !( addr[ i ] < 0x100 ) ){
			fprintf( stderr, __FILE__ 
					": str_to_hwaddr()"
					": too big value in the address \n");
			return( -1 );
		}

		buffer[ i ] = addr[ i ];
	}

	return( 1 );
}

int str_to_inetaddr( char *address,
		     uint8_t *buffer,
		     int buf_len )
{
	char	*p;
	int	addr[ IP_ADDR_SIZE ],
		count,
		i;

	memset( buffer, 0x00, buf_len );

	for( p = address; *p; p++ )
		if( *p != '.' && !isdigit( *p ) ){
			fprintf( stderr, 
				 __FILE__ 
				 ": str_to_inetaddr()"
				 ": invalid digits present in address"
				 " (%c in %s) \n", *p, address );
			return( -1 );
		}
	
	if( (count = split_address( address, '.' )) != IP_ADDR_SIZE ){
		fprintf( stderr, __FILE__
				": str_to_inetaddr()"
				": ip address size invalid \n" );
		return( -1 );
	}

	for( i = 0; i < buf_len && i < IP_ADDR_SIZE; i++ ){
		addr[ i ] = atoi( address );
		address += strlen( address ) + 1;

		if( !( addr[ i ] < 0x100 ) ){
			fprintf( stderr, 
				__FILE__ 
				": str_to_inetaddr()"
				": too big value in the address \n");
			return( -1 );
		}

		buffer[ i ] = addr[ i ];
	}
	
	return( 1 );
}

char *hwaddr_to_str( uint8_t *address, 
		     char *buffer, 
		     int buf_len )
{
	snprintf( buffer, buf_len,
			"%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x", 
			address[ 0 ], address[ 1 ], address[ 2 ],
			address[ 3 ], address[ 4 ], address[ 5 ] );

	return( buffer );	
}

char *inetaddr_to_str(  uint8_t *address,
			char *buffer, 
			int buf_len )
{
	snprintf( buffer, buf_len,
			"%i.%i.%i.%i",  address[ 0 ], address [ 1 ],
					address[ 2 ], address [ 3 ] );

	return( buffer );
}

void hexdump( uint8_t *data, int len )
{
	int	i, j;

	for( i = 0; i < len; i += LINE_LEN ){
		printf( "%8.8x ", i );
		for( j = i; j < ( i + LINE_LEN ); j++ )
			if( j < len ) 
				printf( "%2.2x\x20", data[ j ] );
			else	printf( "\x20\x20\x20" );
		
		printf( "| " );
		
		for( j = i; j < ( i + LINE_LEN ) && j < len; j++ )
			if( isprint( data[ j ] ) ) 
				printf( "%c", data[ j ] );
			else	printf( "." );
		
		printf( " | \n" );
	}
}

static int split_address( char *address, char sep )
{
	int	count = 1;
	char	*where;

	while( address && *address && 
	      (where = strchr( address, sep )) ){
		*where = 0x00;
		address = where + 1;
		count++;
	}

	return( count );
}
