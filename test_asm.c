#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hack_helpers.h>
#include <inet_conv.h>

#define __STR "some string"

int main( int argc, char *argv[] )
{
	char	*string,
		buffer[ 1000 ];
	int	i = 4000000;
	
	string = (char*) allocate( strlen( __STR ) + 1 );
	_memcpy( string, __STR, strlen( __STR ) );
	
	printf( "%s \n"
		"strlen(): %i _strlen(): %i \n"
		"memcmp(): %i _memcmp(): %i \n"
		"memcmp(s,s+1): %i _memcmp(s,s+1): %i \n"
		"memcmp(s+1,s): %i _memcmp(s+1,s): %i \n",
	      	 string, 
		 strlen( string ), 
		_strlen( string ),
		 memcmp( string, string, _strlen( string ) ), 
		_memcmp( string, string, _strlen( string ) ),
		 memcmp( string, string + 1, _strlen( string ) - 1 ),	
		_memcmp( string, string + 1, _strlen( string ) - 1 ),
		 memcmp( string + 1, string, _strlen( string ) - 1 ),	
		_memcmp( string + 1, string, _strlen( string ) - 1 ) );
	
	hexdump( buffer, 16 );
	memcpy( buffer, string, _strlen( string ) + 1 );
	hexdump( buffer, 16 );
	_memcpy( buffer, string, _strlen( string ) + 1 );
	hexdump( buffer, 16 );
	memset( buffer, 0x1123, _strlen( string ) + 1 );
	hexdump( buffer, 16 );
	_memset( buffer, 0x1123, _strlen( string ) + 1 );
	hexdump( buffer, 16 );

	if( argc > 1 )
		switch( atoi( argv[ 1 ] ) ){
			case( 1 ):
				while( i-- )
					strlen( string );
				break;
			case( 2 ):
				while( i-- )
					_strlen( string );
				break;
			case( 3 ):
				while( i-- )
					memcmp( string, string, 
							_strlen( string ) );
				break;
			case( 4 ):
				while( i-- )
					_memcmp( string, string, 
							_strlen( string ) );
				break;
			case( 5 ):
				while( i-- )
					memcpy( buffer, string, 
							_strlen( string ) );
				break;
			case( 6 ):
				while( i-- )
					_memcpy( buffer, string,
							_strlen( string ) );
				break;
			case( 7 ):
				while( i-- )
					memset( buffer, 0x1122, 16 );
				break;
			case( 8 ):
				while( i-- )
					_memset( buffer, 0x1122, 16 );
				break;
		}

	return( 0 );
}
