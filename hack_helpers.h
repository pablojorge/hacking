#ifndef	__HACK_HELPERS_H
#define   __HACK_HELPERS_H

size_t _strlen( const char *s );
int    _memcmp( const void *s1, const void *s2, int n );
void*  _memcpy( void *dest, const void *orig, int n );
void*  _memset( void *dest, int c, int n );

#if 0
#if defined( memset )
#undef memset
#endif
#define	memcmp _memcmp
#define	memcpy _memcpy
#define	memset _memset
#define strlen _strlen
#endif
	
#endif
