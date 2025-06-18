#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <raw_inet.h>

#ifndef __INET_CONV_H
#define   __INET_CONV_H

#define LINE_LEN 	0x0010
#define ADDR_BUFFER_LEN 0x0014

int str_to_hwaddr( char *, uint8_t *, int );
int str_to_inetaddr( char *, uint8_t *, int );
char* hwaddr_to_str( uint8_t *, char *, int );
char* inetaddr_to_str( uint8_t *, char *, int );

void hexdump( uint8_t*, int );

#endif
