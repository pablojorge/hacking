.text
.global _strlen
.global	_memcmp
.global	_memcpy
.global	_memset

/**
 * _strlen:
 * 	size_t _strlen( const char *s )
 * 
 *	8(%ebp)	: s
 *
 * 	an attempt to make strlen() faster
 *
 * 	the idea is to reach the end of the string and then return the 
 *	difference between the ending address and starting address. 
 *	this is faster than a counter, because inside the loop we only 
 *	increment the address.
 */

_strlen:
	pushl	%ebp		# saving %ebp
	movl	%esp, 	 %ebp	# using %ebp as a 'reference' in the stack

	movl  8(%ebp),	 %eax	# 'string' => eax 

.__strlen_loop:
	cmpb   $0x00,   (%eax)
	je      .__strlen_end
	incl	%eax
	jmp	.__strlen_loop

.__strlen_end:
	subl  8(%ebp),   %eax	# the string is "%eax - 8(%ebp)" bytes long

	movl	%ebp,	 %esp
	popl	%ebp
	ret

/**
 * _memcmp:
 *	int   _memcmp( const void *s1, const void *s2, int n )
 *	
 *	8(%ebp)	: s1
 *     12(%ebp) : s2
 *     16(%ebp) : n
 */

_memcmp:
	pushl	%ebp
	movl	%esp,	 %ebp
	pushl	%ebx		# saving the registers
	pushl	%ecx
	pushl	%edx

	movl  8(%ebp),	 %ebx	# moving data from the stack into the registers
	movl 12(%ebp),   %ecx	# to make access to their values faster
	movl 16(%ebp),   %edx

	xorl	%eax,	 %eax	# clear eax

	cmpl   $0x00,	 %edx	# if 'n' is less or equal to zero before 
	jle	.__memcpy_end	# starting, do nothing

.__memcmp_loop:
	movb   (%ebx),	 %al	
	subb   (%ecx),	 %al	# get the difference between the two bytes
	jne	.__memcmp_not_equal
	incl	%ebx
	incl	%ecx
	decl	%edx
	je	.__memcmp_end	# 'n' reached zero
	jmp	.__memcmp_loop

.__memcmp_not_equal:
	jg	.__memcmp_greater
	xorl	%eax, 	 %eax
	decl	%eax
	jmp	.__memcmp_end

.__memcmp_greater:
	xorl	%eax,	 %eax
	incl	%eax
	jmp	.__memcmp_end

.__memcmp_end:
	popl	%edx		# restore register's previous values
	popl	%ecx
	popl	%ebx
	
	movl	%ebp,	 %esp
	popl	%ebp
	ret

/**
 * _memcpy:
 *	void* _memcpy( void *dest, const void *orig, int n )
 *	
 *	8(%ebp)	: dest
 *     12(%ebp) : orig
 *     16(%ebp) : n
 */

_memcpy:
	pushl	%ebp
	movl	%esp,	 %ebp
	pushl	%ebx
	pushl	%ecx
	pushl	%edx

	movl  8(%ebp),	 %eax
	movl 12(%ebp),   %ebx
	movl 16(%ebp),   %ecx

	cmpl   $0x00,	 %ecx
	jle	.__memcpy_end

.__memcpy_loop:
	movb   (%ebx),	 %dl
	movb	%dl,	(%eax)
	incl	%eax
	incl	%ebx
	decl	%ecx
	je	.__memcpy_end
	jmp	.__memcpy_loop

.__memcpy_end:
	popl	%edx
	popl	%ecx
	popl	%ebx
	
	movl  8(%ebp),	 %eax
	
	movl	%ebp,	 %esp
	popl	%ebp
	ret

/**
 * _memset:
 *	void* _memset( void *dest, int c, int n )
 *	
 *	8(%ebp)	: dest
 *     12(%ebp) : c
 *     16(%ebp) : n
 */

_memset:
	pushl	%ebp
	movl	%esp,	 %ebp
	pushl	%ebx
	pushl	%ecx

	movl  8(%ebp),	 %eax
	movl 12(%ebp),   %ebx
	movl 16(%ebp),   %ecx

	cmpl   $0x00,	 %ecx
	jle	.__memset_end

.__memset_loop:
	movb    %bl,	(%eax)
	incl	%eax
	decl	%ecx
	je	.__memset_end
	jmp	.__memset_loop

.__memset_end:
	popl	%ecx
	popl	%ebx
	
	movl  8(%ebp),	 %eax
	
	movl	%ebp,	 %esp
	popl	%ebp
	ret

