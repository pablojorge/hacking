TOPDIR 	= ..
INCLUDE = -I $(TOPDIR)/../include -I .
LIB 	= -L $(TOPDIR)/../lib
ALL 	= arpspoof sniff wol rip test_asm
BIN	= $(TOPDIR)/../bin/
INSTALL = $(ALL)
HEADERS = raw_inet.h

include $(TOPDIR)/Rules.mk

HACKING_OBJECTS=raw_inet.o inet_conv.o #hack_helpers.o
SHARED_OBJECTS=memmgmt.o list.o wrappers.o

arpspoof: arpspoof.o $(SHARED_OBJECTS) $(HACKING_OBJECTS) raw_operations.o $(HEADERS)
	$(link)

sniff: sniff.o $(HACKING_OBJECTS) raw_operations.o $(SHARED_OBJECTS) $(HEADERS)
	$(link)

wol: wol.o $(HACKING_OBJECTS) $(SHARED_OBJECTS) $(HEADERS)
	$(link)

rip: rip.o $(HACKING_OBJECTS) $(SHARED_OBJECTS) $(HEADERS)
	$(link)

test_asm: test_asm.o hack_helpers.o inet_conv.o $(SHARED_OBJECTS) $(HEADERS)
	$(link)
