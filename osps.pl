#! perl
# Author: Kenneth Kron kkron@zanshinryu.com
# @(#) netcat.pl	Sends to a nominated socket on remote server.
#			Can be used with HP Jetdirect and similar devices.
#
# Copyright (c) 2002 Graham Jenkins <grahjenk@au1.ibm.com>. All rights reserved.
# This program is free software; you can redistribute it and/or modify it under
# the same terms as Perl itself.

require 'sanity.pl' ;
use strict;
use File::Copy;
use File::Basename;
use File::stat qw(:FIELDS);

use Getopt::Long qw(:config bundling_override);
use Pod::Usage;

my $VERSION ;
$VERSION = "1.0";
my ($Port,$debug,$invalid,$start,$Input,$Output,$buffer,$prev);
my $timeout=3600;

# var,[=:],[isf]
my $man = 0;
my $help =0;
my $version = 0;
my $verbose = 0;
my $name ;
my $path ;
my $file ;
my $suffix ;
my $FileVersion ;
my $UserList ;
my $Notify ;
my %Notify; $Notify{"none"}=1 ; $Notify{"mail"} =1;
my @Add ;
my $INPUT ;
my $Start ;
my $End ;
GetOptions ('help|?' => \$help,
	    'man' => \$man,
	    'version' => \$version,
	    'file=s' => \$file,
	    'verbose|v' => \$verbose,
#            'debug:i' => \$log
	   ) or pod2usage(1);
pod2usage(1) if $help;
pod2usage(-exitstatus => 0, -verbose => 2) if $man;
print "$VERSION\n" and exit(0) if $version;

$Input = $file ;
($name,$path,$suffix) = fileparse($file, ".osps") ;
$Output = $path . $name ;
my ($Range, $Encryptor, @Line) ;
$INPUT = mustopen ("<$Input");

chomp($_=<$INPUT>) ;
@Line =  split / /,$_;
$FileVersion=  $Line[2] ;
if (v1.0 < $FileVersion) {
  die "Configuration file version too high, upgrade osps" } ;

($_=<$INPUT>) ;
@Line = split / /, $_ ;
m/(\d+)\D+(\d+)/ =~ $Line[3] ;
($Start, $End) =  ($1, $2) ;
$Range = $End - $Start;
if ($Range<2) { die "Invalid range specified: $Range"} ;
$Port = $Start + krand() % $Range ;

chomp($_=<$INPUT>) ;
@Line = split / /, $_;
stat($Line[3]) or die "No encryptor found in $Input" ;
$Encryptor=  join(" ",(@Line[3..$#Line])) ;

chomp($_=<$INPUT>) ;
@Line = split / /, $_;
die "No user list found in $Input"
  if (!defined($UserList=  join(" ",@Line[3..$#Line]))) ;
$Encryptor .= join(" "," -r",$UserList,"--encrypt $Output") ;

chomp($_=<$INPUT>) ;
@Line = split / /, $_;
$Notify = $Line[3] ;
die "Invalid notify option found in $Input"
  if (!$Notify{$Notify}) ;

chomp($_=<$INPUT>) ;
@Line = split / /, $_;
@Add=  @Line[3..$#Line] ;
unlink ($Output) ;
my $OH = mustopen(">$Output") ;
while (<$INPUT>) {
  s/\$OSPS_Port/$Port/ ;
  print $OH $_ ;
}
close $OH ;

unlink ("$Output\.asc") ;
system("$Encryptor") ;
#system("echo $Encryptor") ;
#$_ = $Notify{$Notify} {
#   /mail/ && 
     do { system("mail -s \"Updated OSPS file for $Output\<$Input\.asc\"") } ;
#}


__END__

=head1 NAME

osps.pl - 


=head1 SYNOPSIS

osps [--debug] [--version] [--file {path to OSPSified config file}]


=head1 DESCRIPTION

OSPS - (ô sp -s z ) as in auspices. Obfuscated Server Port Service.

OSPS is a service port generator and cryptographic communication system. OSPS
is designed to make it easier for you to implement need-to-know security for
your server port #'s. OSPS is a simple but effective system for making your
private services that much harder to hack. If your IDS/IPS is working then you
should be fairly able to detect a port scan looking for open services and you
can defend against those to a degree but if you are running your services on
WKS ports then scanning isn't required nor is any ``man in the middle
attack''. OSPS is designed to hide the service port #'s from those who do not
need to know and yet make them available to those who do need to know.

Services running under the OSPS of OSPS get their listening port number
randomly generated on a regular basis. When it's time to choose a new port
OSPS generates the port # and restarts the service. OSPS then uses public key
encryption to encrypt the new port # information for all of the authorized
users of the service and then places that file in a well known location. Since
it is encrypted the port # file can even be placed in a public location,
emailed to all authorized users or placed in a well know but secure location
all of which is supported by OSPS.

=head2 How does OSPS work.

Generating new port numbers for services. The operation of OSPS has been
modeled after chkconfig which should be familiar to modern system admins.


An OSPSified config file will contain the following lines at the start of the
file

# OSPS v.$x as the first line.
# osps: port_range n-m {Acceptable port range}
# osps: encryptor (encryptor and argument list)
# osps: user list (this list will be passed to encryptor & notify if notify =
mail)
# osps: notify (none|mail|/path/to/status/file)

and optionally

#osps: additional files (absolute path to additional OSPSified configuration
files which need to be synchronized with this configuration file.

If any of these lines is non-existent osps will exit with an error message.

Scheduling:

OSPS contains no scheduling information on how often to regenerate port #'s
OSPS expects to be called by a scheduler/security system when it's time to
change port #'s.

OSPS reads /etc/OSPS.conf to decide get it's task list.


