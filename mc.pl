#!/usr/bin/perl -w

BEGIN { unshift @INC, "lib" }
use strict;
use SNMP::MIB::Compiler;
use Data::Dumper;

my $outdir = 'out';
my $file   = shift || 'SNMPv2-MIB';

my $mib = new SNMP::MIB::Compiler;
$mib->add_path('mibs', '/foo/bar/mibs', '/home/ftp/doc/mibs/ascend');
$mib->add_extention('', '.mib', '.my');

mkdir $outdir, '0755' unless -d $outdir;
$mib->repository($outdir);

$mib->{'accept_smiv1'} = 1;
$mib->{'accept_smiv2'} = 1;

$mib->{'debug_recursive'} = 1;
$mib->{'debug_lexer'}     = 0;

$mib->{'make_dump'}  = 1;
$mib->{'use_dump'}   = 1;
$mib->{'do_imports'} = 1;

# $mib->load($file) || $mib->compile($file);

# my $node = 'snmpEnableAuthenTraps';
# my $oid = $mib->resolve_oid($node);
# print "$node => $oid\n";
# print "$oid => ", $mib->convert_oid($oid), "\n\n";

$mib->load($file) || $mib->compile($file);

print $mib->resolve_oid('ifInOctets'), "\n";
print $mib->convert_oid('1.3.6.1.2.1.31.1.1.1.10'), "\n";
print $mib->tree('ifMIB');