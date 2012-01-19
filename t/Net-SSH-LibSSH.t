# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Net-SSH-LibSSH.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;
use warnings;

use Test::More tests => 2;
BEGIN { use_ok('Net::SSH::LibSSH') };

# Create new object
my $ssh = Net::SSH::LibSSH->new(
    server => 0,
    debug  => 0,
);
isa_ok($ssh, 'Net::SSH::LibSSH');
