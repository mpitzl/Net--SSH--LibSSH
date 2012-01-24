# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Net-SSH-LibSSH.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;
use warnings;

use Test::More tests => 6;
BEGIN { use_ok('Net::SSH::LibSSH') };

# Create new object
my $ssh = Net::SSH::LibSSH->new(
    server => 0,
    debug  => 0,
);
isa_ok($ssh, 'Net::SSH::LibSSH');

is($ssh->error_string(0), 'success', 'Check error string for SSH_ERR_SUCCESS');
is($ssh->error_string(-38),
    'rekeying not supported by peer',
    'Check error string for SSH_ERR_NEED_REKEY'
);
is($ssh->error_string(-39),
    'unknown error',
    'Check error string for unknown error code'
);

is(Net::SSH::LibSSH->error_string(0), 'success', 'Check error string for SSH_ERR_SUCCESS');
