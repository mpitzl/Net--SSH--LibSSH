# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Net-SSH-LibSSH.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;
use warnings;

use Test::More tests => 9;
BEGIN { use_ok('Net::SSH::LibSSH', qw(error_string)) };

# Create new object
my $ssh = Net::SSH::LibSSH->new(
    server => 0,
    debug  => 0,
);
isa_ok($ssh, 'Net::SSH::LibSSH');

can_ok($ssh, 'error_string');
is($ssh->error_string(0), 'success', 'Check error string for SSH_ERR_SUCCESS');
is($ssh->error_string(-38),
    'rekeying not supported by peer',
    'Check error string for SSH_ERR_NEED_REKEY'
);
is($ssh->error_string(-39),
    'unknown error',
    'Check error string for unknown error code'
);

is(error_string(0),
    'success', 'Check error string for SSH_ERR_SUCCESS');
eval {Net::SSH::LibSSH->error_string()};
ok($@, "Calling error_string() without argument dies: $@");

eval {Net::SSH::LibSSH->error_string('lalala')};
ok($@, "Calling error_string() with string dies: $@");
