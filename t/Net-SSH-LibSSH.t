# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Net-SSH-LibSSH.t'
# change 'tests => 1' to 'tests => last_test_to_print';
#########################
use strict;
use warnings;

use Test::More tests => 18;
BEGIN { use_ok('Net::SSH::LibSSH', qw(:all)) };

# Create new object
my $ssh = Net::SSH::LibSSH->new(
    server => 1,
    debug  => 0,
);
isa_ok($ssh, 'Net::SSH::LibSSH');

can_ok($ssh, 'error_string');
is($ssh->error_string(0), 'success', 'Check error string for SSH_ERR_SUCCESS');
is($ssh->error_string(-38),
    'rekeying not supported by peer',
    'Check error string for SSH_ERR_NEED_REKEY'
);
is($ssh->error_string(-80),
    'unknown error',
    'Check error string for unknown error code'
);

is(error_string(0),
    'success', 'Check error string for SSH_ERR_SUCCESS');
eval {Net::SSH::LibSSH->error_string()};
ok($@, "Calling error_string() without argument dies:\n$@");

eval {Net::SSH::LibSSH->error_string('lalala')};
ok($@, "Calling error_string() with string dies:\n $@");

my $privkey = qq{-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAuWTBp2h37Qr9ycFl0l6Mp6SS0bZ1irWqClFQ6py1/aQABEw2
sa/UuCxn3kvuvdCDaWw7FfW9FtXNnmK08MWFGuCgBkf0gTibMj5XOjNl47SEQYta
18Lx7C93h587MnZwp2SLqtpPfejOQAz5bwbYQtg9BJ9/YToatiUbMeQqKxtjW8c0
fP+cTKCHeRuVf4oLZ/Rv3nJjLNPE6XndM/VdG+lmdHOAUMurnTgkX048TmXE4OxI
rQUq79B0jFCwIeYH6gQGHE+VFfF/n1h21bhbjIKx0XY/U4wWrk7Wzv4Qj+RbPpGs
9DOilssfLHiEh1iPApHlICFRxxa896isZOtVrQIDAQABAoIBAF3SPaaI2dgeLd1C
gFL8AlZ8lMiIe+eck9bw2/A/KmKX8mI6Z5t4jkA+SLpY1xM8SKS7XxN37x91R7+V
2FfYvcmiT5meJICYswG0RtRvWmrn2d6JtYlnYKLUSrtZu82H3u73lS77mCrx/B6x
8jFb12nMoOSMCxybGRWApciT3Ts+noA4xdyvJWakwOGYwEP4+skLNwxm2F62EXWS
4fO69D5CQ3dS5HOhPugJeg+Mjl9KsW5MPPFxhYfcqZM1t+CIjcNIWFWIg2X1TULK
dh9nM9KAbGhAmupf3CTr2DWwIwkXYPxTbu4X+5OIcfM8uT+cGRcK3+itrongz6So
RQJmakkCgYEA3DaxnM0sSG1jHuhEBBX5S9AvpJknYCDV7rx3TBMVwkmEcU2I6Eif
ZSvH/hbhOSfsVEIoanKq680PoX+AO+z79U3Y8UeDEbK93e5W3XShtbRlEF98PPxF
NZ4XS9zlXyJ1izEHRj49tstvW3PNJ0MD6MTl8SspH6rP3Uisq+0nTZsCgYEA14V7
Tz4qt/hq0FV8270Cy3bPRn7oFRy0/FsC2TOLu6naAcCQIcLgWXPEJOqfcnyXiZck
PBsWh745Bm1Ry9veF0X+z0FhMzOWSIIf7UCRHpVI8PVjYGDrWKLbmo59teEiOgiY
7wMYQbE88JnCIYF7zxRoVFI7B9yGZxr4aE+KQlcCgYBVKa28pzhF9k/MByUus1TK
9gNG05f/vBMgFbDJMeRLU+UtcD/PHS7PkIPyhuSpFwB1gXRh3mCteotd+JIeGsNC
Fc4dWXud35M//cmIMW/MdqxTDapdZ25YkwANbasjBI+Sue5HQxDY3Yn+QyWG1orv
fR40C24G+icTO+TTRI7bmwKBgFcY3YVftTnVzazV73iKAPgi0o9FuBrYGBgn25XV
a/HyKWUt4dGTBMGBtFHK85b73O3Aw+b6d3dyG2+KfFTrTOyQ3/H4FQTxIxm4ZJin
0D3QzMJ8GKYZZOLUJfVnAkyfaAqV8OAemw3pR5xgNwD9aAB+2c7B0JNTvokqcBsP
ketPAoGAf2hRVfqIdtNm092ZMLRpnuf/Z84CZ3hM/uclLbb0ZoUOrAZ6EewGJytk
taKg5ZE91BaGtEpc4DCvxnOejdCTtbNbKBYzIDvfp1Efe5ktl+sPlC8TuWPdV1Ih
L2JmgD17Wk/dh8wuN4qjQHap9BQf2G+vDPAJ9d31JVSdMCBQ9wM=
-----END RSA PRIVATE KEY-----};

my $ret = $ssh->add_hostkey($privkey);
ok($ret == 0, "Error loading valid private key: " . $ssh->error_string($ret));

$ret = $ssh->add_hostkey('');
ok($ret < 0, "Loading empty key returns no error!");

$ret = $ssh->add_hostkey("\0\0\0\0\0\lalalala\0\0\0");
ok($ret < 0, "Loading broken key returns no error!");

$ret = $ssh->add_hostkey(substr($privkey, 100, 10, 'x' x 10));
ok($ret < 0, "Loading invalid private key returns no error!");

my $pubkey = <<'EOF';
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC5ZMGnaHftCv3JwWXSXoynpJLRtnWKtaoKUVDqnLX9pAAETDaxr9S4LGfeS+690INpbDsV9b0W1c2eYrTwxYUa4KAGR/SBOJsyPlc6M2XjtIRBi1rXwvHsL3eHnzsydnCnZIuq2k996M5ADPlvBthC2D0En39hOhq2JRsx5CorG2NbxzR8/5xMoId5G5V/igtn9G/ecmMs08Tped0z9V0b6WZ0c4BQy6udOCRfTjxOZcTg7EitBSrv0HSMULAh5gfqBAYcT5UV8X+fWHbVuFuMgrHRdj9TjBauTtbO/hCP5Fs+kaz0M6KWyx8seISHWI8CkeUgIVHHFrz3qKxk61Wt tester@example.org
EOF

# For testing the parsing of public keys, we need a client side
# Net::SSH::LibSSH object
my $client = Net::SSH::LibSSH->new(
    server => 0,
    debug  => 0,
);
$ret = $client->add_hostkey($pubkey);
ok($ret == 0, "Error loading valid public key: " . $client->error_string($ret));

$ret = $client->add_hostkey(substr($pubkey, 100, 10, 'x' x 10));
ok($ret < 0, "Loading invalid public key returns no error!");

ok(type_to_string(1) eq 'SSH2_MSG_DISCONNECT',
    'Convert numeric type into string'
);
ok(disconnect_to_string(10) eq 'SSH2_DISCONNECT_CONNECTION_LOST',
    'Convert numeric disconnect reason code into string'
);
ok(chan_open_to_string(1) eq 'SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED',
    'Convert numeric channel open reason code into string'
);

