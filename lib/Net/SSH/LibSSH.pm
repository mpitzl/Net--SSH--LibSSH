package Net::SSH::LibSSH;

use 5.012002;
use strict;
use warnings;

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# Constants for the SSH packet types, taken from ssh2.h
use constant {
    SSH2_MSG_DISCONNECT                    => 1,
    SSH2_MSG_IGNORE                        => 2,
    SSH2_MSG_UNIMPLEMENTED                 => 3,
    SSH2_MSG_DEBUG                         => 4,
    SSH2_MSG_SERVICE_REQUEST               => 5,
    SSH2_MSG_SERVICE_ACCEPT                => 6,
    SSH2_MSG_KEXINIT                       => 20,
    SSH2_MSG_NEWKEYS                       => 21,
    SSH2_MSG_KEXDH_INIT                    => 30,
    SSH2_MSG_KEXDH_REPLY                   => 31,
    SSH2_MSG_KEX_DH_GEX_REQUEST_OLD        => 30,
    SSH2_MSG_KEX_DH_GEX_GROUP              => 31,
    SSH2_MSG_KEX_DH_GEX_INIT               => 32,
    SSH2_MSG_KEX_DH_GEX_REPLY              => 33,
    SSH2_MSG_KEX_DH_GEX_REQUEST            => 34,
    SSH2_MSG_KEX_ECDH_INIT                 => 30,
    SSH2_MSG_KEX_ECDH_REPLY                => 31,
    SSH2_MSG_USERAUTH_REQUEST              => 50,
    SSH2_MSG_USERAUTH_FAILURE              => 51,
    SSH2_MSG_USERAUTH_SUCCESS              => 52,
    SSH2_MSG_USERAUTH_BANNER               => 53,
    SSH2_MSG_USERAUTH_PK_OK                => 60,
    SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ     => 60,
    SSH2_MSG_USERAUTH_INFO_REQUEST         => 60,
    SSH2_MSG_USERAUTH_INFO_RESPONSE        => 61,
    SSH2_MSG_USERAUTH_JPAKE_CLIENT_STEP1   => 60,
    SSH2_MSG_USERAUTH_JPAKE_SERVER_STEP1   => 61,
    SSH2_MSG_USERAUTH_JPAKE_CLIENT_STEP2   => 62,
    SSH2_MSG_USERAUTH_JPAKE_SERVER_STEP2   => 63,
    SSH2_MSG_USERAUTH_JPAKE_CLIENT_CONFIRM => 64,
    SSH2_MSG_USERAUTH_JPAKE_SERVER_CONFIRM => 65,
    SSH2_MSG_GLOBAL_REQUEST                => 80,
    SSH2_MSG_REQUEST_SUCCESS               => 81,
    SSH2_MSG_REQUEST_FAILURE               => 82,
    SSH2_MSG_CHANNEL_OPEN                  => 90,
    SSH2_MSG_CHANNEL_OPEN_CONFIRMATION     => 91,
    SSH2_MSG_CHANNEL_OPEN_FAILURE          => 92,
    SSH2_MSG_CHANNEL_WINDOW_ADJUST         => 93,
    SSH2_MSG_CHANNEL_DATA                  => 94,
    SSH2_MSG_CHANNEL_EXTENDED_DATA         => 95,
    SSH2_MSG_CHANNEL_EOF                   => 96,
    SSH2_MSG_CHANNEL_CLOSE                 => 97,
    SSH2_MSG_CHANNEL_REQUEST               => 98,
    SSH2_MSG_CHANNEL_SUCCESS               => 99,
    SSH2_MSG_CHANNEL_FAILURE               => 100,
    SSH2_MSG_KEX_ROAMING_RESUME            => 30,
    SSH2_MSG_KEX_ROAMING_AUTH_REQUIRED     => 31,
    SSH2_MSG_KEX_ROAMING_AUTH              => 32,
    SSH2_MSG_KEX_ROAMING_AUTH_OK           => 33,
    SSH2_MSG_KEX_ROAMING_AUTH_FAIL         => 34,
};

our @EXPORT = qw(
    SSH2_MSG_DISCONNECT
    SSH2_MSG_IGNORE
    SSH2_MSG_UNIMPLEMENTED
    SSH2_MSG_DEBUG
    SSH2_MSG_SERVICE_REQUEST
    SSH2_MSG_SERVICE_ACCEPT
    SSH2_MSG_KEXINIT
    SSH2_MSG_NEWKEYS
    SSH2_MSG_KEXDH_INIT
    SSH2_MSG_KEXDH_REPLY
    SSH2_MSG_KEX_DH_GEX_REQUEST_OLD
    SSH2_MSG_KEX_DH_GEX_GROUP
    SSH2_MSG_KEX_DH_GEX_INIT
    SSH2_MSG_KEX_DH_GEX_REPLY
    SSH2_MSG_KEX_DH_GEX_REQUEST
    SSH2_MSG_KEX_ECDH_INIT
    SSH2_MSG_KEX_ECDH_REPLY
    SSH2_MSG_USERAUTH_REQUEST
    SSH2_MSG_USERAUTH_FAILURE
    SSH2_MSG_USERAUTH_SUCCESS
    SSH2_MSG_USERAUTH_BANNER
    SSH2_MSG_USERAUTH_PK_OK
    SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ
    SSH2_MSG_USERAUTH_INFO_REQUEST
    SSH2_MSG_USERAUTH_INFO_RESPONSE
    SSH2_MSG_USERAUTH_JPAKE_CLIENT_STEP1
    SSH2_MSG_USERAUTH_JPAKE_SERVER_STEP1
    SSH2_MSG_USERAUTH_JPAKE_CLIENT_STEP2
    SSH2_MSG_USERAUTH_JPAKE_SERVER_STEP2
    SSH2_MSG_USERAUTH_JPAKE_CLIENT_CONFIRM
    SSH2_MSG_USERAUTH_JPAKE_SERVER_CONFIRM
    SSH2_MSG_GLOBAL_REQUEST
    SSH2_MSG_REQUEST_SUCCESS
    SSH2_MSG_REQUEST_FAILURE
    SSH2_MSG_CHANNEL_OPEN
    SSH2_MSG_CHANNEL_OPEN_CONFIRMATION
    SSH2_MSG_CHANNEL_OPEN_FAILURE
    SSH2_MSG_CHANNEL_WINDOW_ADJUST
    SSH2_MSG_CHANNEL_DATA
    SSH2_MSG_CHANNEL_EXTENDED_DATA
    SSH2_MSG_CHANNEL_EOF
    SSH2_MSG_CHANNEL_CLOSE
    SSH2_MSG_CHANNEL_REQUEST
    SSH2_MSG_CHANNEL_SUCCESS
    SSH2_MSG_CHANNEL_FAILURE
    SSH2_MSG_KEX_ROAMING_RESUME
    SSH2_MSG_KEX_ROAMING_AUTH_REQUIRED
    SSH2_MSG_KEX_ROAMING_AUTH
    SSH2_MSG_KEX_ROAMING_AUTH_OK
    SSH2_MSG_KEX_ROAMING_AUTH_FAIL
);

our $VERSION = '0.01';

require XSLoader;
XSLoader::load('Net::SSH::LibSSH', $VERSION);

sub new {
    shift(); # Throw away the class
    my %args = @_;

    my $server = delete $args{server} // 0;
    my $debug  = delete $args{debug}  // 0;

    return init($server, $debug, \%args);
}

sub can_write {
    return length($_[0]->output_ptr());
}

sub DESTROY {
    $_[0]->free();
}

# Preloaded methods go here.

1;
__END__

=head1 NAME

Net::SSH::LibSSH - Perl extension for libopenssh

=head1 VERSION

Version 0.01

=head1 SYNOPSIS

  use Net::SSH::LibSSH;
  my $ssh = Net::SSH::LibSSH->new(
    server => 1,
    debug  => 0,
  ) or die "Error creating new Net::SSH::LibSSH object!";

  # Add a host key. Server needs a private, client a public key
  $ssh->add_hostkey($key_data)
      or die "Invalid host key given!";

  # Data read on fd must be added to the internal input buffer
  $ssh->input_append($data);

  # Get a SSH packet, returns 0 if no packet could be read
  # First call initiates banner exchange and key exchange which sets up the
  # encryption on transport layer level
  my $type = $ssh->packet_next();
  if ($type) {
      ...
  } else {
      # read more data
  }

  # Put packet into output buffer
  $ssh->packet_put($type, $data);

  # Write data if any
  if(my $olen = $ssh->can_write()) {
      # write $olen bytes of data to socket
  }

=head1 DESCRIPTION

Net::SSH::LibSSH is a Perl binding to libopenssh enabling the user to write
programs using the low level SSH2 api. Hides all the encryption done on
transport layer.

Net::SSH::LibSSH provides no functionality for actual reading or writing data.
It just provides access to the SSH2 internal input and output buffers containing
the unencrypted packets.

=head2 METHODS

=over 2

=item new()

Constructor creating a new Net::SSH::LibSSH object. On failure B<undef> is
returned.

Supports the following options:

=over 4

=item server => [0|1]

Mode of operation for the library. 0 means to operate as SSH2 client, 1 is the
SSH2 server mode.

=item debug => [0|1|2|3|4]

Set debug level. A value of 0 turns debugging off, 1 to 4 enables debugging. The
higher the debug level the more debug output is written to STDERR.

=item Key Exchange Parameters

The following keys are parameters for the SSH2 key exchange. Using these
parameters one can configure the cryptographic algorithms to use. For
possible values please read also ssh_config(5) and sshd_config(5).

Valid parameter names are:

=over 8

=item PROPOSAL_KEX_ALGS

=item PROPOSAL_SERVER_HOST_KEY_ALGS

=item PROPOSAL_ENC_ALGS_CTOS

=item PROPOSAL_ENC_ALGS_STOC

=item PROPOSAL_MAC_ALGS_CTOS

=item PROPOSAL_MAC_ALGS_STOC

=item PROPOSAL_COMP_ALGS_CTOS

=item PROPOSAL_COMP_ALGS_STOC

=item PROPOSAL_LANG_CTOS

=item PROPOSAL_LANG_STOC

=back

=back

=item add_hostkey($key_data)

Takes a string containing either a private or public key and tries to load it
into the Net::SSH::LibSSH object.

Returns 1 on success, 0 on failure.

=item packet_next()

This returns the type of the next packet which could be parsed from the input
buffer. If there was no packet or an incomplete packet, 0 is returned.

=item packet_payload()

Must be called after packet_next to get the payload of the available packet.

Returns the payload.

=item packet_put($type, $data)

Adds a packet of type $type with the payload $data to the internal output
buffer.

=item input_space($len)

Checks if there is enough input buffer space for $len bytes of data.

=item input_append($data)

Appends $data to the input buffer.

=item output_space($len)

Checks if there is enough output buffer space for $len bytes of data.


=item output_ptr()

Returns the contents of the output buffer.

=item output_consume($len)

Removes $len bytes from the output buffer.

=item can_write()

Returns the number of bytes in the output buffer which must be sent over the
network.

=back

=head2 EXPORT

Exports all the SSH2 message types as constants:
SH2_MSG_IGNORE, SSH2_MSG_USERAUTH_REQUEST, SSH2_MSG_CHANNEL_OPEN, ...

=head1 AUTHOR

Matthias Pitzl, E<lt>pitzl@genua.deE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by Matthias Pitzl

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.12.2 or,
at your option, any later version of Perl 5 you may have available.

=cut
