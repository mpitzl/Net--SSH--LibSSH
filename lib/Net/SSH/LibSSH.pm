package Net::SSH::LibSSH;

use 5.012002;
use strict;
use warnings;
use Carp;
use Scalar::Util qw(looks_like_number);

require Exporter;

our @ISA = qw(Exporter);

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
my %SSH_MSG = reverse (
    SSH2_MSG_DISCONNECT                    => 1,
    SSH2_MSG_IGNORE                        => 2,
    SSH2_MSG_UNIMPLEMENTED                 => 3,
    SSH2_MSG_DEBUG                         => 4,
    SSH2_MSG_SERVICE_REQUEST               => 5,
    SSH2_MSG_SERVICE_ACCEPT                => 6,
    SSH2_MSG_KEXINIT                       => 20,
    SSH2_MSG_NEWKEYS                       => 21,
# Reverse lookup will always give lowest common denominator
    SSH2_MSG_KEXDH_INIT                    => 30,
    SSH2_MSG_KEXDH_REPLY                   => 31,
#    SSH2_MSG_KEX_DH_GEX_REQUEST_OLD        => 30,
#    SSH2_MSG_KEX_DH_GEX_GROUP              => 31,
    SSH2_MSG_KEX_DH_GEX_INIT               => 32,
    SSH2_MSG_KEX_DH_GEX_REPLY              => 33,
    SSH2_MSG_KEX_DH_GEX_REQUEST            => 34,
#    SSH2_MSG_KEX_ECDH_INIT                 => 30,
#    SSH2_MSG_KEX_ECDH_REPLY                => 31,
    SSH2_MSG_USERAUTH_REQUEST              => 50,
    SSH2_MSG_USERAUTH_FAILURE              => 51,
    SSH2_MSG_USERAUTH_SUCCESS              => 52,
    SSH2_MSG_USERAUTH_BANNER               => 53,
#    SSH2_MSG_USERAUTH_PK_OK                => 60,
#    SSH2_MSG_USERAUTH_PASSWD_CHANGEREQ     => 60,
    SSH2_MSG_USERAUTH_INFO_REQUEST         => 60,
    SSH2_MSG_USERAUTH_INFO_RESPONSE        => 61,
#    SSH2_MSG_USERAUTH_JPAKE_CLIENT_STEP1   => 60,
#    SSH2_MSG_USERAUTH_JPAKE_SERVER_STEP1   => 61,
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
#    SSH2_MSG_KEX_ROAMING_RESUME            => 30,
#    SSH2_MSG_KEX_ROAMING_AUTH_REQUIRED     => 31,
#    SSH2_MSG_KEX_ROAMING_AUTH              => 32,
#    SSH2_MSG_KEX_ROAMING_AUTH_OK           => 33,
#    SSH2_MSG_KEX_ROAMING_AUTH_FAIL         => 34,
);

# Constants for error codes returned by various functions
use constant {
    SSH_ERR_SUCCESS                   => 0,
    SSH_ERR_INTERNAL_ERROR            => -1,
    SSH_ERR_ALLOC_FAIL                => -2,
    SSH_ERR_MESSAGE_INCOMPLETE        => -3,
    SSH_ERR_INVALID_FORMAT            => -4,
    SSH_ERR_BIGNUM_IS_NEGATIVE        => -5,
    SSH_ERR_BIGNUM_TOO_LARGE          => -6,
    SSH_ERR_ECPOINT_TOO_LARGE         => -7,
    SSH_ERR_NO_BUFFER_SPACE           => -8,
    SSH_ERR_INVALID_ARGUMENT          => -9,
    SSH_ERR_KEY_BITS_MISMATCH         => -10,
    SSH_ERR_EC_CURVE_INVALID          => -11,
    SSH_ERR_KEY_TYPE_MISMATCH         => -12,
    SSH_ERR_KEY_TYPE_UNKNOWN          => -13,
    SSH_ERR_EC_CURVE_MISMATCH         => -14,
    SSH_ERR_EXPECTED_CERT             => -15,
    SSH_ERR_KEY_LACKS_CERTBLOB        => -16,
    SSH_ERR_KEY_CERT_UNKNOWN_TYPE     => -17,
    SSH_ERR_KEY_CERT_INVALID_SIGN_KEY => -18,
    SSH_ERR_KEY_INVALID_EC_VALUE      => -19,
    SSH_ERR_SIGNATURE_INVALID         => -20,
    SSH_ERR_LIBCRYPTO_ERROR           => -21,
    SSH_ERR_UNEXPECTED_TRAILING_DATA  => -22,
    SSH_ERR_SYSTEM_ERROR              => -23,
    SSH_ERR_KEY_CERT_INVALID          => -24,
    SSH_ERR_AGENT_COMMUNICATION       => -25,
    SSH_ERR_AGENT_FAILURE             => -26,
    SSH_ERR_DH_GEX_OUT_OF_RANGE       => -27,
    SSH_ERR_DISCONNECTED              => -28,
    SSH_ERR_MAC_INVALID               => -29,
    SSH_ERR_NO_CIPHER_ALG_MATCH       => -30,
    SSH_ERR_NO_MAC_ALG_MATCH          => -31,
    SSH_ERR_NO_COMPRESS_ALG_MATCH     => -32,
    SSH_ERR_NO_KEX_ALG_MATCH          => -33,
    SSH_ERR_NO_HOSTKEY_ALG_MATCH      => -34,
    SSH_ERR_NO_HOSTKEY_LOADED         => -35,
    SSH_ERR_PROTOCOL_MISMATCH         => -36,
    SSH_ERR_NO_PROTOCOL_VERSION       => -37,
    SSH_ERR_NEED_REKEY                => -38,
    SSH_ERR_PASSPHRASE_TOO_SHORT      => -39,
    SSH_ERR_FILE_CHANGED              => -40,
    SSH_ERR_KEY_UNKNOWN_CIPHER        => -41,
    SSH_ERR_KEY_WRONG_PASSPHRASE      => -42,
    SSH_ERR_KEY_BAD_PERMISSIONS       => -43,
    SSH_ERR_KEY_CERT_MISMATCH         => -44,
    SSH_ERR_KEY_NOT_FOUND             => -45,
};
my %SSH_ERR = reverse (
    SSH_ERR_SUCCESS                   => 0,
    SSH_ERR_INTERNAL_ERROR            => -1,
    SSH_ERR_ALLOC_FAIL                => -2,
    SSH_ERR_MESSAGE_INCOMPLETE        => -3,
    SSH_ERR_INVALID_FORMAT            => -4,
    SSH_ERR_BIGNUM_IS_NEGATIVE        => -5,
    SSH_ERR_BIGNUM_TOO_LARGE          => -6,
    SSH_ERR_ECPOINT_TOO_LARGE         => -7,
    SSH_ERR_NO_BUFFER_SPACE           => -8,
    SSH_ERR_INVALID_ARGUMENT          => -9,
    SSH_ERR_KEY_BITS_MISMATCH         => -10,
    SSH_ERR_EC_CURVE_INVALID          => -11,
    SSH_ERR_KEY_TYPE_MISMATCH         => -12,
    SSH_ERR_KEY_TYPE_UNKNOWN          => -13,
    SSH_ERR_EC_CURVE_MISMATCH         => -14,
    SSH_ERR_EXPECTED_CERT             => -15,
    SSH_ERR_KEY_LACKS_CERTBLOB        => -16,
    SSH_ERR_KEY_CERT_UNKNOWN_TYPE     => -17,
    SSH_ERR_KEY_CERT_INVALID_SIGN_KEY => -18,
    SSH_ERR_KEY_INVALID_EC_VALUE      => -19,
    SSH_ERR_SIGNATURE_INVALID         => -20,
    SSH_ERR_LIBCRYPTO_ERROR           => -21,
    SSH_ERR_UNEXPECTED_TRAILING_DATA  => -22,
    SSH_ERR_SYSTEM_ERROR              => -23,
    SSH_ERR_KEY_CERT_INVALID          => -24,
    SSH_ERR_AGENT_COMMUNICATION       => -25,
    SSH_ERR_AGENT_FAILURE             => -26,
    SSH_ERR_DH_GEX_OUT_OF_RANGE       => -27,
    SSH_ERR_DISCONNECTED              => -28,
    SSH_ERR_MAC_INVALID               => -29,
    SSH_ERR_NO_CIPHER_ALG_MATCH       => -30,
    SSH_ERR_NO_MAC_ALG_MATCH          => -31,
    SSH_ERR_NO_COMPRESS_ALG_MATCH     => -32,
    SSH_ERR_NO_KEX_ALG_MATCH          => -33,
    SSH_ERR_NO_HOSTKEY_ALG_MATCH      => -34,
    SSH_ERR_NO_HOSTKEY_LOADED         => -35,
    SSH_ERR_PROTOCOL_MISMATCH         => -36,
    SSH_ERR_NO_PROTOCOL_VERSION       => -37,
    SSH_ERR_NEED_REKEY                => -38,
    SSH_ERR_PASSPHRASE_TOO_SHORT      => -39,
    SSH_ERR_FILE_CHANGED              => -40,
    SSH_ERR_KEY_UNKNOWN_CIPHER        => -41,
    SSH_ERR_KEY_WRONG_PASSPHRASE      => -42,
    SSH_ERR_KEY_BAD_PERMISSIONS       => -43,
    SSH_ERR_KEY_CERT_MISMATCH         => -44,
    SSH_ERR_KEY_NOT_FOUND             => -45,
);

# Constants for various reason codes
use constant {
    # Disconnect reason codes
    SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT    => 1,
    SSH2_DISCONNECT_PROTOCOL_ERROR                 => 2,
    SSH2_DISCONNECT_KEY_EXCHANGE_FAILED            => 3,
    SSH2_DISCONNECT_HOST_AUTHENTICATION_FAILED     => 4,
    SSH2_DISCONNECT_MAC_ERROR                      => 5,
    SSH2_DISCONNECT_COMPRESSION_ERROR              => 6,
    SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE          => 7,
    SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED => 8,
    SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE        => 9,
    SSH2_DISCONNECT_CONNECTION_LOST                => 10,
    SSH2_DISCONNECT_BY_APPLICATION                 => 11,
    SSH2_DISCONNECT_TOO_MANY_CONNECTIONS           => 12,
    SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER         => 13,
    SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE => 14,
    SSH2_DISCONNECT_ILLEGAL_USER_NAME              => 15,

    # Channel open failure reason codes
    SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED          => 1,
    SSH2_OPEN_CONNECT_FAILED                       => 2,
    SSH2_OPEN_UNKNOWN_CHANNEL_TYPE                 => 3,
    SSH2_OPEN_RESOURCE_SHORTAGE                    => 4,
};
my %SSH_DISCONNECT = reverse(
    # Disconnect reason codes
    SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT    => 1,
    SSH2_DISCONNECT_PROTOCOL_ERROR                 => 2,
    SSH2_DISCONNECT_KEY_EXCHANGE_FAILED            => 3,
    SSH2_DISCONNECT_HOST_AUTHENTICATION_FAILED     => 4,
    SSH2_DISCONNECT_MAC_ERROR                      => 5,
    SSH2_DISCONNECT_COMPRESSION_ERROR              => 6,
    SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE          => 7,
    SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED => 8,
    SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE        => 9,
    SSH2_DISCONNECT_CONNECTION_LOST                => 10,
    SSH2_DISCONNECT_BY_APPLICATION                 => 11,
    SSH2_DISCONNECT_TOO_MANY_CONNECTIONS           => 12,
    SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER         => 13,
    SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE => 14,
    SSH2_DISCONNECT_ILLEGAL_USER_NAME              => 15,
);
my %SSH_CHAN_OPEN = reverse (
    # Channel open failure reason codes
    SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED          => 1,
    SSH2_OPEN_CONNECT_FAILED                       => 2,
    SSH2_OPEN_UNKNOWN_CHANNEL_TYPE                 => 3,
    SSH2_OPEN_RESOURCE_SHORTAGE                    => 4,
);

# Constants for the SFTP packet types, taken from sftp.h
use constant {
    SSH2_FXP_INIT                 => 1,
    SSH2_FXP_VERSION              => 2,
    SSH2_FXP_OPEN                 => 3,
    SSH2_FXP_CLOSE                => 4,
    SSH2_FXP_READ                 => 5,
    SSH2_FXP_WRITE                => 6,
    SSH2_FXP_LSTAT                => 7,
    SSH2_FXP_FSTAT                => 8,
    SSH2_FXP_SETSTAT              => 9,
    SSH2_FXP_FSETSTAT             => 10,
    SSH2_FXP_OPENDIR              => 11,
    SSH2_FXP_READDIR              => 12,
    SSH2_FXP_REMOVE               => 13,
    SSH2_FXP_MKDIR                => 14,
    SSH2_FXP_RMDIR                => 15,
    SSH2_FXP_REALPATH             => 16,
    SSH2_FXP_STAT                 => 17,
    SSH2_FXP_RENAME               => 18,
    SSH2_FXP_READLINK             => 19,
    SSH2_FXP_SYMLINK              => 20,
    SSH2_FXP_LINK                 => 21,
    SSH2_FXP_STATUS               => 101,
    SSH2_FXP_HANDLE               => 102,
    SSH2_FXP_DATA                 => 103,
    SSH2_FXP_NAME                 => 104,
    SSH2_FXP_ATTRS                => 105,
    SSH2_FXP_EXTENDED             => 200,
    SSH2_FXP_EXTENDED_REPLY       => 201,
};

my %SFTP_MSG = reverse (
    SSH2_FXP_INIT                 => 1,
    SSH2_FXP_VERSION              => 2,
    SSH2_FXP_OPEN                 => 3,
    SSH2_FXP_CLOSE                => 4,
    SSH2_FXP_READ                 => 5,
    SSH2_FXP_WRITE                => 6,
    SSH2_FXP_LSTAT                => 7,
    SSH2_FXP_FSTAT                => 8,
    SSH2_FXP_SETSTAT              => 9,
    SSH2_FXP_FSETSTAT             => 10,
    SSH2_FXP_OPENDIR              => 11,
    SSH2_FXP_READDIR              => 12,
    SSH2_FXP_REMOVE               => 13,
    SSH2_FXP_MKDIR                => 14,
    SSH2_FXP_RMDIR                => 15,
    SSH2_FXP_REALPATH             => 16,
    SSH2_FXP_STAT                 => 17,
    SSH2_FXP_RENAME               => 18,
    SSH2_FXP_READLINK             => 19,
    SSH2_FXP_SYMLINK              => 20,
    SSH2_FXP_LINK                 => 21,
    SSH2_FXP_STATUS               => 101,
    SSH2_FXP_HANDLE               => 102,
    SSH2_FXP_DATA                 => 103,
    SSH2_FXP_NAME                 => 104,
    SSH2_FXP_ATTRS                => 105,
    SSH2_FXP_EXTENDED             => 200,
    SSH2_FXP_EXTENDED_REPLY       => 201,
);

use constant {
    SSH2_FX_OK                  => 0,
    SSH2_FX_EOF                 => 1,
    SSH2_FX_NO_SUCH_FILE        => 2,
    SSH2_FX_PERMISSION_DENIED   => 3,
    SSH2_FX_FAILURE             => 4,
    SSH2_FX_BAD_MESSAGE         => 5,
    SSH2_FX_NO_CONNECTION       => 6,
    SSH2_FX_CONNECTION_LOST     => 7,
    SSH2_FX_OP_UNSUPPORTED      => 8,
};

my %SFTP_STATUS = reverse (
    SSH2_FX_OK                  => 0,
    SSH2_FX_EOF                 => 1,
    SSH2_FX_NO_SUCH_FILE        => 2,
    SSH2_FX_PERMISSION_DENIED   => 3,
    SSH2_FX_FAILURE             => 4,
    SSH2_FX_BAD_MESSAGE         => 5,
    SSH2_FX_NO_CONNECTION       => 6,
    SSH2_FX_CONNECTION_LOST     => 7,
    SSH2_FX_OP_UNSUPPORTED      => 8,
);

use constant {
    SSH2_FXF_READ         => 0x00000001,
    SSH2_FXF_WRITE        => 0x00000002,
    SSH2_FXF_APPEND       => 0x00000004,
    SSH2_FXF_CREAT        => 0x00000008,
    SSH2_FXF_TRUNC        => 0x00000010,
    SSH2_FXF_EXCL         => 0x00000020,
};

my %SFTP_OPENMODE = reverse (
    SSH2_FXF_READ         => 0x00000001,
    SSH2_FXF_WRITE        => 0x00000002,
    SSH2_FXF_APPEND       => 0x00000004,
    SSH2_FXF_CREAT        => 0x00000008,
    SSH2_FXF_TRUNC        => 0x00000010,
    SSH2_FXF_EXCL         => 0x00000020,
);

use constant {
    SSH2_FILEXFER_ATTR_SIZE        => 0x00000001,
    SSH2_FILEXFER_ATTR_UIDGID      => 0x00000002,
    SSH2_FILEXFER_ATTR_PERMISSIONS => 0x00000004,
    SSH2_FILEXFER_ATTR_ACMODTIME   => 0x00000008,
    SSH2_FILEXFER_ATTR_EXTENDED    => 0x80000000,
};

my %SFTP_ATTR = reverse (
    SSH2_FILEXFER_ATTR_SIZE        => 0x00000001,
    SSH2_FILEXFER_ATTR_UIDGID      => 0x00000002,
    SSH2_FILEXFER_ATTR_PERMISSIONS => 0x00000004,
    SSH2_FILEXFER_ATTR_ACMODTIME   => 0x00000008,
    SSH2_FILEXFER_ATTR_EXTENDED    => 0x80000000,
);

my @SSH_FUNC = qw (
    error_string
    type_to_string
    disconnect_to_string
    chan_open_to_string
    sftp_msg_to_string
    sftp_status_to_string
    sftp_openmode_to_string
    sftp_attr_to_string
    fingerprint
);
our @EXPORT_OK = (
    values %SSH_MSG,
    values %SSH_ERR,
    values %SSH_DISCONNECT,
    values %SSH_CHAN_OPEN,
    values %SFTP_MSG,
    values %SFTP_STATUS,
    values %SFTP_OPENMODE,
    values %SFTP_ATTR,
    @SSH_FUNC,
);

our %EXPORT_TAGS = (
    all => [
	values %SSH_MSG,
	values %SSH_ERR,
	values %SSH_DISCONNECT,
	values %SSH_CHAN_OPEN,
	values %SFTP_MSG,
	values %SFTP_STATUS,
	values %SFTP_OPENMODE,
	values %SFTP_ATTR,
	@SSH_FUNC
    ],
    functions => [@SSH_FUNC],
    errno => [values %SSH_ERR],
    msgno => [values %SSH_MSG, values %SFTP_MSG],
    const => [
	values %SSH_DISCONNECT,
	values %SSH_CHAN_OPEN,
	values %SFTP_STATUS,
	values %SFTP_OPENMODE,
	values %SFTP_ATTR,
    ],
);

Exporter::export_ok_tags("all", "functions", "errno", "msgno", "const");

our $VERSION = '0.02';

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

sub type_to_string {
    return to_string("type_to_string", \%SSH_MSG, @_);
}

sub disconnect_to_string {
    return to_string("disconnect_to_string", \%SSH_DISCONNECT, @_);
}

sub chan_open_to_string {
    return to_string("chan_open_to_string", \%SSH_CHAN_OPEN, @_);
}

sub sftp_msg_to_string {
    return to_string("sftp_msg_to_string", \%SFTP_MSG, @_);
}

sub sftp_openmode_to_string {
    return to_string("sftp_openmode_to_string", \%SFTP_OPENMODE, @_);
}

sub sftp_status_to_string {
    return to_string("sftp_status_to_string", \%SFTP_STATUS, @_);
}

sub sftp_attr_to_string {
    return to_string("sftp_attr_to_string", \%SFTP_ATTR, @_);
}

sub error_string {
    return to_string("error_string", \&Net::SSH::LibSSH::_error_string, @_);
}

sub to_string {
    my $subname = shift;
    my $reference = shift;

    if (@_ == 1) {
	if (looks_like_number($_[0])) {
	    if (ref($reference) eq "CODE") {
		return $reference->($_[0]);
	    } else {
		return $reference->{$_[0]};
	    }
	} else {
	    confess("First argument must be a number!");
	}
    } elsif (@_ == 2) {
	# First arg is assumed to be $self
	if (looks_like_number($_[1])) {
	    if (ref($reference) eq "CODE") {
		return $reference->($_[1]);
	    } else {
		return $reference->{$_[1]};
	    }
	} else {
	    confess("First argument must be a number!");
	}
    }
    confess("Usage: \$obj->$subname(\$n) or $subname(\$n)!");
}

sub fingerprint {
    if (@_ == 1) {
	return unless ($_[0]);
	return Net::SSH::LibSSH::_fingerprint($_[0]);
    } elsif (@_ == 2) {
	# First arg is assumed to be $self
	return unless ($_[1]);
	return Net::SSH::LibSSH::_fingerprint($_[1]);
    }
    confess("Usage: \$obj->fingerprint(\$n) or fingerprint(\$n)!");
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

Version 0.02

=head1 SYNOPSIS

  use Net::SSH::LibSSH qw(:all);
  my $ssh = Net::SSH::LibSSH->new(
    server => 1,
    debug  => 0,
  ) or die "Error creating new Net::SSH::LibSSH object!";

  # Add a host key. Server needs a private, client a public key
  my $ret = $ssh->add_hostkey($key_data);
  if ($ret != SSH_ERR_SUCCESS)
      die "Error adding host key: " . error_string($ret) . "\n";

  # Data read on fd must be added to the internal input buffer
  $ret = $ssh->input_append($data);
  if ($ret != SSH_ERR_SUCCESS)
      die "Error appending input data: " . error_string($ret) . "\n";

  # Get a SSH packet, returns 0 if no packet could be read
  # First call initiates banner exchange and key exchange which sets up the
  # encryption on transport layer level
  my $type = $ssh->packet_next();
  if ($type > 0) {
      # Read payload
      my $data = $ssh->packet_payload()
          or die "Error reading packet payload!";
  } elsif ($type < 0)
      die "Error reading next packet: " . error_string($type) . "\n";
  } else {
      # read more data
  }

  # Put packet into output buffer
  $ret = $ssh->packet_put($type, $data);
  if ($ret != SSH_ERR_SUCCESS)
      die "Error adding new packet: " . error_string($ret) . "\n";

  # Write data if any
  if (my $olen = $ssh->can_write())
      # write $olen bytes of data to socket

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

Returns SSH_ERR_SUCCESS on success, otherwise a negative error code is returned.

=item packet_next()

This returns the type of the next packet which could be parsed from the input
buffer. If there was no packet or an incomplete packet, 0 is returned. If there
was an error a negative error code is returned.

=item packet_payload()

Must be called after packet_next to get the payload of the available packet.

Returns the payload or undef on error.

=item packet_put($type, $data)

Adds a packet of type $type with the payload $data to the internal output
buffer. Returns SSH_ERR_SUCCESS on success, otherwise a negative error code.

=item input_space($len)

Checks if there is enough input buffer space for $len bytes of data.

=item input_append($data)

Appends $data to the input buffer. In case of an error a negative value is
returned.

=item output_space($len)

Checks if there is enough output buffer space for $len bytes of data.

=item output_ptr()

Returns the contents of the output buffer.

=item output_consume($len)

Removes $len bytes from the output buffer. Returns SSH_ERR_SUCCESS on success,
otherwise a negative error code is returned.

=item can_write()

Returns the number of bytes in the output buffer which must be sent over the
network.

=item error_string($errno)

Returns a string describing the error code given. Can be either called as method
of the class or imported by C<use Net::SSH::LibSSH qw(error_string);>.


=item *_to_string($id)

These functions return the constant names corresponding to the constant's value.
They can be either called as methods of the class or imported by
C<use Net::SSH::LibSSH qw(:functions);>.
Some type codes are used multiple times by the SSH2 protocol. In these cases,
the most common name will be returned.

=over 4

=item type_to_string($id)

SSH2 message types

=item disconnect_to_string($id)

SSH2 disconnect reason codes

=item chan_open_to_string($id)

SSH2 channel open failure reason codes

=item sftp_msg_to_string($id)

SFTP message types

=item sftp_status_to_string($id)

SFTP status constants

=item sftp_openmode_to_string($id)

SFTP open modes

=item sftp_attr_to_string($id)

SFTP attribute names

=back

=item set_verify_host_key_callback($coderef)

Installs the given $coderef as new custom host key verification handler. Gets
called from libssh. The callback function given gets the host key in PEM format
and must return 1 on positive key verification or 0 otherwise.

=item set_application_data($appdata)

Stores the given data in the Net::SSH::LibSSH object (or more accurate: stores a
pointer to your perl data inside the ssh C-struct).
The stored data is passed as second argument to an own host key verification
callback.

=item get_application_data()

Retrieve the application data stored inside the Net::SSH::LibSSH object. Returns
undef if there has been no data stored previously.

=item fingerprint($key)

Takes a key either in PEM format or in the format used in the authorized_keys
file and returns an MD5 fingerprint in hexadecimal notation.

=back

=head2 EXPORT

Nothing is exported by default.

The following tags are supported:

    :all
    :functions - what you could call without a LibSSH object
    :errno - constants for errors
    :msgno - constants for ssh and sftp messages
    :const - various other constants used in protocol messages

Constant names are taken from the OpenSSH header files ssh2.h and sftp.h,
meaning their names are not identical to the ssh rfcs.

These constants are defined:

SSH2 message types:
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

SSH2 error constants:
    SSH_ERR_SUCCESS
    SSH_ERR_INTERNAL_ERROR
    SSH_ERR_ALLOC_FAIL
    SSH_ERR_MESSAGE_INCOMPLETE
    SSH_ERR_INVALID_FORMAT
    SSH_ERR_BIGNUM_IS_NEGATIVE
    SSH_ERR_BIGNUM_TOO_LARGE
    SSH_ERR_ECPOINT_TOO_LARGE
    SSH_ERR_NO_BUFFER_SPACE
    SSH_ERR_INVALID_ARGUMENT
    SSH_ERR_KEY_BITS_MISMATCH
    SSH_ERR_EC_CURVE_INVALID
    SSH_ERR_KEY_TYPE_MISMATCH
    SSH_ERR_KEY_TYPE_UNKNOWN
    SSH_ERR_EC_CURVE_MISMATCH
    SSH_ERR_EXPECTED_CERT
    SSH_ERR_KEY_LACKS_CERTBLOB
    SSH_ERR_KEY_CERT_UNKNOWN_TYPE
    SSH_ERR_KEY_CERT_INVALID_SIGN_KEY
    SSH_ERR_KEY_INVALID_EC_VALUE
    SSH_ERR_SIGNATURE_INVALID
    SSH_ERR_LIBCRYPTO_ERROR
    SSH_ERR_UNEXPECTED_TRAILING_DATA
    SSH_ERR_SYSTEM_ERROR
    SSH_ERR_KEY_CERT_INVALID
    SSH_ERR_AGENT_COMMUNICATION
    SSH_ERR_AGENT_FAILURE
    SSH_ERR_DH_GEX_OUT_OF_RANGE
    SSH_ERR_DISCONNECTED
    SSH_ERR_MAC_INVALID
    SSH_ERR_NO_CIPHER_ALG_MATCH
    SSH_ERR_NO_MAC_ALG_MATCH
    SSH_ERR_NO_COMPRESS_ALG_MATCH
    SSH_ERR_NO_KEX_ALG_MATCH
    SSH_ERR_NO_HOSTKEY_ALG_MATCH
    SSH_ERR_NO_HOSTKEY_LOADED
    SSH_ERR_PROTOCOL_MISMATCH
    SSH_ERR_NO_PROTOCOL_VERSION
    SSH_ERR_NEED_REKEY
    SSH_ERR_PASSPHRASE_TOO_SHORT
    SSH_ERR_FILE_CHANGED
    SSH_ERR_KEY_UNKNOWN_CIPHER
    SSH_ERR_KEY_WRONG_PASSPHRASE
    SSH_ERR_KEY_BAD_PERMISSIONS
    SSH_ERR_KEY_CERT_MISMATCH
    SSH_ERR_KEY_NOT_FOUND

SSH2 disconnect reason codes:
    SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT
    SSH2_DISCONNECT_PROTOCOL_ERROR
    SSH2_DISCONNECT_KEY_EXCHANGE_FAILED
    SSH2_DISCONNECT_HOST_AUTHENTICATION_FAILED
    SSH2_DISCONNECT_MAC_ERROR
    SSH2_DISCONNECT_COMPRESSION_ERROR
    SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE
    SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED
    SSH2_DISCONNECT_HOST_KEY_NOT_VERIFIABLE
    SSH2_DISCONNECT_CONNECTION_LOST
    SSH2_DISCONNECT_BY_APPLICATION
    SSH2_DISCONNECT_TOO_MANY_CONNECTIONS
    SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER
    SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE
    SSH2_DISCONNECT_ILLEGAL_USER_NAME

SSH2 channel open failure reason codes:
    SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED
    SSH2_OPEN_CONNECT_FAILED
    SSH2_OPEN_UNKNOWN_CHANNEL_TYPE
    SSH2_OPEN_RESOURCE_SHORTAGE

SFTP message types:
    SSH2_FXP_INIT
    SSH2_FXP_VERSION
    SSH2_FXP_OPEN
    SSH2_FXP_CLOSE
    SSH2_FXP_READ
    SSH2_FXP_WRITE
    SSH2_FXP_LSTAT
    SSH2_FXP_FSTAT
    SSH2_FXP_SETSTAT
    SSH2_FXP_FSETSTAT
    SSH2_FXP_OPENDIR
    SSH2_FXP_READDIR
    SSH2_FXP_REMOVE
    SSH2_FXP_MKDIR
    SSH2_FXP_RMDIR
    SSH2_FXP_REALPATH
    SSH2_FXP_STAT
    SSH2_FXP_RENAME
    SSH2_FXP_READLINK
    SSH2_FXP_SYMLINK
    SSH2_FXP_LINK
    SSH2_FXP_STATUS
    SSH2_FXP_HANDLE
    SSH2_FXP_DATA
    SSH2_FXP_NAME
    SSH2_FXP_ATTRS
    SSH2_FXP_EXTENDED
    SSH2_FXP_EXTENDED_REPLY

SFTP status constants:
    SSH2_FX_OK
    SSH2_FX_EOF
    SSH2_FX_NO_SUCH_FILE
    SSH2_FX_PERMISSION_DENIED
    SSH2_FX_FAILURE
    SSH2_FX_BAD_MESSAGE
    SSH2_FX_NO_CONNECTION
    SSH2_FX_CONNECTION_LOST
    SSH2_FX_OP_UNSUPPORTED

SFTP open modes:
    SSH2_FXF_READ
    SSH2_FXF_WRITE
    SSH2_FXF_APPEND
    SSH2_FXF_CREAT
    SSH2_FXF_TRUNC
    SSH2_FXF_EXCL

SFTP attribute names:
    SSH2_FILEXFER_ATTR_SIZE
    SSH2_FILEXFER_ATTR_UIDGID
    SSH2_FILEXFER_ATTR_PERMISSIONS
    SSH2_FILEXFER_ATTR_ACMODTIME
    SSH2_FILEXFER_ATTR_EXTENDED


=head1 AUTHOR

Matthias Pitzl, E<lt>pitzl@genua.deE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by Matthias Pitzl

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.12.2 or,
at your option, any later version of Perl 5 you may have available.

=cut
