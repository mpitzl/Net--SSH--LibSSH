#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <sys/types.h>

/* Include stuff of OpenSSH */
#include <buffer.h>
#include <cipher.h>
#include <key.h>
#include <kex.h>
#include <ssh_api.h>
#include <myproposal.h>

/* Include err.h from libopenssh sources */
#include <err.h>

/* For debugging purposes */
#include <log.h>

/* Map struct session_state to perl package */
typedef struct ssh Net__SSH__LibSSH;

/* List of kex proposal parameter names. Used as hash keys. */
static char *kex_param_keys[PROPOSAL_MAX] = {
    "PROPOSAL_KEX_ALGS",
    "PROPOSAL_SERVER_HOST_KEY_ALGS",
    "PROPOSAL_ENC_ALGS_CTOS",
    "PROPOSAL_ENC_ALGS_STOC",
    "PROPOSAL_MAC_ALGS_CTOS",
    "PROPOSAL_MAC_ALGS_STOC",
    "PROPOSAL_COMP_ALGS_CTOS",
    "PROPOSAL_COMP_ALGS_STOC",
    "PROPOSAL_LANG_CTOS",
    "PROPOSAL_LANG_STOC"
};

/* Place to store a callback function for the host key verification */
static SV *verify_host_key_cb = NULL;

/*
 * Convert the given sshkey struct into PEM format. Code derived from
 * sshkey_write() in key.c.
 */
static SV*
_convert_sshkey_to_pem(struct sshkey *key) {
    struct sshbuf *b = NULL, *bb = NULL;
    char *uu = NULL;
    SV *key_pem = sv_2mortal(newSVpvn("", 0));

    if ((b = sshbuf_new()) == NULL)
	goto out;

    if ((bb = sshbuf_new()) == NULL)
	goto out;

    if (sshkey_to_blob_buf(key, bb) != 0)
	goto out;

    if ((uu = sshbuf_dtob64(bb)) == NULL)
	goto out;

    if (sshbuf_putf(b, "%s ", sshkey_ssh_name(key)) != 0)
	goto out;

    if (sshbuf_put(b, uu, strlen(uu)) != 0)
	goto out;

    sv_setpvn(key_pem, sshbuf_ptr(b), sshbuf_len(b));

out:
    if (b != NULL)
	sshbuf_free(b);

    if (bb != NULL)
	sshbuf_free(bb);

    if (uu != NULL)
	free(uu);

    return key_pem;
}

/*
 * This function is the callback to be registered in libopenssh to perform the
 * host key verification. It then calls the perl callback sub.
 * It gets called with a key and the ssh context.
 * The key is passed as struct sshkey which must be converted into PEM format
 * before it gets passed to the perl callback sub.
 */
static int
_exec_callback(struct sshkey *key, struct ssh *ssh) {
    dSP;
    int ret = 0, count = 0;
    SV *sshkey_converted;

    PUSHMARK(SP);

    /* Convert the given key into PEM format */
    sshkey_converted = _convert_sshkey_to_pem(key);

    if (SvLEN(sshkey_converted) == 0)
	croak("Error converting SSH key into PEM format!");

    /* Push the converted key onto perl's stack */
    XPUSHs(sshkey_converted);
    PUTBACK;

    count = call_sv(verify_host_key_cb, G_SCALAR);

    SPAGAIN;

    if (count != 1)
	croak("Host key verification callback must return a scalar!");

    PUTBACK; /* XXX Really needed? */

    ret = POPi;
    return (ret > 0 ? 0 : -1);
}

MODULE = Net::SSH::LibSSH		PACKAGE = Net::SSH::LibSSH

PROTOTYPES: DISABLE

Net::SSH::LibSSH*
init(is_server, debug, ...)
    int is_server;
    int debug;

    PREINIT:
	struct kex_params kex_params;
	HV *kex_param_hash;
	SV **kex_param_val;
	STRLEN len;
	char *value_string;
	int i, ret = 0, log_stderr = 1;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_VERBOSE;
	extern char *__progname;
	struct ssh *session;

    CODE:
	if (items > 3)
	    croak("Too many arguments!");

	/* Initialize with default values */
	Copy(myproposal, kex_params.proposal, PROPOSAL_MAX, char*);

	/* Second function argument is optional */
	if (items == 3) {

	    /* Check if we really got a HASH reference */
	    if (!SvROK(ST(2)) || !SvTYPE(ST(2)) == SVt_PVHV)
		croak("Second argument must be a HASH reference!");

	    kex_param_hash = (HV*) SvRV(ST(2));

	    /* Overwrite defaults with user provided values */
	    for (i = 0; i < PROPOSAL_MAX; i++) {
		kex_param_val = hv_fetch(kex_param_hash, kex_param_keys[i], 0,
		    FALSE);

		if (kex_param_val == NULL)
		    continue;

		/* This allows empty strings too! */
		value_string = SvPV(*kex_param_val, len);
		kex_params.proposal[i] = value_string;
	    }

	}

	if (debug) {
	    switch(debug) {
	    case 1:
		log_level = SYSLOG_LEVEL_VERBOSE;
		break;
	    case 2:
		log_level = SYSLOG_LEVEL_DEBUG1;
		break;
	    case 3:
		log_level = SYSLOG_LEVEL_DEBUG2;
		break;
	    default:
		log_level = SYSLOG_LEVEL_DEBUG3;
		break;
	    }

	    log_init(__progname, log_level, log_facility, log_stderr);
	}

	if ((ret = ssh_init(&session, is_server, &kex_params)) < 0) {
	    warn("Error initializing libssh session: %d!", ret);
	    XSRETURN_UNDEF;
	}

	RETVAL = session;

    OUTPUT:
	RETVAL

void
free(ssh)
    Net::SSH::LibSSH *ssh;

    CODE:
	ssh_free(ssh);

int
add_hostkey(ssh, key)
    Net::SSH::LibSSH *ssh;
    char *key;

    INIT:
	int ret;

    CODE:
	RETVAL = ssh_add_hostkey(ssh, key);

    OUTPUT:
	RETVAL

int
packet_next(ssh)
    Net::SSH::LibSSH *ssh;

    PREINIT:
	u_char type;
	int ret = 0;

    CODE:
	if((ret = ssh_packet_next(ssh, &type)) < 0)
	    RETVAL = ret;
	else
	    RETVAL = type;

    OUTPUT:
	RETVAL

SV*
packet_payload(ssh)
    Net::SSH::LibSSH *ssh;

    INIT:
	void *data;
	u_int len;

    CODE:
	data = ssh_packet_payload(ssh, &len);

	if (data == NULL)
	    XSRETURN_UNDEF;

	ST(0) = sv_2mortal(newSVpv("", 0));
	sv_setpvn(ST(0), (char *)data, len);

int
packet_put(ssh, type, data)
    Net::SSH::LibSSH *ssh;
    int type;
    SV *data;

    INIT:
	STRLEN len;
	char *payload;

    CODE:
	payload = SvPV(data, len);
	RETVAL = ssh_packet_put(ssh, type, payload, len);

    OUTPUT:
	RETVAL

int
input_space(ssh, len)
    Net::SSH::LibSSH *ssh;
    u_int len;

    CODE:
	RETVAL = ssh_input_space(ssh, len);

    OUTPUT:
	RETVAL

int
input_append(ssh, data)
    Net::SSH::LibSSH *ssh;
    SV* data;

    INIT:
	STRLEN len;
	char *append_data;

    CODE:
	append_data = SvPV(data, len);
	RETVAL = ssh_input_append(ssh, append_data, len);

    OUTPUT:
	RETVAL

int
output_space(ssh, len)
    Net::SSH::LibSSH *ssh;
    u_int len;

    CODE:
	RETVAL = ssh_output_space(ssh, len);

   OUTPUT:
	RETVAL

SV*
output_ptr(ssh)
    Net::SSH::LibSSH *ssh;

    INIT:
	void *data;
	u_int len;

    CODE:
	data = ssh_output_ptr(ssh, &len);
	if (data == NULL)
	    XSRETURN_UNDEF;

	ST(0) = sv_2mortal(newSVpv("", 0));
	sv_setpvn(ST(0), (char *)data, len);

int
output_consume(ssh, len)
    Net::SSH::LibSSH *ssh;
    u_int len;

    CODE:
	RETVAL = ssh_output_consume(ssh, len);

    OUTPUT:
	RETVAL

SV*
_error_string(n)
    int n;

    INIT:
	const char *errstr;

    CODE:
	errstr = ssh_err(n);
	ST(0) = sv_2mortal(newSVpv(errstr, 0));

void
set_verify_host_key_callback(ssh, cb)
    Net::SSH::LibSSH *ssh;
    SV *cb;

    CODE:
	if (verify_host_key_cb == NULL)
	    verify_host_key_cb = newSVsv(cb);
	else
	    SvSetSV(verify_host_key_cb, cb);

	ssh_set_verify_host_key_callback(ssh, _exec_callback);
