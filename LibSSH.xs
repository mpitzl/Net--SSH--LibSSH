#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include <sys/types.h>

/* Include stuff of OpenSSH */
#include <authfile.h>
#include <sshbuf.h>
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
 * Parse a given key string in PEM format and store it into the passed struct
 * sshkey. Returns 0 on success, otherwise an error code.
 */
int
_convert_pem_to_sshkey(struct ssh *ssh, char *key, struct sshkey **sshkey) {
    struct sshbuf *key_buf = NULL;
    int ret = SSH_ERR_SUCCESS;

    if (ssh->kex->server) {
	/* Parse private key */
	if ((key_buf = sshbuf_new()) == NULL)
	    return SSH_ERR_ALLOC_FAIL;

	if ((ret = sshbuf_put(key_buf, key, strlen(key))) != 0)
	    goto out;

	if ((ret = sshkey_parse_private(key_buf, "hostkey", "", sshkey, NULL)) != 0) {
	    goto out;
	}
    } else {
	/* Parse public key */
	if ((*sshkey = sshkey_new(KEY_UNSPEC)) == NULL)
	    return SSH_ERR_ALLOC_FAIL;

	if ((ret = sshkey_read(*sshkey, &key)) != 0)
	    goto out;
    }

out:
    if (key_buf)
	sshbuf_free(key_buf);

    return ret;
}

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


    /* Convert the given key into PEM format */
    sshkey_converted = _convert_sshkey_to_pem(key);

    if (SvLEN(sshkey_converted) == 0)
	croak("Error converting SSH key into PEM format!");

    /* Push the converted key and optional application data onto perl's stack */
    PUSHMARK(SP);
    XPUSHs(sshkey_converted);
    if (ssh->app_data != NULL)
	XPUSHs(ssh->app_data);
    else
	XPUSHs(&PL_sv_undef);
    PUTBACK;

    count = call_sv(verify_host_key_cb, G_SCALAR);

    SPAGAIN;

    if (count != 1)
	croak("Host key verification callback must return a scalar!");

    ret = POPi;

    /*
     * Perl should return 1 on success, 0 on error but libopenssh expects 0 on
     * success and -1 on error
     */
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
	int i, ret = SSH_ERR_SUCCESS, log_stderr = 1;
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

    PPCODE:
	ssh_free(ssh);

int
add_hostkey(ssh, key)
    Net::SSH::LibSSH *ssh;
    char *key;

    INIT:
	int ret = SSH_ERR_SUCCESS;
	struct sshkey *sshkey = NULL;

    CODE:
	/*
	 * Key is a string and needs to be parsed into an sshkey struct before
	 * passing it to ssh_add_hostkey()
	 */
	ret = _convert_pem_to_sshkey(ssh, key, &sshkey);

	if (ret < 0) {
	    if (sshkey)
		sshkey_free(sshkey);
	} else {
	    ret = ssh_add_hostkey(ssh, sshkey);
	}

	RETVAL = ret;

    OUTPUT:
	RETVAL

int
packet_next(ssh)
    Net::SSH::LibSSH *ssh;

    INIT:
	u_char type;
	int ret;

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
	const u_char *data;
	size_t len;

    CODE:
	data = ssh_packet_payload(ssh, &len);

	if (data == NULL)
	    XSRETURN_UNDEF;

	RETVAL = newSVpv("", 0);
	sv_setpvn(RETVAL, (char *)data, len);

    OUTPUT:
	RETVAL

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
	const u_char *data;
	size_t len;

    CODE:
	data = ssh_output_ptr(ssh, &len);
	if (data == NULL)
	    XSRETURN_UNDEF;

	RETVAL = newSVpv("", 0);
	sv_setpvn(RETVAL, (char *)data, len);

    OUTPUT:
	RETVAL

int
output_consume(ssh, len)
    Net::SSH::LibSSH *ssh;
    u_int len;

    CODE:
	RETVAL = ssh_output_consume(ssh, len);

    OUTPUT:
	RETVAL

void
set_verify_host_key_callback(ssh, cb)
    Net::SSH::LibSSH *ssh;
    SV *cb;

    PPCODE:
	/* cb must be a CODE ref */
	if (!SvROK(cb) || SvTYPE(SvRV(cb)) != SVt_PVCV)
	    croak("Callback must be a CODE ref!");

	if (verify_host_key_cb == NULL)
	    verify_host_key_cb = newSVsv(cb);
	else
	    SvSetSV(verify_host_key_cb, cb);

	ssh_set_verify_host_key_callback(ssh, _exec_callback);

void
set_application_data(ssh, app_data)
    Net::SSH::LibSSH *ssh;
    SV *app_data;

    PPCODE:
	SvREFCNT_inc(app_data); // XXX: Ansonsten ist u.U. der Wert spaeter undef
	ssh->app_data = app_data;

SV*
get_application_data(ssh)
    Net::SSH::LibSSH *ssh;

    CODE:
	if(ssh->app_data != NULL)
	    RETVAL = ssh->app_data;
	else
	    RETVAL = &PL_sv_undef;

    OUTPUT:
	RETVAL


SV*
_error_string(n)
    int n;

    CODE:
	RETVAL = newSVpv(ssh_err(n), 0);

    OUTPUT:
	RETVAL

SV*
_fingerprint(key)
    SV *key;

    INIT:
	struct sshkey *parsed_key;
	struct sshbuf *buffer;
	char *key_str;
	char *fp;
	int ret;
	STRLEN len;

    CODE:
	key_str = SvPV(key, len);

	if (len == 0)
	    XSRETURN_UNDEF;

	if ((parsed_key = sshkey_new(KEY_UNSPEC)) == NULL) {
	    warn("Error allocating sshkey!");
	    XSRETURN_UNDEF;
	}

	/* First try to parse a public key as in ~/.ssh/authorized_keys */
	if ((ret = sshkey_read(parsed_key, &key_str)) != 0) {
	    /* No success, now try PEM format */
	    if ((buffer = sshbuf_new()) == NULL) {
		warn("Error allocating sshbuf!");
		sshkey_free(parsed_key);
		XSRETURN_UNDEF;
	    }

	    if ((ret = sshbuf_put(buffer, key_str, len)) != 0) {
		warn("Error putting key into buffer: %s", ssh_err(ret));
		sshkey_free(parsed_key);
		sshbuf_free(buffer);
		XSRETURN_UNDEF;
	    }

	    if ((ret = sshkey_parse_private(buffer, "", "internal", &parsed_key,
		NULL)) != 0) {
		warn("Error parsing key: %s", ssh_err(ret));
		sshkey_free(parsed_key);
		sshbuf_free(buffer);
		XSRETURN_UNDEF;
	    }
	    sshbuf_free(buffer);
	}

	fp = sshkey_fingerprint(parsed_key, SSH_FP_MD5, SSH_FP_HEX);

	if (fp == NULL)
	    RETVAL = &PL_sv_undef;
	else
	    RETVAL = newSVpv(fp, 0);

	sshkey_free(parsed_key);

    OUTPUT:
	RETVAL
