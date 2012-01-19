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

MODULE = Net::SSH::LibSSH		PACKAGE = Net::SSH::LibSSH

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
	int i, log_stderr = 1;
	SyslogFacility log_facility = SYSLOG_FACILITY_AUTH;
	LogLevel log_level = SYSLOG_LEVEL_VERBOSE;
	extern char *__progname;

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

	RETVAL = ssh_init(is_server, &kex_params);

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
	ret = ssh_add_hostkey(ssh, key);
	RETVAL = (ret == 0);

    OUTPUT:
	RETVAL

int
packet_next(ssh)
    Net::SSH::LibSSH *ssh;

    CODE:
	RETVAL = ssh_packet_next(ssh);

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
	ST(0) = sv_2mortal(newSVpv("", 0));
	sv_setpvn(ST(0), (char *)data, len);

void
packet_put(ssh, type, data)
    Net::SSH::LibSSH *ssh;
    int type;
    SV *data;

    INIT:
	STRLEN len;
	char *payload;

    CODE:
	payload = SvPV(data, len);
	ssh_packet_put(ssh, type, payload, len);

int
input_space(ssh, len)
    Net::SSH::LibSSH *ssh;
    u_int len;

    CODE:
	RETVAL = ssh_input_space(ssh, len);

    OUTPUT:
	RETVAL

void
input_append(ssh, data)
    Net::SSH::LibSSH *ssh;
    SV* data;

    INIT:
	STRLEN len;
	char *append_data;

    CODE:
	append_data = SvPV(data, len);
	ssh_input_append(ssh, append_data, len);

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
	ST(0) = sv_2mortal(newSVpv("", 0));
	sv_setpvn(ST(0), (char *)data, len);

void
output_consume(ssh, len)
    Net::SSH::LibSSH *ssh;
    u_int len;

    CODE:
	ssh_output_consume(ssh, len);
