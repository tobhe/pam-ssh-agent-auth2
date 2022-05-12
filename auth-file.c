/* $OpenBSD$ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <pwd.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "xmalloc.h"
#include "hostfile.h"
#include "match.h"
#include "log.h"
#include "misc.h"
#include "servconf.h"
#include "sshkey.h"
#include "auth.h"
#include "auth-options.h"
#include "canohost.h"
#include "packet.h"
#include "authfile.h"

/* import */
extern ServerOptions options;

static int
match_principals_option(const char *principal_list, struct sshkey_cert *cert)
{
	char *result;
	u_int i;

	/* XXX percent_expand() sequences for authorized_principals? */

	for (i = 0; i < cert->nprincipals; i++) {
		if ((result = match_list(cert->principals[i],
		    principal_list, NULL)) != NULL) {
			debug3("matched principal from key options \"%.100s\"",
			    result);
			free(result);
			return 1;
		}
	}
	return 0;
}

/*
 * Check a single line of an authorized_keys-format file. Returns 0 if key
 * matches, -1 otherwise. Will return key/cert options via *authoptsp
 * on success. "loc" is used as file/line location in log messages.
 */
static int
check_authkey_line(struct ssh *ssh, struct passwd *pw, struct sshkey *key,
    char *cp, const char *loc, struct sshauthopt **authoptsp)
{
	int want_keytype = sshkey_is_cert(key) ? KEY_UNSPEC : key->type;
	struct sshkey *found = NULL;
	struct sshauthopt *keyopts = NULL, *certopts = NULL, *finalopts = NULL;
	char *key_options = NULL, *fp = NULL;
	const char *reason = NULL;
	int ret = -1;

	if (authoptsp != NULL)
		*authoptsp = NULL;

	if ((found = sshkey_new(want_keytype)) == NULL) {
		debug3_f("keytype %d failed", want_keytype);
		goto out;
	}

	/* XXX djm: peek at key type in line and skip if unwanted */

	if (sshkey_read(found, &cp) != 0) {
		/* no key?  check for options */
		debug2("%s: check options: '%s'", loc, cp);
		key_options = cp;
		if (sshkey_advance_past_options(&cp) != 0) {
			reason = "invalid key option string";
			goto fail_reason;
		}
		skip_space(&cp);
		if (sshkey_read(found, &cp) != 0) {
			/* still no key?  advance to next line*/
			debug2("%s: advance: '%s'", loc, cp);
			goto out;
		}
	}
	/* Parse key options now; we need to know if this is a CA key */
	if ((keyopts = sshauthopt_parse(key_options, &reason)) == NULL) {
		debug("%s: bad key options: %s", loc, reason);
		auth_debug_add("%s: bad key options: %s", loc, reason);
		goto out;
	}
	/* Ignore keys that don't match or incorrectly marked as CAs */
	if (sshkey_is_cert(key)) {
		/* Certificate; check signature key against CA */
		if (!sshkey_equal(found, key->cert->signature_key) ||
		    !keyopts->cert_authority)
			goto out;
	} else {
		/* Plain key: check it against key found in file */
		if (!sshkey_equal(found, key) || keyopts->cert_authority)
			goto out;
	}

	/* We have a candidate key, perform authorisation checks */
	if ((fp = sshkey_fingerprint(found,
	    options.fingerprint_hash, SSH_FP_DEFAULT)) == NULL)
		fatal_f("fingerprint failed");

	debug("%s: matching %s found: %s %s", loc,
	    sshkey_is_cert(key) ? "CA" : "key", sshkey_type(found), fp);

	if (auth_authorise_keyopts(ssh, pw, keyopts,
	    sshkey_is_cert(key), loc) != 0) {
		reason = "Refused by key options";
		goto fail_reason;
	}

	/* That's all we need for plain keys. */
	if (!sshkey_is_cert(key)) {
		verbose("Accepted key %s %s found at %s",
		    sshkey_type(found), fp, loc);
		finalopts = keyopts;
		keyopts = NULL;
		goto success;
	}

	/*
	 * Additional authorisation for certificates.
	 */

	/* Parse and check options present in certificate */
	if ((certopts = sshauthopt_from_cert(key)) == NULL) {
		reason = "Invalid certificate options";
		goto fail_reason;
	}
	if (auth_authorise_keyopts(ssh, pw, certopts, 0, loc) != 0) {
		reason = "Refused by certificate options";
		goto fail_reason;
	}
	if ((finalopts = sshauthopt_merge(keyopts, certopts, &reason)) == NULL)
		goto fail_reason;

	/*
	 * If the user has specified a list of principals as
	 * a key option, then prefer that list to matching
	 * their username in the certificate principals list.
	 */
	if (keyopts->cert_principals != NULL &&
	    !match_principals_option(keyopts->cert_principals, key->cert)) {
		reason = "Certificate does not contain an authorized principal";
		goto fail_reason;
	}
	if (sshkey_cert_check_authority_now(key, 0, 0, 0,
	    keyopts->cert_principals == NULL ? pw->pw_name : NULL,
	    &reason) != 0)
		goto fail_reason;

	verbose("Accepted certificate ID \"%s\" (serial %llu) "
	    "signed by CA %s %s found at %s",
	    key->cert->key_id,
	    (unsigned long long)key->cert->serial,
	    sshkey_type(found), fp, loc);

 success:
	if (finalopts == NULL)
		fatal_f("internal error: missing options");
	if (authoptsp != NULL) {
		*authoptsp = finalopts;
		finalopts = NULL;
	}
	/* success */
	ret = 0;
	goto out;

 fail_reason:
	error("%s", reason);
	auth_debug_add("%s", reason);
 out:
	free(fp);
	sshauthopt_free(keyopts);
	sshauthopt_free(certopts);
	sshauthopt_free(finalopts);
	sshkey_free(found);
	return ret;
}

/*
 * Checks whether key is allowed in authorized_keys-format file,
 * returns 1 if the key is allowed or 0 otherwise.
 */
int
check_authkeys_file(struct ssh *ssh, struct passwd *pw, FILE *f,
    char *file, struct sshkey *key, struct sshauthopt **authoptsp)
{
	char *cp, *line = NULL, loc[256];
	size_t linesize = 0;
	int found_key = 0;
	u_long linenum = 0, nonblank = 0;

	if (authoptsp != NULL)
		*authoptsp = NULL;

	while (getline(&line, &linesize, f) != -1) {
		linenum++;
		/* Always consume entire file */
		if (found_key)
			continue;

		/* Skip leading whitespace, empty and comment lines. */
		cp = line;
		skip_space(&cp);
		if (!*cp || *cp == '\n' || *cp == '#')
			continue;

		nonblank++;
		snprintf(loc, sizeof(loc), "%.200s:%lu", file, linenum);
		if (check_authkey_line(ssh, pw, key, cp, loc, authoptsp) == 0)
			found_key = 1;
	}
	free(line);
	debug2_f("%s: processed %lu/%lu lines", file, nonblank, linenum);
	return found_key;
}

/*
 * Returns the remote DNS hostname as a string. The returned string must not
 * be freed. NB. this will usually trigger a DNS query the first time it is
 * called.
 * This function does additional checks on the hostname to mitigate some
 * attacks on based on conflation of hostnames and IP addresses.
 */

static char *
remote_hostname(struct ssh *ssh)
{
	struct sockaddr_storage from;
	socklen_t fromlen;
	struct addrinfo hints, *ai, *aitop;
	char name[NI_MAXHOST], ntop2[NI_MAXHOST];
	const char *ntop = ssh_remote_ipaddr(ssh);

	/* Get IP address of client. */
	fromlen = sizeof(from);
	memset(&from, 0, sizeof(from));
	if (getpeername(ssh_packet_get_connection_in(ssh),
	    (struct sockaddr *)&from, &fromlen) == -1) {
		debug("getpeername failed: %.100s", strerror(errno));
		return xstrdup(ntop);
	}

	ipv64_normalise_mapped(&from, &fromlen);
	if (from.ss_family == AF_INET6)
		fromlen = sizeof(struct sockaddr_in6);

	debug3("Trying to reverse map address %.100s.", ntop);
	/* Map the IP address to a host name. */
	if (getnameinfo((struct sockaddr *)&from, fromlen, name, sizeof(name),
	    NULL, 0, NI_NAMEREQD) != 0) {
		/* Host name not found.  Use ip address. */
		return xstrdup(ntop);
	}

	/*
	 * if reverse lookup result looks like a numeric hostname,
	 * someone is trying to trick us by PTR record like following:
	 *	1.1.1.10.in-addr.arpa.	IN PTR	2.3.4.5
	 */
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;	/*dummy*/
	hints.ai_flags = AI_NUMERICHOST;
	if (getaddrinfo(name, NULL, &hints, &ai) == 0) {
		logit("Nasty PTR record \"%s\" is set up for %s, ignoring",
		    name, ntop);
		freeaddrinfo(ai);
		return xstrdup(ntop);
	}

	/* Names are stored in lowercase. */
	lowercase(name);

	/*
	 * Map it back to an IP address and check that the given
	 * address actually is an address of this host.  This is
	 * necessary because anyone with access to a name server can
	 * define arbitrary names for an IP address. Mapping from
	 * name to IP address can be trusted better (but can still be
	 * fooled if the intruder has access to the name server of
	 * the domain).
	 */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = from.ss_family;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(name, NULL, &hints, &aitop) != 0) {
		logit("reverse mapping checking getaddrinfo for %.700s "
		    "[%s] failed.", name, ntop);
		return xstrdup(ntop);
	}
	/* Look for the address from the list of addresses. */
	for (ai = aitop; ai; ai = ai->ai_next) {
		if (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop2,
		    sizeof(ntop2), NULL, 0, NI_NUMERICHOST) == 0 &&
		    (strcmp(ntop, ntop2) == 0))
				break;
	}
	freeaddrinfo(aitop);
	/* If we reached the end of the list, the address was not there. */
	if (ai == NULL) {
		/* Address not found for the host name. */
		logit("Address %.100s maps to %.600s, but this does not "
		    "map back to the address.", ntop, name);
		return xstrdup(ntop);
	}
	return xstrdup(name);
}

/*
 * Return the canonical name of the host in the other side of the current
 * connection.  The host name is cached, so it is efficient to call this
 * several times.
 */

const char *
auth_get_canonical_hostname(struct ssh *ssh, int use_dns)
{
	static char *dnsname;

	if (!use_dns)
		return ssh_remote_ipaddr(ssh);
	else if (dnsname != NULL)
		return dnsname;
	else {
		dnsname = remote_hostname(ssh);
		return dnsname;
	}
}

int
auth_authorise_keyopts(struct ssh *ssh, struct passwd *pw,
    struct sshauthopt *opts, int allow_cert_authority, const char *loc)
{
	const char *remote_ip = ssh_remote_ipaddr(ssh);
	const char *remote_host = auth_get_canonical_hostname(ssh,
	    options.use_dns);
	time_t now = time(NULL);
	char buf[64];

	/*
	 * Check keys/principals file expiry time.
	 * NB. validity interval in certificate is handled elsewhere.
	 */
	if (opts->valid_before && now > 0 &&
	    opts->valid_before < (uint64_t)now) {
		format_absolute_time(opts->valid_before, buf, sizeof(buf));
		debug("%s: entry expired at %s", loc, buf);
		auth_debug_add("%s: entry expired at %s", loc, buf);
		return -1;
	}
	/* Consistency checks */
	if (opts->cert_principals != NULL && !opts->cert_authority) {
		debug("%s: principals on non-CA key", loc);
		auth_debug_add("%s: principals on non-CA key", loc);
		/* deny access */
		return -1;
	}
	/* cert-authority flag isn't valid in authorized_principals files */
	if (!allow_cert_authority && opts->cert_authority) {
		debug("%s: cert-authority flag invalid here", loc);
		auth_debug_add("%s: cert-authority flag invalid here", loc);
		/* deny access */
		return -1;
	}

	/* Perform from= checks */
	if (opts->required_from_host_keys != NULL) {
		switch (match_host_and_ip(remote_host, remote_ip,
		    opts->required_from_host_keys )) {
		case 1:
			/* Host name matches. */
			break;
		case -1:
		default:
			debug("%s: invalid from criteria", loc);
			auth_debug_add("%s: invalid from criteria", loc);
			/* FALLTHROUGH */
		case 0:
			logit("%s: Authentication tried for %.100s with "
			    "correct key but not from a permitted "
			    "host (host=%.200s, ip=%.200s, required=%.200s).",
			    loc, pw->pw_name, remote_host, remote_ip,
			    opts->required_from_host_keys);
			auth_debug_add("%s: Your host '%.200s' is not "
			    "permitted to use this key for login.",
			    loc, remote_host);
			/* deny access */
			return -1;
		}
	}
	/* Check source-address restriction from certificate */
	if (opts->required_from_host_cert != NULL) {
		switch (addr_match_cidr_list(remote_ip,
		    opts->required_from_host_cert)) {
		case 1:
			/* accepted */
			break;
		case -1:
		default:
			/* invalid */
			error("%s: Certificate source-address invalid", loc);
			/* FALLTHROUGH */
		case 0:
			logit("%s: Authentication tried for %.100s with valid "
			    "certificate but not from a permitted source "
			    "address (%.200s).", loc, pw->pw_name, remote_ip);
			auth_debug_add("%s: Your address '%.200s' is not "
			    "permitted to use this certificate for login.",
			    loc, remote_ip);
			return -1;
		}
	}
	/*
	 *
	 * XXX this is spammy. We should report remotely only for keys
	 *     that are successful in actual auth attempts, and not PK_OK
	 *     tests.
	 */
	auth_log_authopts(loc, opts, 1);

	return 0;
}
