/* $OpenBSD$ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2008 Damien Miller.  All rights reserved.
 * Copyright (c) 2008 Jamie Beverly.
 * Copyright (c) 2022 Tobias Heider <tobias.heider@canonical.com>
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

#include "../../config.h"
#include <syslog.h>

#include <security/pam_appl.h>
#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "packet.h"
#include "hostfile.h"
#include "auth.h"
#include "authfd.h"
#include "authfile.h"
#include "auth-options.h"
#include "crypto_api.h"
#include "digest.h"
#include "log.h"
#include "misc.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "servconf.h"

#define CHALLENGE_PREFIX	"pam-ssh-agent-auth-challenge"
#define CHALLENGE_NONCE_LEN	32
#define UNUSED(expr) do { (void)(expr); } while (0)

ServerOptions options;
struct sshauthopt *auth_opts = NULL;

char		*authorized_keys_file = "/etc/security/authorized_keys";

extern char	*__progname;

void
auth_debug_add(const char *fmt,...)
{
}

void
auth_log_authopts(const char *loc, const struct sshauthopt *opts, int do_remote)
{
}

static FILE *
pam_openfile(const char *file, struct passwd *pw)
{
	char line[1024];
	struct stat st;
	int fd;
	FILE *f;

	if ((fd = open(file, O_RDONLY|O_NONBLOCK)) == -1) {
		if (errno != ENOENT)
			debug("Could not open authorized_keys '%s': %s", file,
			    strerror(errno));
		return NULL;
	}

	if (fstat(fd, &st) == -1) {
		close(fd);
		return NULL;
	}
	if (!S_ISREG(st.st_mode)) {
		logit("User %s authorized_keys %s is not a regular file",
		    pw->pw_name, file);
		close(fd);
		return NULL;
	}
	unset_nonblock(fd);
	if ((f = fdopen(fd, "r")) == NULL) {
		close(fd);
		return NULL;
	}
	if (safe_path_fd(fileno(f), file, pw, line, sizeof(line)) != 0) {
		fclose(f);
		logit("Authentication refused: %s", line);
		return NULL;
	}

	return f;
}

/* obtain a list of keys from the agent */
static int
pam_get_agent_identities(int *agent_fdp,
    struct ssh_identitylist **idlistp)
{
	int r, agent_fd;
	struct ssh_identitylist *idlist;

	if ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		if (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		return r;
	}
	if ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		debug_fr(r, "ssh_fetch_identitylist");
		close(agent_fd);
		return r;
	}
	/* success */
	*agent_fdp = agent_fd;
	*idlistp = idlist;
	debug_f("agent returned %zu keys", idlist->nkeys);
	return 0;
}

static int
pam_user_key_allowed(pam_handle_t *pamh, struct sshkey *key,
    char *file)
{
	struct passwd *pw = getpwuid(0);
	struct sshauthopt *authoptsp = NULL;
	int found_key = 0;
	/* Needed for remote_ip and remote_host. */
	struct ssh ssh = {0};
	FILE *f;

	if ((f = pam_openfile(file, pw)) != NULL) {
		found_key = check_authkeys_file(&ssh, pw, f, file, key, &authoptsp);
		fclose(f);
	}

	return found_key;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct sshbuf *sigbuf = NULL;
	u_char *nonce;
	struct ssh_identitylist *idlist = NULL;
	int ret = PAM_AUTH_ERR, agent_fd = -1;
	size_t j;

	for(; argc > 0; ++argv, argc--) {
		if(strncasecmp(*argv, "file=", strlen("file=")) == 0 ) {
			authorized_keys_file = (char *) *argv + strlen("file=");
		}
	}

	if (pam_get_agent_identities(&agent_fd, &idlist) != 0) {
		pam_syslog(pamh, LOG_CRIT, "pam_get_agent_identities() failed.");
		goto exit;
	}

	for (j = 0; j < idlist->nkeys; j++) {
		/* Check if key in authorized_keys */
		if (!pam_user_key_allowed(pamh, idlist->keys[j],
		    authorized_keys_file))
			continue;

		/* Generate random challenge */
		if ((sigbuf = sshbuf_new()) == NULL ||
		    sshbuf_put_cstring(sigbuf, CHALLENGE_PREFIX) != 0 ||
		    sshbuf_reserve(sigbuf, CHALLENGE_NONCE_LEN, &nonce) != 0)
			goto exit;

		arc4random_buf(nonce, CHALLENGE_NONCE_LEN);

		/* Sign challenge via ssh-agent */
		u_char *sig = NULL;
		size_t	slen = 0;
		if (ssh_agent_sign(agent_fd, idlist->keys[j], &sig, &slen,
		    sshbuf_ptr(sigbuf), sshbuf_len(sigbuf), NULL, 0) != 0)
			goto exit;

		/* Verify signature */
		if (sshkey_verify(idlist->keys[j], sig, slen,
		    sshbuf_ptr(sigbuf), sshbuf_len(sigbuf),
		    NULL, 0, NULL) == 0) {
			pam_syslog(pamh, LOG_INFO, "Found matching %s key: %s",
			    sshkey_type(idlist->keys[j]),
			    sshkey_fingerprint(idlist->keys[j], SSH_DIGEST_SHA256,
			    SSH_FP_DEFAULT));

			ret = PAM_SUCCESS;
			break;
		}
		sshbuf_free(sigbuf);
		sigbuf = NULL;
	}

 exit:
	ssh_free_identitylist(idlist);
	sshbuf_free(sigbuf);

	return ret;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	UNUSED(pamh);
	UNUSED(flags);
	UNUSED(argc);
	UNUSED(argv);
	return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module _pam_ssh_agent_auth_modstruct = {
	"pam_ssh_agent_auth",
	pam_sm_authenticate,
	pam_sm_setcred,
	NULL,
	NULL,
	NULL,
	NULL,
};
#endif
