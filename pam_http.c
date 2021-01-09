/*-
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2021 Gordon Tetlow. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>

#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#define MAXURILEN 2048

bool		debug = false;

static void
dbgprnt(char *fmt,...)
{
	va_list		ap;

	if (!debug)
		return;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t * pamh, int flags, int argc, const char *argv[])
{
	const char     *user, *service, *confuri, *puri, *pstr;
	char		host[MAXHOSTNAMELEN + 1], finaluri[MAXURILEN];
	int		pam_err;
	CURL	       *curl;
	CURLcode	curlres;

	/* Get configuration items. */
	for (int i = 0; i < argc; i++) {
		const char     *value = strchr(argv[i], '=');
		if (value != NULL) {
			if (strncmp(argv[i], "uri=", 4) == 0)
				confuri = value + 1;
		} else if (strncmp(argv[i], "debug", 5) == 0) {
			debug = true;
		}
	}
	dbgprnt("confuri: '%s'\n", confuri);

	/* Gather fields to replace in the URI. */
	if (gethostname(host, MAXHOSTNAMELEN) != 0)
		return (PAM_AUTH_ERR);
	dbgprnt("hostname: %s\n", host);

	if ((pam_err = pam_get_item(pamh, PAM_SERVICE, (const void **)&service)) != PAM_SUCCESS)
		return (pam_err);
	dbgprnt("service: %s\n", service);

	if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
		return (pam_err);
	if (getpwnam(user) == NULL)
		return (PAM_USER_UNKNOWN);
	dbgprnt("username: %s\n", user);

	/* Build expanded URI */
	puri = confuri;
	memset(finaluri, 0, MAXURILEN);
	while ((pstr = strchr(puri, '%')) != NULL) {
		if ((pstr - puri + 1) > (long)(MAXURILEN - strlen(finaluri)))
			return (PAM_AUTH_ERR);
		strncat(finaluri, puri, pstr - puri);

		switch (pstr[1]) {
		case '%':
			if (strlcat(finaluri, "%", MAXURILEN) >= MAXURILEN)
				return (PAM_AUTH_ERR);
			break;
		case 'h':
			if (strlcat(finaluri, host, MAXURILEN) >= MAXURILEN)
				return (PAM_AUTH_ERR);
			break;
		case 's':
			if (strlcat(finaluri, service, MAXURILEN) >= MAXURILEN)
				return (PAM_AUTH_ERR);
			break;
		case 'u':
			if (strlcat(finaluri, user, MAXURILEN) >= MAXURILEN)
				return (PAM_AUTH_ERR);
			break;
		default:
			dbgprnt("Invalid uri token: %%%c\n", pstr[1]);
			return (PAM_AUTH_ERR);
		}
		puri = pstr + 2;
	}
	if (strlcat(finaluri, puri, MAXURILEN) >= MAXURILEN)
		return (PAM_AUTH_ERR);
	dbgprnt("finaluri: '%s'\n", finaluri);

	/* Time to make the curl call. */
	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, finaluri);
		curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
		curlres = curl_easy_perform(curl);
		dbgprnt("curlres: %d\n", curlres);
		curl_easy_cleanup(curl);

		if (curlres == CURLE_OK) {
			long		curlrescode;
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &curlrescode);
			dbgprnt("curlrescode: %d\n", curlrescode);
			if (curlrescode == 200)
				return (PAM_SUCCESS);
		}
	}

	return (PAM_AUTH_ERR);
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t * pamh, int flags, int argc, const char *argv[])
{

	return (PAM_SERVICE_ERR);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t * pamh, int flags, int argc, const char *argv[])
{

	return (PAM_SERVICE_ERR);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t * pamh, int flags, int argc, const char *argv[])
{

	return (PAM_SERVICE_ERR);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t * pamh, int flags, int argc, const char *argv[])
{

	return (PAM_SERVICE_ERR);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t * pamh, int flags, int argc, const char *argv[])
{

	return (PAM_SERVICE_ERR);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_http");
#endif
