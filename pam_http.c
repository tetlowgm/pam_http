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

#ifdef __linux__
#define _POSIX_C_SOURCE 200112L
#endif

#include <sys/param.h>

#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#define MAXURILEN 2048

static bool	debug = false;

struct options {
	const char     *confuri;
	long		timeout;
};

/*
 * I find it very annoying that strlcat hasn't been integrated into glibc. I
 * get that it may not be the best practice to just include it here, but it
 * works and I'm really rather lazy.
 */
#ifdef __linux__
#include "strlcat.c"
#endif

static void
dbgprnt(const char *const fmt,...)
{
	va_list		ap;

	if (!debug)
		return;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

/*
 * This routine takes the configuration URI and replaces the template character
 * sequences with the appropriate expansion. Returns the untruncated length of
 * the resulting string, so truncation can be trivially detected by comparing
 * the return value against finaluri_size.
 */
static size_t
builduri(char *finaluri, size_t finaluri_size, const char *confuri,
         pam_handle_t * pamh, const char * const type)
{
	const char     *user = NULL, *service = NULL, *puri, *pstr;
	char		host[MAXHOSTNAMELEN + 1] = "\0";
	size_t		totaluri_size = 0;
	bool		write = true;

	totaluri_size += strlen(confuri);
	puri = confuri;

	if (finaluri_size == 0)
		write = false;

	if (write)
		memset(finaluri, 0, finaluri_size);

	while ((pstr = strchr(puri, '%')) != NULL) {
		if ((pstr - puri + 1) > (long)(finaluri_size - strlen(finaluri)))
			write = false;
		if (write)
			strncat(finaluri, puri, pstr - puri);

		switch (pstr[1]) {
		case '%':
			/* Replacing %% with % makes the string smaller. */
			totaluri_size--;
			if (write && (strlcat(finaluri, "%", finaluri_size) >= finaluri_size))
				write = false;
			break;
		case 'h':
			if (host[0] == '\0') {
				if (gethostname(host, MAXHOSTNAMELEN) != 0)
					return 0;
				dbgprnt("hostname: %s\n", host);
			}

			/*
			 * Here (and later) we are replacing %X with a
			 * string, so sub 2.
			 */
			totaluri_size += strlen(host) - 2;

			if (write && (strlcat(finaluri, host, finaluri_size) >= finaluri_size))
				write = false;
			break;
		case 's':
			if (service == NULL) {
				if (pam_get_item(pamh, PAM_SERVICE, (const void **)&service) != PAM_SUCCESS)
					return 0;
				dbgprnt("service: %s\n", service);
			}

			totaluri_size += strlen(service) - 2;

			if (write && (strlcat(finaluri, service, finaluri_size) >= finaluri_size))
				write = false;
			break;
		case 't':
			totaluri_size += strlen(type) - 2;

			if (write && (strlcat(finaluri, type, finaluri_size) >= finaluri_size))
				write = false;
			break;
		case 'u':
			if (user == NULL) {
				if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS)
					return 0;
				if (getpwnam(user) == NULL)
					return 0;
				dbgprnt("username: %s\n", user);
			}

			totaluri_size += strlen(user) - 2;

			if (write && (strlcat(finaluri, user, finaluri_size) >= finaluri_size))
				write = false;
			break;
		default:
			dbgprnt("Invalid uri token: %%%c\n", pstr[1]);
			return 0;
		}
		puri = pstr + 2;
	}
	if (write && (strlcat(finaluri, puri, finaluri_size) >= finaluri_size))
		;
	dbgprnt("finaluri: '%s'\n", finaluri);

	return totaluri_size;
}

static void
parse_args(struct options *opt, int argc, const char *argv[])
{

	opt->confuri = NULL;
	opt->timeout = 30;

	for (int i = 0; i < argc; i++) {
		const char     *value = strchr(argv[i], '=');
		if (value != NULL) {
			if (strncmp(argv[i], "timeout=", 8) == 0)
				opt->timeout = atol(value + 1);
			if (strncmp(argv[i], "uri=", 4) == 0)
				opt->confuri = value + 1;
		} else if (strncmp(argv[i], "debug", 5) == 0) {
			debug = true;
		}
	}
	dbgprnt("Options:\n  confuri: '%s'\n  timeout: %ld\n", opt->confuri, opt->timeout);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t * pamh, __attribute__((unused)) int flags,
		 int argc, const char *argv[])
{
	char		finaluri[MAXURILEN + 1];
	int		pam_err = PAM_AUTH_ERR;
	size_t		ret;
	CURL	       *curl;
	CURLcode	curlres;
	struct options	opt;

	/* Get configuration items. */
	parse_args(&opt, argc, argv);

	/* Build expanded URI */
	ret = builduri(finaluri, MAXURILEN, opt.confuri, pamh, "account");
	if (ret == 0)
		return PAM_AUTH_ERR;
	else if (ret > MAXURILEN) {
		dbgprnt("Total URI size larger than buffer: %d > %d\n", ret, MAXURILEN);
		return PAM_AUTH_ERR;
	}

	/* Time to make the curl call. */
	pam_err = PAM_AUTH_ERR;
	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, finaluri);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, opt.timeout);
		curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
		curlres = curl_easy_perform(curl);
		dbgprnt("curlres: %d\n", curlres);

		if (curlres == CURLE_OK) {
			long		curlrescode;
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &curlrescode);
			dbgprnt("curlrescode: %d\n", curlrescode);
			if (curlrescode == 200)
				pam_err = PAM_SUCCESS;
		}
		curl_easy_cleanup(curl);
	}

	return (pam_err);
}

PAM_EXTERN int
pam_sm_authenticate(__attribute__((unused)) pam_handle_t * pamh,
		    __attribute__((unused)) int flags,
		    __attribute__((unused)) int argc,
		    __attribute__((unused)) const char *argv[])
{

	return (PAM_SERVICE_ERR);
}

PAM_EXTERN int
pam_sm_setcred(__attribute__((unused)) pam_handle_t * pamh,
	       __attribute__((unused)) int flags,
	       __attribute__((unused)) int argc,
	       __attribute__((unused)) const char *argv[])
{

	return (PAM_SERVICE_ERR);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t * pamh, __attribute__((unused)) int flags,
		    int argc, const char *argv[])
{
	char		finaluri[MAXURILEN];
	int		pam_err = PAM_AUTH_ERR;
	size_t		ret;
	CURL	       *curl;
	CURLcode	curlres;
	struct options	opt;

	/* Get configuration items. */
	parse_args(&opt, argc, argv);

	/* Build expanded URI */
	ret = builduri(finaluri, MAXURILEN, opt.confuri, pamh, "open_session");
	if (ret == 0)
		return PAM_AUTH_ERR;
	else if (ret > MAXURILEN) {
		dbgprnt("Total URI size larger than buffer: %d > %d\n", ret, MAXURILEN);
		return PAM_AUTH_ERR;
	}

	/* Time to make the curl call. */
	pam_err = PAM_AUTH_ERR;
	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, finaluri);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, opt.timeout);
		curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
		curlres = curl_easy_perform(curl);
		dbgprnt("curlres: %d\n", curlres);

		if (curlres == CURLE_OK) {
			long		curlrescode;
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &curlrescode);
			dbgprnt("curlrescode: %d\n", curlrescode);
			if (curlrescode == 200)
				pam_err = PAM_SUCCESS;
		}
		curl_easy_cleanup(curl);
	}

	return (pam_err);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t * pamh, __attribute__((unused)) int flags,
		     int argc, const char *argv[])
{
	char		finaluri[MAXURILEN];
	int		pam_err = PAM_AUTH_ERR;
	size_t		ret;
	CURL	       *curl;
	CURLcode	curlres;
	struct options	opt;

	/* Get configuration items. */
	parse_args(&opt, argc, argv);

	/* Build expanded URI */
	ret = builduri(finaluri, MAXURILEN, opt.confuri, pamh, "close_session");
	if (ret == 0)
		return PAM_AUTH_ERR;
	else if (ret > MAXURILEN) {
		dbgprnt("Total URI size larger than buffer: %d > %d\n", ret, MAXURILEN);
		return PAM_AUTH_ERR;
	}

	/* Time to make the curl call. */
	pam_err = PAM_AUTH_ERR;
	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, finaluri);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, opt.timeout);
		curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
		curlres = curl_easy_perform(curl);
		dbgprnt("curlres: %d\n", curlres);

		if (curlres == CURLE_OK) {
			long		curlrescode;
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &curlrescode);
			dbgprnt("curlrescode: %d\n", curlrescode);
			if (curlrescode == 200)
				pam_err = PAM_SUCCESS;
		}
		curl_easy_cleanup(curl);
	}

	return (pam_err);
}

PAM_EXTERN int
pam_sm_chauthtok(__attribute__((unused)) pam_handle_t * pamh,
		 __attribute__((unused)) int flags,
		 __attribute__((unused)) int argc,
		 __attribute__((unused)) const char *argv[])
{

	return (PAM_SERVICE_ERR);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_http");
#endif
