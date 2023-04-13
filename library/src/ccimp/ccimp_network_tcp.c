/*
 * Copyright (c) 2017-2023 Digi International Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 * Digi International Inc., 9350 Excelsior Blvd., Suite 700, Hopkins, MN 55343
 * ===========================================================================
 */

#include "ccimp/ccimp_network.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#if (defined APP_SSL)
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif /* APP_SSL */

#include "ccimp/ccimp_os.h"
#include "cc_config.h"
#include "cc_logging.h"
#include "dns_helper.h"

#if (defined UNIT_TEST)
#define ccimp_network_tcp_open       ccimp_network_tcp_open_real
#define ccimp_network_tcp_send       ccimp_network_tcp_send_real
#define ccimp_network_tcp_receive    ccimp_network_tcp_receive_real
#define ccimp_network_tcp_close      ccimp_network_tcp_close_real
#endif /* UNIT_TEST */

/*
 * FIXME: This must be lower than the timeout specified in the call to
 * ccapi_start_transport_tcp() to avoid a race condition (CCAPI-163)
 */
#define APP_CONNECT_TIMEOUT 25
#define APP_DISCONNECT_TIMEOUT 10

/*------------------------------------------------------------------------------
                 D A T A    T Y P E S    D E F I N I T I O N S
------------------------------------------------------------------------------*/
typedef struct {
	int sock;
#if (defined APP_SSL)
	SSL_CTX *ctx;
	SSL *ssl;
#endif /* APP_SSL */
	ccimp_os_system_up_time_t disconnect_start_time;
	ccimp_os_system_up_time_t connect_start_time;
} network_handle_t;

/*------------------------------------------------------------------------------
                    F U N C T I O N  D E C L A R A T I O N S
------------------------------------------------------------------------------*/
static int app_tcp_create_socket(void);
static ccimp_status_t app_tcp_connect(int const sock, in_addr_t const ip_addr);
static ccimp_status_t app_is_tcp_connect_complete(int const sock);
static void free_network_handle(network_handle_t *const ssl_ptr);
#if (defined APP_SSL)
static int get_user_passwd(char *buf, int size, int rwflag, void *password);
static int app_load_certificate_and_key(SSL_CTX *const ctx);
static int app_verify_device_cloud_certificate(SSL *const ssl);
static int app_ssl_connect(network_handle_t *const handle);
#endif /* APP_SSL */

/*------------------------------------------------------------------------------
                     F U N C T I O N  D E F I N I T I O N S
------------------------------------------------------------------------------*/
ccimp_status_t ccimp_network_tcp_close(ccimp_network_close_t *const data)
{
	network_handle_t *const handle = data->handle;

	if (handle->disconnect_start_time.sys_uptime == 0) {
		ccimp_os_get_system_time(&handle->disconnect_start_time);
	} else {
		unsigned long elapsed_time;
		ccimp_os_system_up_time_t current_time;

		ccimp_os_get_system_time(&current_time);
		elapsed_time = current_time.sys_uptime - handle->disconnect_start_time.sys_uptime;

		if (elapsed_time > APP_DISCONNECT_TIMEOUT)
			goto close;
	}

#if (defined APP_SSL)
	if (handle->ssl != NULL) {
		/* Send close notify to peer */
		int ret = SSL_shutdown(handle->ssl);

		if (ret == 0)
			return CCIMP_STATUS_BUSY;

		if (ret < 0) {
			int error = SSL_get_error(handle->ssl, ret);

			if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE)
				return CCIMP_STATUS_BUSY;

			log_error("Error closing connection: SSL error %d", error);
		}
	}
#endif /* APP_SSL */

close:
	if (handle->sock != -1 && close(handle->sock) < 0)
		log_error("Error closing connection: %s (%d)", strerror(errno), errno);

	free_network_handle(handle);

	return CCIMP_STATUS_OK;
}

ccimp_status_t ccimp_network_tcp_receive(ccimp_network_receive_t *const data)
{
	network_handle_t *const handle = data->handle;
	int read_bytes = 0;

#if (defined APP_SSL)
	if (SSL_pending(handle->ssl) == 0) {
		int ready;
		struct timeval timeout;
		fd_set read_set;

		timeout.tv_sec = 0;
		timeout.tv_usec = 0;

		FD_ZERO(&read_set);
		FD_SET(handle->sock, &read_set);

		ready = select(handle->sock + 1, &read_set, NULL, NULL, &timeout);
		if (ready == 0) {
			return CCIMP_STATUS_BUSY;
		} else if (ready < 0) {
			log_debug("%s: select on sock %d returned %d, errno %d",
					__func__, handle->sock, ready, errno);
			return CCIMP_STATUS_OK;
		}
	}
	read_bytes = SSL_read(handle->ssl, data->buffer, data->bytes_available);
#else /* APP_SSL */
	read_bytes = read(handle->sock, data->buffer, data->bytes_available);
#endif /* APP_SSL */

	if (read_bytes > 0) {
		data->bytes_used = (size_t) read_bytes;

		return CCIMP_STATUS_OK;
	}

	if (read_bytes == 0) {
		/* EOF on input: the connection was closed. */
		log_debug("%s: EOF on socket", __func__);
		errno = ECONNRESET;
		return CCIMP_STATUS_ERROR;
	} else {
		int const err = errno;

		/* An error of some sort occurred: handle it appropriately. */
#if (defined APP_SSL)
		int ssl_error = SSL_get_error(handle->ssl, read_bytes);

		if (ssl_error == SSL_ERROR_WANT_READ)
			return CCIMP_STATUS_BUSY;

		SSL_set_shutdown(handle->ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
#endif /* APP_SSL */
		if (err == EAGAIN)
			return CCIMP_STATUS_BUSY;

		log_error("Error establishing connection (%s): %s (%d)",  __func__, strerror(err), err);
		/* If not timeout (no data) return an error */
		dns_cache_invalidate();

		return CCIMP_STATUS_ERROR;
	}

	return CCIMP_STATUS_OK;
}

ccimp_status_t ccimp_network_tcp_send(ccimp_network_send_t *const data)
{
	network_handle_t *const handle = data->handle;
	int sent_bytes = 0;
	int err;

#if (defined APP_SSL)
	sent_bytes = SSL_write(handle->ssl, data->buffer, data->bytes_available);
#else /* APP_SSL */
	sent_bytes = write(handle->sock, data->buffer, data->bytes_available);
#endif /* APP_SSL */

	if (sent_bytes >= 0) {
		data->bytes_used = (size_t) sent_bytes;

		return CCIMP_STATUS_OK;
	}

	err = errno;
	if (err == EAGAIN)
		return CCIMP_STATUS_BUSY;

	log_error("Error establishing connection (%s): %s (%d)", __func__, strerror(err), err);
#if (defined APP_SSL)
	SSL_set_shutdown(handle->ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
#endif /* APP_SSL */
	dns_cache_invalidate();

	return CCIMP_STATUS_ERROR;
}

ccimp_status_t ccimp_network_tcp_open(ccimp_network_open_t *const data)
{
	ccimp_status_t status = CCIMP_STATUS_ERROR;
	struct sockaddr_in interface_addr;
	socklen_t interface_addr_len;
	network_handle_t *handle = data->handle;

	if (handle == NULL) {
		handle = calloc(1, sizeof *handle);
		if (handle == NULL) {
			log_error("Error opening connection to '%s': Unable to allocate memory", data->device_cloud.url);
			return CCIMP_STATUS_ERROR;
		}

		handle->sock = -1;

#if (defined APP_SSL)
		handle->ctx = NULL;
		handle->ssl = NULL;
#endif /* APP_SSL */

		ccimp_os_get_system_time(&handle->connect_start_time);
		data->handle = handle;
	}

	if (handle->sock == -1) {
		in_addr_t ip_addr;

		if (dns_resolve(data->device_cloud.url, &ip_addr) != 0) {
			log_error("Failed to resolve DNS for %s", data->device_cloud.url);
			status = CCIMP_STATUS_ERROR;
			goto error;
		}

		handle->sock = app_tcp_create_socket();
		if (handle->sock == -1) {
			status = CCIMP_STATUS_ERROR;
			goto error;
		}

		status = app_tcp_connect(handle->sock, ip_addr);
		if (status != CCIMP_STATUS_OK)
			goto error;
	}

	/* Get socket info of connected interface */
	interface_addr_len = sizeof interface_addr;
	if (getsockname(handle->sock, (struct sockaddr *) &interface_addr, &interface_addr_len)) {
		log_error("Failed to get the socket bound address: %s (%d)", strerror(errno), errno);
		status = CCIMP_STATUS_ERROR;
		goto error;
	}

	status = app_is_tcp_connect_complete(handle->sock);
	if (status == CCIMP_STATUS_OK) {
#if (defined APP_SSL)
		log_debug("%s: opening SSL socket", __func__);
		if (app_ssl_connect(handle)) {
			log_error("%s", "Error establishing SSL connection");
			status = CCIMP_STATUS_ERROR;
			goto error;
		}
#endif /* APP_SSL */
		/* Make it non-blocking now */
		{
			int enabled = 1;

			if (ioctl(handle->sock, FIONBIO, &enabled) < 0) {
				log_error("Error opening connection to '%s': %s (%d)",
					data->device_cloud.url, strerror(errno), errno);
				status = CCIMP_STATUS_ERROR;
				goto error;
			}
		}

		log_info("Connected to %s", data->device_cloud.url);

		return CCIMP_STATUS_OK;
	}

	if (status == CCIMP_STATUS_BUSY) {
		unsigned long elapsed_time;
		ccimp_os_system_up_time_t uptime;

		ccimp_os_get_system_time(&uptime);
		elapsed_time = uptime.sys_uptime - handle->connect_start_time.sys_uptime;

		if (elapsed_time > APP_CONNECT_TIMEOUT) {
			log_error("Error opening connection to '%s': Failed to connect within %d seconds",
					data->device_cloud.url, APP_CONNECT_TIMEOUT);
			status = CCIMP_STATUS_ERROR;
		}
	}

error:
	if (status == CCIMP_STATUS_ERROR) {
		log_error("Failed to connect to %s", data->device_cloud.url);
		dns_set_redirected(0);

		if (handle->sock != -1)
			close(handle->sock);

		free_network_handle(handle);
		data->handle = NULL;
	}

	return status;
}

static int app_tcp_create_socket(void)
{
	int sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

	if (sock >= 0) {
		int enabled = 1;

		if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &enabled, sizeof enabled) < 0)
			log_error("Failed to set socket option SO_KEEPALIVE: %s (%d)", strerror(errno), errno);

		if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof enabled) < 0)
			log_error("Failed to set socket option TCP_NODELAY: %s (%d)", strerror(errno), errno);
	} else {
		log_error("Failed to connect to Remote Manager: %s (%d)", strerror(errno), errno);
	}

	return sock;
}

static ccimp_status_t app_tcp_connect(int const sock, in_addr_t const ip_addr)
{
	struct sockaddr_in sin = { 0 };
	ccimp_status_t status = CCIMP_STATUS_OK;

	memcpy(&sin.sin_addr, &ip_addr, sizeof sin.sin_addr);
#if (defined APP_SSL)
	sin.sin_port = htons(CCIMP_SSL_PORT);
#else /* APP_SSL */
	sin.sin_port = htons(CCIMP_TCP_PORT);
#endif /* APP_SSL */
	sin.sin_family = AF_INET;

	log_debug("%s: sock %d", __func__, sock);

	if (connect(sock, (struct sockaddr *) &sin, sizeof sin) < 0) {
		int const err = errno;

		switch (err) {
			case EINTR:
			case EAGAIN:
			case EINPROGRESS:
				status = CCIMP_STATUS_BUSY;
				break;
			default:
				log_error("Failed to connect to Remote Manager: %s (%d)", strerror(err), err);
				status = CCIMP_STATUS_ERROR;
		}
	}

	return status;
}

static ccimp_status_t app_is_tcp_connect_complete(int const sock)
{
	ccimp_status_t status = CCIMP_STATUS_BUSY;
	struct timeval timeout = { 0 };
	fd_set read_set, write_set;
	int rc;

	FD_ZERO(&read_set);
	FD_SET(sock, &read_set);
	write_set = read_set;

#if (defined APP_SSL)
	/* Wait for 2 seconds to connect */
	timeout.tv_sec = 2;
#endif /* APP_SSL */
	rc = select(sock + 1, &read_set, &write_set, NULL, &timeout);
	if (rc < 0) {
		if (errno != EINTR) {
			log_error("Error on Remote Manager connection: %s (%d)", strerror(errno), errno);
			status = CCIMP_STATUS_ERROR;
		}
	} else {
		/* Check whether the socket is now writable (connection succeeded). */
		if (rc > 0 && FD_ISSET(sock, &write_set)) {
			/* We expect "socket writable" when the connection succeeds. */
			/* If we also got a "socket readable" we have an error. */
			if (FD_ISSET(sock, &read_set)) {
				log_error("Error on Remote Manager connection: %s", "Socket readable");
				status = CCIMP_STATUS_ERROR;
			} else {
				status = CCIMP_STATUS_OK;
			}
		}
	}

	return status;
}

static void free_network_handle(network_handle_t *const handle)
{
#if (defined APP_SSL)
	if (handle != NULL) {
		SSL_free(handle->ssl);
		handle->ssl = NULL;

		SSL_CTX_free(handle->ctx);
		handle->ctx = NULL;
	}
#endif /* APP_SSL */

	free(handle);
}

#if (defined APP_SSL)
#if (defined APP_SSL_CLNT_CERT)
static int get_user_passwd(char *buf, int size, int rwflag, void *password)
{
	char const passwd[] = APP_SSL_CLNT_CERT_PASSWORD;
	int const pwd_bytes = ARRAY_SIZE(passwd) - 1;
	int const copy_bytes = (pwd_bytes < size) ? pwd_bytes : size - 1;

	UNUSED_ARGUMENT(rwflag);
	UNUSED_ARGUMENT(password);

	if (copy_bytes >= 0) {
		memcpy(buf, passwd, copy_bytes);
		buf[copy_bytes] = '\0';
	}

	return copy_bytes;
}
#endif /* APP_SSL_CLNT_CERT */

static int app_load_certificate_and_key(SSL_CTX *const ctx)
{
	int ret = -1;

	ret = SSL_CTX_load_verify_locations(ctx, APP_SSL_CA_CERT_PATH, NULL);
	if (ret != 1) {
		log_error("Error setting up SSL connection: %s", "Failed to load CA cert");
		ERR_print_errors_fp(stderr);
		goto error;
	}

#if (defined APP_SSL_CLNT_CERT)
	SSL_CTX_set_default_passwd_cb(ctx, get_user_passwd);
	ret = SSL_CTX_use_certificate_file(ctx, APP_SSL_CLNT_KEY, SSL_FILETYPE_PEM);
	if (ret != 1) {
		log_error("Error setting up SSL connection: Failed to load '%s' cert", APP_SSL_CLNT_CERT);
		goto error;
	}

	ret = SSL_CTX_use_RSAPrivateKey_file(ctx, APP_SSL_CLNT_CERT, SSL_FILETYPE_PEM);
	if (ret != 1) {
		log_error("Error setting up SSL connection: Failed to load RSA private key (%s)", APP_SSL_CLNT_CERT);
		goto error;
	}
#endif /* APP_SSL_CLNT_CERT */

error:
	return ret;
}

static int app_verify_device_cloud_certificate(SSL *const ssl)
{
	int ret = -1;
	X509 *const device_cloud_cert = SSL_get_peer_certificate(ssl);

	if (device_cloud_cert == NULL) {
		log_error("Error verifying Remote Manager certificate: %s", "Could not load peer certificate");
		goto done;
	}

	ret = SSL_get_verify_result(ssl);
	if (ret != X509_V_OK) {
		log_error("Error verifying Remote Manager certificate: Invalid certificate (%d)", ret);
		goto done;
	}

done:
	X509_free(device_cloud_cert);

	return ret;
}

static int app_ssl_connect(network_handle_t *const handle)
{
	int ret = -1;

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
	handle->ctx = SSL_CTX_new(TLSv1_2_client_method());
#else
	handle->ctx = SSL_CTX_new(TLS_client_method());
#endif
	if (handle->ctx == NULL) {
		log_error("Error setting up SSL connection: %s", "SSL context is NULL");
		ERR_print_errors_fp(stderr);
		goto error;
	}

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
	/*
	 * We need to relax what ciphers are allowed with openssl-3.0 so
	 * that we do not break RM. In the near future they will support
	 * only modern ciphers and we can remove this.
	 */
	SSL_CTX_set_security_level(handle->ctx, 0);
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
	if (!SSL_CTX_set_min_proto_version(handle->ctx, TLS1_2_VERSION)) {
		log_error("Failed to set the minimum protocol version 0x%X",
			 TLS1_2_VERSION);
		goto error; /* FAILED */
	}
#if 0 /* do not enforce an upper bound,  left as an example only */
	if (!SSL_CTX_set_max_proto_version(handle->ctx, TLS1_3_VERSION)) {
		log_error("Failed to set the maximum protocol version 0x%X",
			 TLS1_3_VERSION);
		goto error; /* FAILED */
	}
#endif
#endif

#ifdef CCIMP_CLIENT_CERTIFICATE_CAP_ENABLED
	char *key_filename = get_client_cert_path();

	/* Check if the certificate file exists */
	if (access(key_filename, F_OK) == 0 ) {
		log_debug("Using cert file '%s' for SSL connection", key_filename);
		SSL_CTX_set_verify(handle->ctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_use_certificate_file(handle->ctx, key_filename, SSL_FILETYPE_PEM);
		SSL_CTX_use_PrivateKey_file(handle->ctx, key_filename, SSL_FILETYPE_PEM);
#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
		/*
		 * For OpenSSL >=1.1.1, turn on client cert support which is
		 * otherwise turned off by default (by design).
		 * https://github.com/openssl/openssl/issues/6933
		 */
		SSL_CTX_set_post_handshake_auth(handle->ctx, 1);
#endif
	} else {
		log_debug("Error setting up SSL connection: Certificate file '%s' does not exist. Maybe first connection?",
				key_filename);
	}
#endif /* CCIMP_CLIENT_CERTIFICATE_CAP_ENABLED */
	handle->ssl = SSL_new(handle->ctx);
	if (handle->ssl == NULL) {
		log_error("Error setting up SSL connection: %s", "SSL is NULL");
		ERR_print_errors_fp(stderr);
		goto error;
	}

	SSL_set_fd(handle->ssl, handle->sock);
	if (app_load_certificate_and_key(handle->ctx) != 1)
		goto error;

	SSL_set_options(handle->ssl, SSL_OP_ALL);
	if (SSL_connect(handle->ssl) <= 0) {
		log_error("Error establishing SSL connection: %s (%d)", strerror(errno), errno);
		ERR_print_errors_fp(stderr);
		goto error;
	}

	if (app_verify_device_cloud_certificate(handle->ssl) != X509_V_OK)
		goto error;

	ret = 0;

error:
	return ret;
}
#endif /* APP_SSL */
