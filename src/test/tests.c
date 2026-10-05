/*
 * Copyright 2008-2023 Aerospike, Inc.
 *
 * Portions may be licensed to Aerospike, Inc. under one or more contributor
 * license agreements.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

#include "sa_client.h"
#include "sa_logging.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define SA_MAGIC 0x51dec1cc

#define SECRET "127.0.0.1"
#define SECRET_RESPONSE "{\"SecretValue\":\"MTI3LjAuMC4x\"}"
#define ERROR_RESPONSE "{\"Error\":\"fakesecret not present in file\"}"

#define LEAK_SECRET "s3cr3t-value"
#define LEAK_SECRET_B64 "czNjcjN0LXZhbHVl"

#define TEST_TIMEOUT_S 30
#define CONNECT_TIMEOUT_MS 500
#define TIMING_MARGIN_MS 300
#define MAX_BACKLOG_FILL 64

typedef struct fake_agent_s {
	int fd;
	char port[8];
	SSL_CTX* ctx;
	const char* response;
	char sni[256];
	bool answered;
	pthread_t thread;
} fake_agent;

static const char* g_cert_dir;
static char g_log[16384];
static bool g_skipped;

void mylog(const char* format, ...)
{
	va_list args;
	char line[2048];

	va_start(args, format);
	vsnprintf(line, sizeof(line), format, args);
	va_end(args);

	printf("LOGGED DURING TEST: %s\n", line);
	strncat(g_log, line, sizeof(g_log) - strlen(g_log) - 1);
	strncat(g_log, "\n", sizeof(g_log) - strlen(g_log) - 1);
}

char* readCertFile(const char* name)
{
	char path[1024];
	snprintf(path, sizeof(path), "%s/%s.pem", g_cert_dir, name);

	FILE* fptr;
	long flen;

	fptr = fopen(path, "rb");
	assert(fptr != NULL);
	fseek(fptr, 0, SEEK_END);
	flen = ftell(fptr);
	rewind(fptr);

	char* buff = (char*) malloc(flen+1);
	size_t n = fread(buff, 1, flen, fptr);
	fclose(fptr);

	assert(n == (size_t)flen);
	buff[flen] = 0;

	return buff;
}

//==========================================================
// Fake secret agent.
//

static int
listen_on(const char* ip, int backlog, char* port, size_t port_sz)
{
	struct sockaddr_storage ss;
	struct sockaddr_in* v4 = (struct sockaddr_in*)&ss;
	struct sockaddr_in6* v6 = (struct sockaddr_in6*)&ss;
	socklen_t len;

	memset(&ss, 0, sizeof(ss));

	if (inet_pton(AF_INET, ip, &v4->sin_addr) == 1) {
		v4->sin_family = AF_INET;
		len = sizeof(*v4);
	}
	else if (inet_pton(AF_INET6, ip, &v6->sin6_addr) == 1) {
		v6->sin6_family = AF_INET6;
		len = sizeof(*v6);
	}
	else {
		return -1;
	}

	int fd = socket(ss.ss_family, SOCK_STREAM, 0);

	if (fd < 0) {
		return -1;
	}

	if (bind(fd, (struct sockaddr*)&ss, len) != 0 || listen(fd, backlog) != 0 ||
			getsockname(fd, (struct sockaddr*)&ss, &len) != 0) {
		close(fd);
		return -1;
	}

	in_port_t p = ss.ss_family == AF_INET ? v4->sin_port : v6->sin6_port;
	snprintf(port, port_sz, "%d", ntohs(p));
	return fd;
}

static bool
agent_io(int fd, SSL* ssl, void* buf, size_t n, bool write_buf)
{
	char* p = (char*)buf;
	size_t done = 0;

	while (done < n) {
		int rv;

		if (ssl != NULL) {
			rv = write_buf ? SSL_write(ssl, p + done, (int)(n - done)) :
					SSL_read(ssl, p + done, (int)(n - done));
		}
		else {
			rv = (int)(write_buf ? write(fd, p + done, n - done) :
					read(fd, p + done, n - done));
		}

		if (rv <= 0) {
			return false;
		}

		done += rv;
	}

	return true;
}

static void
agent_answer(fake_agent* a, int fd, SSL* ssl)
{
	if (ssl != NULL) {
		if (SSL_accept(ssl) != 1) {
			return;
		}

		const char* sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
		snprintf(a->sni, sizeof(a->sni), "%s", sni != NULL ? sni : "");
	}

	uint32_t header[2];
	char req[4096];

	if (!agent_io(fd, ssl, header, sizeof(header), false) || ntohl(header[0]) != SA_MAGIC ||
			ntohl(header[1]) > sizeof(req) || !agent_io(fd, ssl, req, ntohl(header[1]), false)) {
		return;
	}

	size_t len = strlen(a->response);

	header[0] = htonl(SA_MAGIC);
	header[1] = htonl((uint32_t)len);

	if (agent_io(fd, ssl, header, sizeof(header), true) &&
			agent_io(fd, ssl, (void*)a->response, len, true)) {
		a->answered = true;
	}
}

static void*
agent_serve(void* arg)
{
	fake_agent* a = (fake_agent*)arg;
	struct pollfd pfd = {
		.fd = a->fd,
		.events = POLLIN
	};

	if (poll(&pfd, 1, 5000) != 1) {
		return NULL;
	}

	int fd = accept(a->fd, NULL, NULL);

	if (fd < 0) {
		return NULL;
	}

	struct timeval tv = { .tv_sec = 5 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	SSL* ssl = NULL;

	if (a->ctx != NULL) {
		ssl = SSL_new(a->ctx);
		SSL_set_fd(ssl, fd);
	}

	agent_answer(a, fd, ssl);

	SSL_free(ssl);
	ERR_clear_error();
	close(fd);
	return NULL;
}

static SSL_CTX*
agent_tls_ctx(const char* name)
{
	char cert[1024];
	char key[1024];

	snprintf(cert, sizeof(cert), "%s/%s.pem", g_cert_dir, name);
	snprintf(key, sizeof(key), "%s/%s-key.pem", g_cert_dir, name);

	SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
	assert(ctx != NULL);

	int cert_rv = SSL_CTX_use_certificate_chain_file(ctx, cert);
	int key_rv = SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM);
	assert(cert_rv == 1 && key_rv == 1);

	return ctx;
}

// Answers one request on ip, over TLS with the named certificate when cert is not NULL.
static bool
agent_start(fake_agent* a, const char* ip, const char* cert, const char* response)
{
	memset(a, 0, sizeof(fake_agent));
	a->response = response;
	a->fd = listen_on(ip, 8, a->port, sizeof(a->port));

	if (a->fd < 0) {
		return false;
	}

	if (cert != NULL) {
		a->ctx = agent_tls_ctx(cert);
	}

	int rv = pthread_create(&a->thread, NULL, agent_serve, a);
	assert(rv == 0);
	return true;
}

static void
agent_stop(fake_agent* a)
{
	pthread_join(a->thread, NULL);
	close(a->fd);
	SSL_CTX_free(a->ctx);
}

//==========================================================
// Helpers.
//

static sa_err
fetch(const char* addr, const char* port, const char* ca_name, bool tls, int timeout,
		const char* path)
{
	sa_cfg cfg;
	sa_cfg_init(&cfg);
	cfg.addr = (char*)addr;
	cfg.port = (char*)port;
	cfg.timeout = timeout;
	cfg.tls.enabled = tls;

	if (ca_name != NULL) {
		cfg.tls.ca_string = readCertFile(ca_name);
	}

	sa_client c;
	sa_client_init(&c, &cfg);

	sa_set_log_function(&mylog);

	size_t result_size = 0;
	uint8_t* secret = NULL;
	sa_err err = sa_secret_get_bytes(&c, path, &secret, &result_size);

	if (err.code == SA_OK) {
		secret[result_size] = 0;
		assert(!strcmp(SECRET, (char*)secret));
		free(secret);
	}

	free(cfg.tls.ca_string);
	return err;
}

static uint64_t
now_ms()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

typedef struct blackhole_s {
	const char* addr;
	char port[8];
	int lfd;
	int fds[MAX_BACKLOG_FILL];
	int n_fds;
} blackhole;

// Returns 1 if a non-blocking connect completes within wait_ms, 0 if it is still pending, -1 if it fails.
static int
connect_probe(const char* addr, const char* port, int wait_ms, int* fdp)
{
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons((uint16_t)atoi(port));
	inet_pton(AF_INET, addr, &sin.sin_addr);

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	assert(fd >= 0);
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
	*fdp = fd;

	if (connect(fd, (struct sockaddr*)&sin, sizeof(sin)) == 0) {
		return 1;
	}

	if (errno != EINPROGRESS) {
		return -1;
	}

	struct pollfd pfd = {
		.fd = fd,
		.events = POLLOUT
	};

	if (poll(&pfd, 1, wait_ms) == 0) {
		return 0;
	}

	int so_err = 0;
	socklen_t len = sizeof(so_err);
	getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &len);

	return so_err == 0 ? 1 : -1;
}

static void
blackhole_stop(blackhole* b)
{
	for (int i = 0; i < b->n_fds; i++) {
		close(b->fds[i]);
	}

	if (b->lfd >= 0) {
		close(b->lfd);
	}

	b->n_fds = 0;
	b->lfd = -1;
}

// Linux drops SYNs once a listener's accept queue is full. macOS resets instead,
// but drops SYNs to 127.0.0.2, which it does not configure on lo0.
static bool
blackhole_start(blackhole* b)
{
	memset(b, 0, sizeof(blackhole));
	b->addr = "127.0.0.1";
	b->lfd = listen_on(b->addr, 1, b->port, sizeof(b->port));
	assert(b->lfd >= 0);

	while (b->n_fds < MAX_BACKLOG_FILL) {
		int rv = connect_probe(b->addr, b->port, 200, &b->fds[b->n_fds++]);

		if (rv == 0) {
			return true;
		}

		if (rv < 0) {
			break;
		}
	}

	blackhole_stop(b);

	const char* others[] = { "127.0.0.2", "192.0.2.1" };

	for (size_t i = 0; i < sizeof(others) / sizeof(others[0]); i++) {
		b->addr = others[i];
		snprintf(b->port, sizeof(b->port), "3005");

		int rv = connect_probe(b->addr, b->port, 200, &b->fds[b->n_fds++]);

		if (rv == 0) {
			return true;
		}

		blackhole_stop(b);
	}

	return false;
}

static void
timed_fetch(const char* addr, const char* port, const char* ca_name, bool tls, int timeout,
		sa_err* err, uint64_t* elapsed_ms)
{
	uint64_t start = now_ms();
	*err = fetch(addr, port, ca_name, tls, timeout, "secrets:pass:pass");
	*elapsed_ms = now_ms() - start;
	printf("elapsed: %llu ms, code: %d\n", (unsigned long long)*elapsed_ms, err->code);
}

// verify_err is the X509_V_ERR_* the client must report, or X509_V_OK when it must succeed.
static void
tls_case(const char* listen_ip, const char* cert, const char* addr, const char* ca_name,
		long verify_err, const char* expected_sni)
{
	fake_agent a;

	if (!agent_start(&a, listen_ip, cert, SECRET_RESPONSE)) {
		printf("SKIPPED: cannot listen on %s\n", listen_ip);
		g_skipped = true;
		return;
	}

	sa_err err = fetch(addr, a.port, ca_name, true, 3000, "secrets:pass:pass");
	agent_stop(&a);

	if (verify_err == X509_V_OK) {
		assert(err.code == SA_OK);
		assert(a.answered);
		assert(!strcmp(expected_sni, a.sni));
		return;
	}

	char line[256];
	snprintf(line, sizeof(line), "ERR: SSL_connect certificate verify failed: %s (%ld)\n",
			X509_verify_cert_error_string(verify_err), verify_err);

	assert(err.code == SA_FAILED_INTERNAL);
	assert(!a.answered);
	assert(strstr(g_log, line) != NULL);
}

//==========================================================
// Tests.
//

void test_sa_secret_get_bytes()
{
	fake_agent a;
	bool started = agent_start(&a, "127.0.0.1", NULL, SECRET_RESPONSE);
	assert(started);

	sa_err err = fetch("127.0.0.1", a.port, NULL, false, 2000, "secrets:pass:pass");
	agent_stop(&a);

	assert(err.code == SA_OK);
	assert(a.answered);
}

void test_sa_secret_get_bytes_bad_address()
{
	// bad ip
	sa_err err = fetch("256.0.0.0", "3005", NULL, false, 2000, "secrets:pass:pass");

	assert(err.code == SA_FAILED_BAD_CONFIG);
}

void test_sa_secret_get_bytes_bad_port()
{
	// bad port
	sa_err err = fetch("127.0.0.1", "0", NULL, false, 2000, "secrets:pass:pass");

	assert(err.code == SA_FAILED_BAD_CONFIG);
}

void test_sa_secret_get_bytes_bad_secret()
{
	fake_agent a;
	bool started = agent_start(&a, "127.0.0.1", NULL, ERROR_RESPONSE);
	assert(started);

	sa_err err = fetch("127.0.0.1", a.port, NULL, false, 1000, "secrets:pass:fakesecret");
	agent_stop(&a);

	assert(err.code == SA_FAILED_BAD_REQUEST);
}

void test_sa_secret_get_bytes_missing_resource_name()
{
	fake_agent a;
	bool started = agent_start(&a, "127.0.0.1", NULL, ERROR_RESPONSE);
	assert(started);

	sa_err err = fetch("127.0.0.1", a.port, NULL, false, 1000, "secrets:pass");
	agent_stop(&a);

	assert(err.code == SA_FAILED_BAD_REQUEST);
}

void test_sa_secret_get_bytes_tls()
{
	tls_case("127.0.0.1", "agent", "localhost", "ca", X509_V_OK, "localhost");
}

void test_tls_ipv4_literal()
{
	tls_case("127.0.0.1", "agent", "127.0.0.1", "ca", X509_V_OK, "");
}

void test_tls_ipv6_literal()
{
	tls_case("::1", "agent", "::1", "ca", X509_V_OK, "");
}

void test_tls_ipv6_literal_bracketed()
{
	tls_case("::1", "agent", "[::1]", "ca", X509_V_OK, "");
}

void test_tls_unrelated_ca()
{
	tls_case("127.0.0.1", "agent", "localhost", "other-ca",
			X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, NULL);
}

void test_tls_no_ca()
{
	tls_case("127.0.0.1", "agent", "localhost", NULL,
			X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, NULL);
}

void test_tls_hostname_mismatch()
{
	tls_case("127.0.0.1", "wrong-name", "localhost", "ca", X509_V_ERR_HOSTNAME_MISMATCH, NULL);
}

void test_tls_ip_not_in_san()
{
	tls_case("127.0.0.1", "wrong-name", "127.0.0.1", "ca", X509_V_ERR_IP_ADDRESS_MISMATCH, NULL);
}

void test_connect_timeout_blackhole()
{
	blackhole b;

	if (!blackhole_start(&b)) {
		printf("SKIPPED: no address that drops SYNs found\n");
		g_skipped = true;
		return;
	}

	printf("blackhole: %s:%s\n", b.addr, b.port);

	sa_err err;
	uint64_t elapsed;
	timed_fetch(b.addr, b.port, NULL, false, CONNECT_TIMEOUT_MS, &err, &elapsed);

	sa_err tls_err;
	uint64_t tls_elapsed;
	timed_fetch(b.addr, b.port, "ca", true, CONNECT_TIMEOUT_MS, &tls_err, &tls_elapsed);

	blackhole_stop(&b);

	assert(err.code == SA_FAILED_TIMEOUT && tls_err.code == SA_FAILED_TIMEOUT);
	assert(elapsed >= CONNECT_TIMEOUT_MS - 10 && elapsed < CONNECT_TIMEOUT_MS + TIMING_MARGIN_MS);
	assert(tls_elapsed >= CONNECT_TIMEOUT_MS - 10 && tls_elapsed < CONNECT_TIMEOUT_MS + TIMING_MARGIN_MS);
	assert(strstr(g_log, "ERR: connect timed out\n") != NULL);
}

// TEST-NET-1 is either blackholed or unreachable, depending on the network.
void test_connect_unroutable_address()
{
	sa_err err;
	uint64_t elapsed;
	timed_fetch("192.0.2.1", "3005", NULL, false, CONNECT_TIMEOUT_MS, &err, &elapsed);

	assert(err.code == SA_FAILED_TIMEOUT || err.code == SA_FAILED_INTERNAL);
	assert(elapsed < CONNECT_TIMEOUT_MS + TIMING_MARGIN_MS);
}

void test_connect_refused_fails_fast()
{
	char port[8];
	int lfd = listen_on("127.0.0.1", 1, port, sizeof(port));
	assert(lfd >= 0);
	close(lfd);

	sa_err err;
	uint64_t elapsed;
	timed_fetch("127.0.0.1", port, NULL, false, 5000, &err, &elapsed);

	char line[128];
	snprintf(line, sizeof(line), "ERR: connect failed: -1, errno: %d\n", ECONNREFUSED);

	assert(err.code == SA_FAILED_INTERNAL);
	assert(elapsed < TIMING_MARGIN_MS);
	assert(strstr(g_log, line) != NULL);
}

void test_tls_handshake_timeout()
{
	char port[8];
	int lfd = listen_on("127.0.0.1", 8, port, sizeof(port));
	assert(lfd >= 0);

	sa_err err;
	uint64_t elapsed;
	timed_fetch("127.0.0.1", port, "ca", true, CONNECT_TIMEOUT_MS, &err, &elapsed);

	close(lfd);

	assert(err.code == SA_FAILED_TIMEOUT);
	assert(elapsed >= CONNECT_TIMEOUT_MS - 10 && elapsed < CONNECT_TIMEOUT_MS + TIMING_MARGIN_MS);
	assert(strstr(g_log, "ERR: socket poll timed out\n") != NULL);
}

void test_bad_response_not_logged()
{
	const char* responses[] = {
		"{\"SecretValue\":\"" LEAK_SECRET_B64,
		"{\"SecretValue\":\"" LEAK_SECRET_B64 "\\q\"}",
		"\"" LEAK_SECRET_B64 "\"",
	};

	for (size_t i = 0; i < sizeof(responses) / sizeof(responses[0]); i++) {
		fake_agent a;
		bool started = agent_start(&a, "127.0.0.1", NULL, responses[i]);
		assert(started);

		g_log[0] = 0;
		sa_err err = fetch("127.0.0.1", a.port, NULL, false, 2000, "secrets:pass:pass");
		agent_stop(&a);

		assert(err.code == SA_FAILED_BAD_REQUEST);
		assert(strstr(g_log, "ERR: failed to parse response JSON line") != NULL);
		assert(strstr(g_log, "czNjcjN0") == NULL);
		assert(strstr(g_log, LEAK_SECRET_B64) == NULL);
		assert(strstr(g_log, LEAK_SECRET) == NULL);
	}
}

typedef void (*test_func)();

void run_test(test_func f, char* name) {
	printf("\nRunning test: %s\n", name);
	g_log[0] = 0;
	alarm(TEST_TIMEOUT_S);
	f();
	alarm(0);
}

int main(int argc, char const *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s <cert-dir from gen-certs.sh>\n", argv[0]);
		return 1;
	}

	g_cert_dir = argv[1];
	setvbuf(stdout, NULL, _IOLBF, 0);
	signal(SIGPIPE, SIG_IGN);

	run_test(&test_sa_secret_get_bytes, "test_sa_secret_get_bytes");
	run_test(&test_sa_secret_get_bytes_bad_address, "test_sa_secret_get_bytes_bad_address");
	run_test(&test_sa_secret_get_bytes_bad_port, "test_sa_secret_get_bytes_bad_port");
	run_test(&test_sa_secret_get_bytes_bad_secret, "test_sa_secret_get_bytes_bad_secret");
	run_test(&test_sa_secret_get_bytes_missing_resource_name, "test_sa_secret_get_bytes_missing_resource_name");
	run_test(&test_sa_secret_get_bytes_tls, "test_sa_secret_get_bytes_tls");
	run_test(&test_tls_ipv4_literal, "test_tls_ipv4_literal");
	run_test(&test_tls_ipv6_literal, "test_tls_ipv6_literal");
	run_test(&test_tls_ipv6_literal_bracketed, "test_tls_ipv6_literal_bracketed");
	run_test(&test_tls_unrelated_ca, "test_tls_unrelated_ca");
	run_test(&test_tls_no_ca, "test_tls_no_ca");
	run_test(&test_tls_hostname_mismatch, "test_tls_hostname_mismatch");
	run_test(&test_tls_ip_not_in_san, "test_tls_ip_not_in_san");
	run_test(&test_connect_timeout_blackhole, "test_connect_timeout_blackhole");
	run_test(&test_connect_unroutable_address, "test_connect_unroutable_address");
	run_test(&test_connect_refused_fails_fast, "test_connect_refused_fails_fast");
	run_test(&test_tls_handshake_timeout, "test_tls_handshake_timeout");
	run_test(&test_bad_response_not_logged, "test_bad_response_not_logged");

	printf("TESTS SUCCEEDED%s\n", g_skipped ? " (some skipped)" : "");

	return 0;
}
