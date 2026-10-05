# Secrets Client C

The secret-agent-client-c library is a C client for the [Aerospike Secret Agent](https://docs.aerospike.com/tools/secret-agent).
It is used to request secrets from the secret agent.

## Building
Dependencies
 - [jansson](https://github.com/akheron/jansson)
 - [openssl1.1 or greater](https://github.com/openssl/openssl)

This client is built using make. Clone this repo, cd into it, and run `make`

Shared and static libraries will be output in target/<platform>/lib

## Usage
Make use of the secret client through the APIs exposed in sa_client.h.

Start by creating and configuring a secret agent client, `sa_client` using `sa_client_init()` or `sa_client_new()`.

Request secrets using `sa_secret_get_bytes()`.

**_NOTE:_**  Returned secrets always have an extra byte added to the end in case they are strings
and the caller needs to null terminate them. Secrets are not automatically null terminated.

Logging is disabled by default but can be enabled by passing a
pointer to a function of type `sa_log_func` to the `sa_set_log_function` function.
Log lines do not include request or response bytes, except the error message the agent returns
in its `Error` field.

### Timeouts
`sa_cfg.timeout` is in milliseconds.

- Connecting gets one budget of `timeout`. It covers the TCP connect, trying each address that
  `addr` resolves to in turn while time remains, plus the TLS handshake.
  An agent address that never answers fails with `SA_FAILED_TIMEOUT` after about `timeout`.
- Each wait while sending the request and reading the response then gets its own `timeout`.
- Signals that interrupt a wait do not shorten or extend it.
- DNS resolution (`getaddrinfo`) is blocking and is not covered by the timeout.
- `0` fails at once with `SA_FAILED_TIMEOUT`, without connecting.
- A negative value means no limit: connecting, the handshake and every wait can block forever.

## Examples
Request a secret over TCP with logging.
Log function.
```c
void mylog(const char* format, ...)
{
    va_list args;

    printf("LOGGED DURING TEST: ");
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
}
```
Main.
```c
    const char* addr = "127.0.0.1";
    const char* port = "3005";

    sa_cfg cfg;
    sa_cfg_init(&cfg);
    cfg.addr = addr;
    cfg.port = port;
    cfg.timeout = 2000;

    sa_client c;
    sa_client_init(&c, &cfg);

    sa_set_log_function(&mylog);

    const char* path = "secrets:<resource_key>:<secret_key>";
    size_t result_size = 0;

    uint8_t* secret;
    sa_err err = sa_secret_get_bytes(&c, path, &secret, &result_size);
    
    assert(err.code == SA_OK);

    // null terminate the secret for use as a string
    secret[result_size] = 0;
    printf("secret: %s\n", (char*)secret);
    free(secret);
```

Request a secret over TCP with TLS and logging.
The agent's certificate must cover `addr`, here with an `IP:127.0.0.1` subject alternative name.
See [TLS certificate verification](#tls-certificate-verification).
```c
    const char* addr = "127.0.0.1";
    const char* port = "3005";

    const char* capath = "./path/to/cacert.pem";
    char* cacert = NULL;
    // read_cert_file reads out the entire cert file
    cacert = read_cert_file(capath);

    sa_cfg cfg;
    sa_cfg_init(&cfg);
    cfg.addr = addr;
    cfg.port = port;
    cfg.timeout = 3000;
    cfg.tls.ca_string = cacert;
    cfg.tls.enabled = true;

    sa_client c;
    sa_client_init(&c, &cfg);

    sa_set_log_function(&mylog);

    const char* path = "secrets:<resource_key>:<secret_key>";
    size_t result_size = 0;

    uint8_t* secret;
    sa_err err = sa_secret_get_bytes(&c, path, &secret, &result_size);
    
    assert(err.code == SA_OK);

    // null terminate the secret for use as a string
    secret[result_size] = 0;
    printf("secret: %s\n", (char*)secret);
    free(secret);
```

## TLS certificate verification
When `tls.enabled` is set, the client verifies the Secret Agent's certificate during the
TLS handshake and fails the request if verification fails.

- The certificate must chain to a CA in `tls.ca_string`. The system trust store is not used,
  so a TLS client without `tls.ca_string` always fails.
- The certificate must cover `addr`, the address the client connects to.
  A host name is matched against the certificate's DNS names, ignoring one trailing dot
  (`localhost.` matches `localhost`). Partial wildcards such as `a*.example.com` do not match.
  An IPv4 or IPv6 literal, with or without brackets (`::1` or `[::1]`), must match an IP address
  subject alternative name. An IPv6 zone is ignored, so `fe80::1%lo0` must match `IP:fe80::1`.
- The host name is sent as SNI. IP literals are not.

On failure the reason, for example `hostname mismatch`, `IP address mismatch` or
`unable to get local issuer certificate`, is logged through the log function.

**_Breaking change:_** earlier versions did not verify the agent's certificate at all,
so any certificate was accepted. These setups now fail with `SA_FAILED_INTERNAL`.
Verification cannot be turned off.

- Connecting by an address the certificate does not cover, such as `0.0.0.0` with a certificate
  issued for `localhost`. Connect using a name or IP address listed in the certificate, or reissue
  the certificate with a matching subject alternative name.
- Connecting to an IPv4-mapped IPv6 address such as `::ffff:127.0.0.1`. It is checked as an IPv6
  address, so the certificate needs `IP:::ffff:127.0.0.1`; `IP:127.0.0.1` does not match.
- Pointing `tls.ca_string` at the agent's own certificate when a CA issued that certificate.
  Use the issuing CA. The agent's certificate works as `tls.ca_string` only if it is self-signed.
- An expired or not yet valid agent certificate.

A certificate with no subject alternative names at all is still accepted when its subject
common name matches the host name. This is OpenSSL's fallback for such certificates.

## Testing
`make test` builds the library and `src/test/tests`, generates throwaway certificates into
`target/<platform>/test-certs` with `src/test/gen-certs.sh`, and runs the tests.

The tests start an in-process fake Secret Agent (plain TCP and TLS) on the loopback interface,
so no real agent or network access is needed. The IPv6 cases are skipped when `::1` is unavailable,
and the end-to-end scoped IPv6 case when the loopback interface has no `fe80::1` (macOS has it,
Linux usually does not). The test binary wraps `socket()` to slow down connecting, which works
because the library is linked into it statically.

Requirements: a C compiler, make, jansson, and OpenSSL including the `openssl` command line tool.
On macOS the Makefile uses Homebrew under `/opt/homebrew`.

To run the tests on Linux in Docker from the repository root:
```sh
docker run --rm -v "$PWD":/src:ro ubuntu:24.04 sh -c '
apt-get update && apt-get install -y build-essential libssl-dev libjansson-dev openssl &&
cp -r /src /build && cd /build && rm -rf target src/test/tests && make test'

docker run --rm -v "$PWD":/src:ro rockylinux:8 sh -c '
dnf install -y dnf-plugins-core && dnf config-manager --set-enabled powertools &&
dnf install -y gcc make openssl openssl-devel jansson-devel &&
cp -r /src /build && cd /build && rm -rf target src/test/tests && make test'
```