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

## Testing
Testing requires that the Aerospike Secret Agent is running on the host machine at 0.0.0.0:3005
and another secret agent configured for TLS at 0.0.0.0:3006.
If you need to change this address you can edit the src/test/tests.c file to point to a different endpoint.