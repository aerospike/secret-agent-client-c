#include "sc_client.h"
#include "sc_logging.h"

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>

#define AGENT_ADDR "0.0.0.0"
#define AGENT_PORT "3005"

#define AGENT_ADDR_TLS "0.0.0.0"
#define AGENT_PORT_TLS "3006"

void mylog(const char* format, ...)
{
    va_list args;

    printf("LOGGED DURING TEST: ");
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
}

char* readCertFile(const char* path)
{
    FILE* fptr;
    long flen;

    fptr = fopen(path, "rb");
    fseek(fptr, 0, SEEK_END);
    flen = ftell(fptr);
    rewind(fptr);

    char* buff = (char*) malloc(flen * sizeof(char));
    fread(buff, flen, 1, fptr);
    fclose(fptr);

    return buff;
}

void test_sc_secret_get_bytes()
{
    const char* expected = "127.0.0.1";

    char* addr = AGENT_ADDR;
    char* port = AGENT_PORT;

    sc_cfg cfg;
    sc_cfg_init(&cfg);
    cfg.addr = addr;
    cfg.port = port;
    cfg.timeout = 2000;

    sc_client c;
    sc_client_init(&c, &cfg);

    sc_set_log_function(&mylog);

    const char* path = "secrets:pass:pass";
    size_t result_size = 0;

    uint8_t* secret;
    sc_err err = sc_secret_get_bytes(&c, path, &secret, &result_size);
    
    assert(err.code == SC_OK);

    secret[result_size] = 0;
    assert(!strcmp(expected, (char*)secret));

    free(secret);
}

void test_sc_secret_get_bytes_bad_address()
{
    // bad ip
    char* addr = "256.0.0.0";
    char* port = AGENT_PORT;

    sc_cfg cfg;
    sc_cfg_init(&cfg);
    cfg.addr = addr;
    cfg.port = port;
    cfg.timeout = 2000;

    sc_client c;
    sc_client_init(&c, &cfg);

    sc_set_log_function(&mylog);

    const char* path = "secrets:pass:pass";
    size_t result_size = 0;

    uint8_t* secret;
    sc_err err = sc_secret_get_bytes(&c, path, &secret, &result_size);
    
    assert(err.code == SC_FAILED_INTERNAL);
}

void test_sc_secret_get_bytes_bad_port()
{
    char* addr = AGENT_ADDR;
    // bad port
    char* port = "0";

    sc_cfg cfg;
    sc_cfg_init(&cfg);
    cfg.addr = addr;
    cfg.port = port;
    cfg.timeout = 2000;

    sc_client c;
    sc_client_init(&c, &cfg);

    sc_set_log_function(&mylog);

    const char* path = "secrets:pass:pass";
    size_t result_size = 0;

    uint8_t* secret;
    sc_err err = sc_secret_get_bytes(&c, path, &secret, &result_size);
    
    assert(err.code == SC_FAILED_INTERNAL);
}

void test_sc_secret_get_bytes_bad_secret()
{
    char* addr = AGENT_ADDR;
    // bad port
    char* port = AGENT_PORT;

    sc_cfg cfg;
    sc_cfg_init(&cfg);
    cfg.addr = addr;
    cfg.port = port;
    cfg.timeout = 1000;

    sc_client c;
    sc_client_init(&c, &cfg);

    sc_set_log_function(&mylog);

    const char* path = "secrets:pass:fakesecret";
    size_t result_size = 0;

    uint8_t* secret;
    sc_err err = sc_secret_get_bytes(&c, path, &secret, &result_size);
    
    assert(err.code == SC_FAILED_REQUEST);
}

void test_sc_secret_get_bytes_missing_resource_name()
{
    char* addr = AGENT_ADDR;
    // bad port
    char* port = AGENT_PORT;

    sc_cfg cfg;
    sc_cfg_init(&cfg);
    cfg.addr = addr;
    cfg.port = port;
    cfg.timeout = 1000;

    sc_client c;
    sc_client_init(&c, &cfg);

    sc_set_log_function(&mylog);

    const char* path = "secrets:pass";
    size_t result_size = 0;

    uint8_t* secret;
    sc_err err = sc_secret_get_bytes(&c, path, &secret, &result_size);
    
    assert(err.code == SC_FAILED_REQUEST);
}

void test_sc_secret_get_bytes_tls()
{
    const char* expected = "127.0.0.1";

    char* addr = AGENT_ADDR_TLS;
    char* port = AGENT_PORT_TLS;

    const char* capath = "./src/test/test-data/cacert.pem";
    char* cacert = NULL;
    cacert = readCertFile(capath);

    sc_cfg cfg;
    sc_cfg_init(&cfg);
    cfg.addr = addr;
    cfg.port = port;
    cfg.timeout = 3000;
    cfg.tls.ca_string = cacert;
    cfg.tls.enabled = true;

    sc_client c;
    sc_client_init(&c, &cfg);

    sc_set_log_function(&mylog);

    const char* path = "secrets:pass:pass";
    size_t result_size = 0;

    uint8_t* secret;
    sc_err err = sc_secret_get_bytes(&c, path, &secret, &result_size);
    
    assert(err.code == SC_OK);

    secret[result_size] = 0;
    assert(!strcmp(expected, (char*)secret));

    free(secret);
}

typedef void (*test_func)();

void run_test(test_func f, char* name) {
    printf("\nRunning test: %s\n", name);
    f();
}

int main(int argc, char const *argv[])
{
    run_test(&test_sc_secret_get_bytes, "test_sc_secret_get_bytes");
    run_test(&test_sc_secret_get_bytes_bad_address, "test_sc_secret_get_bytes_bad_address");
    run_test(&test_sc_secret_get_bytes_bad_port, "test_sc_secret_get_bytes_bad_port");
    run_test(&test_sc_secret_get_bytes_bad_secret, "test_sc_secret_get_bytes_bad_secret");
    run_test(&test_sc_secret_get_bytes_missing_resource_name, "test_sc_secret_get_bytes_missing_resource_name");
    run_test(&test_sc_secret_get_bytes_tls, "test_sc_secret_get_bytes_tls");

    printf("TESTS SUCCEEDED\n");

    return 0;
}
