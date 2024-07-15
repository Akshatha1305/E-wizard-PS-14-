#include <stdio.h>
#include "Enclave_u.h"
#include <sgx_urts.h>
#include <iostream>

#define ENCLAVE_FILENAME "../Enclave/enclave.signed.so"
#define SGX_DEBUG_FLAG 1

void ocall_print_string(const char *str) {
    printf("%s", str);
}



void ocall_run_system_command(const char* command) {
    if (command) {
        system(command);
    }
}

int main() {
    sgx_enclave_id_t eid;
    sgx_status_t ret = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Failed to create enclave\n");
        return -1;
    }

    sgx_status_t status = run_python_script(eid);
    if (status != SGX_SUCCESS) {
        printf("ECALL failed\n");
    }

    sgx_destroy_enclave(eid);
    return 0;
}
