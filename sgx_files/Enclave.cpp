#include "Enclave_t.h"

void run_python_script() {
    const char* cmd = "/home/gat/intel/sgx_project/script.py";
    ocall_run_system_command(cmd);
}
