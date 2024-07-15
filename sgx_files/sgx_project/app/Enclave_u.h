#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_RUN_SYSTEM_COMMAND_DEFINED__
#define OCALL_RUN_SYSTEM_COMMAND_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_run_system_command, (const char* cmd));
#endif

sgx_status_t run_python_script(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
