#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ocall_run_system_command_t {
	const char* ms_cmd;
} ms_ocall_run_system_command_t;

static sgx_status_t SGX_CDECL Enclave_ocall_run_system_command(void* pms)
{
	ms_ocall_run_system_command_t* ms = SGX_CAST(ms_ocall_run_system_command_t*, pms);
	ocall_run_system_command(ms->ms_cmd);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	1,
	{
		(void*)Enclave_ocall_run_system_command,
	}
};
sgx_status_t run_python_script(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, NULL);
	return status;
}

