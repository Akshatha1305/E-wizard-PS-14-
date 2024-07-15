SGX_SDK ?= /home/gat/intel/sgx_project/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64

SGX_COMMON_CFLAGS := -m64 -fPIC
SGX_T_CFLAGS := $(SGX_COMMON_CFLAGS)
SGX_T_CFLAGS += -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections
SGX_T_CFLAGS += -fstack-protector
SGX_T_CFLAGS += -I$(SGX_SDK)/include
SGX_T_CFLAGS += -I$(SGX_SDK)/include/tlibc
SGX_T_CFLAGS += -I$(SGX_SDK)/include/libcxx
SGX_T_CFLAGS += -I. -I/usr/include -I/usr/include/x86_64-linux-gnu  # Include standard library paths

SGX_T_LDFLAGS := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles
SGX_T_LDFLAGS += -L$(SGX_SDK)/lib64 -lsgx_trts -L$(SGX_SDK)/lib64/tlibc -lsgx_tstdc
SGX_T_LDFLAGS += -L$(SGX_SDK)/lib64/libcxx -lsgx_tcxx -Wl,--whole-archive -lsgx_tservice -Wl,--no-whole-archive

SGX_ENCLAVE_CONFIG := Enclave.config.xml
SGX_ENCLAVE_SIGNER_KEY := $(SGX_SDK)/bin/private.pem

ENCLAVE_OBJECT := enclave.so
SIGNED_ENCLAVE_OBJECT := enclave.signed.so
