SGX_SDK ?= /home/gat/intel/sgx_project/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64

SGX_COMMON_CFLAGS := -m64
SGX_U_CFLAGS := $(SGX_COMMON_CFLAGS)
SGX_U_CFLAGS += -I$(SGX_SDK)/include
SGX_U_CFLAGS += -I$(SGX_SDK)/include/tlibc
SGX_U_CFLAGS += -I$(SGX_SDK)/include/libcxx

SGX_U_LDFLAGS := $(SGX_COMMON_CFLAGS)
SGX_U_LDFLAGS += -L$(SGX_SDK)/lib64 -lsgx_urts -L$(SGX_SDK)/lib64/tlibc -lsgx_ustdc
SGX_U_LDFLAGS += -L$(SGX_SDK)/lib64/libcxx -lsgx_ucxx -lpthread -lrt
