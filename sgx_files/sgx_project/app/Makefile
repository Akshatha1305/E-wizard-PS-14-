SGX_SDK ?= /home/gat/intel/sgx_project/sgxsdk
SGX_MODE ?= HW

CXX = g++
SGX_COMMON_FLAGS = -m64 -O2 -Wall
SGX_URTS_LIB_PATH = $(SGX_SDK)/lib64
SGX_INCLUDE_PATH = $(SGX_SDK)/include

Enclave_U_C_Files = Enclave_u.c
Enclave_U_H_Files = Enclave_u.h

App_Source_Files = App.cpp

App_Include_Paths = -I$(SGX_INCLUDE_PATH)

App_Link_Flags = -L$(SGX_URTS_LIB_PATH) -lsgx_urts -lpthread

App_Object = app

all: $(App_Object)

$(App_Object): $(App_Source_Files) $(Enclave_U_C_Files)
	$(CXX) $(SGX_COMMON_FLAGS) $(App_Include_Paths) $(App_Source_Files) $(Enclave_U_C_Files) -o $(App_Object) $(App_Link_Flags)

clean:
	rm -f $(App_Object) $(Enclave_U_C_Files) $(Enclave_U_H_Files)

