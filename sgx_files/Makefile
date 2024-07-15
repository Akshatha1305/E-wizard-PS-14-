# Define SGX SDK path
SGX_SDK ?= /home/gat/intel/sgx_project/sgxsdk

Enclave_Cpp_Files := Enclave.cpp
Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx

Enclave_Link_Flags := -L$(SGX_SDK)/lib64 -lsgx_trts -lsgx_tservice -fPIC

EDL_FILE := Enclave.edl

TRUSTED_DIR := .
UNTRUSTED_DIR := ../App

ENCLAVE_TRUSTED_FILES := Enclave_t.c Enclave_t.h
ENCLAVE_UNTRUSTED_FILES := $(UNTRUSTED_DIR)/Enclave_u.c $(UNTRUSTED_DIR)/Enclave_u.h

all: $(ENCLAVE_UNTRUSTED_FILES) $(SIGNED_ENCLAVE_OBJECT) ../App/app

$(ENCLAVE_OBJECT): $(ENCLAVE_TRUSTED_FILES) $(Enclave_Cpp_Files)
	$(CXX) $(SGX_T_CFLAGS) $(Enclave_Include_Paths) -shared -o $@ $(Enclave_Cpp_Files) $(SGX_T_LDFLAGS) $(Enclave_Link_Flags)

$(SIGNED_ENCLAVE_OBJECT): $(ENCLAVE_OBJECT)
	$(SGX_SDK)/bin/x64/sgx_sign sign -key $(SGX_SIGNER_KEY) -enclave $< -out $@ -config $(SGX_ENCLAVE_CONFIG)

$(ENCLAVE_TRUSTED_FILES): $(EDL_FILE)
	$(SGX_SDK)/bin/x64/sgx_edger8r --trusted $< --search-path $(SGX_SDK)/include --search-path $(TRUSTED_DIR)

$(ENCLAVE_UNTRUSTED_FILES): $(EDL_FILE)
	$(SGX_SDK)/bin/x64/sgx_edger8r --untrusted $< --search-path $(SGX_SDK)/include --search-path $(UNTRUSTED_DIR)
	mv Enclave_u.h $(UNTRUSTED_DIR)/Enclave_u.h
	mv Enclave_u.c $(UNTRUSTED_DIR)/Enclave_u.c

../App/app: $(ENCLAVE_UNTRUSTED_FILES) ../App/App.cpp
	$(CXX) $(SGX_COMMON_CFLAGS) -o $@ ../App/App.cpp $(ENCLAVE_UNTRUSTED_FILES) -I$(SGX_SDK)/include -L$(SGX_SDK)/lib64 -lsgx_urts -lpthread

clean:
	rm -f $(ENCLAVE_TRUSTED_FILES) $(ENCLAVE_UNTRUSTED_FILES) $(ENCLAVE_OBJECT) $(SIGNED_ENCLAVE_OBJECT) ../App/app

