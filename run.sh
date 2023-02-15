#!/bin/bash

cd Enclave_A
make clean
make SGX_MODE=SIM

cd ../Enclave_B
make clean
make SGX_MODE=SIM

cd ..
(cd Enclave_A; ./app &)
(cd Enclave_B; ./app)