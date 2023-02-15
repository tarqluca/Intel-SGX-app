#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include "sgx_tcrypto.h"
#include "sgx_trts.h"

int enclave_secret = 1337;

// private to enclave
static sgx_ecc_state_handle_t handle;
static sgx_ec256_private_t encl_sk;
static sgx_ec256_public_t encl_pk;
static sgx_ec256_dh_shared_t encl_K;
static sgx_aes_ctr_128bit_key_t half_key;
static int a, b;

static uint8_t IV[16] = {0};  // set IV to zero --> not required to make it more complex

/*************************
 * BEGIN [2. E_A generates keypair]
 *************************/
//Based on question: https://stackoverflow.com/questions/42015168/sgx-ecc256-create-key-pair-fail
sgx_status_t create_key_pair(sgx_ec256_public_t *pk){
  sgx_status_t status;

  status = sgx_ecc256_open_context(&handle);
  if (status != SGX_SUCCESS){
    return status;  // Don't go further and return the exception
  }

  status = sgx_ecc256_create_key_pair(&encl_sk, &encl_pk, handle);
  if (status != SGX_SUCCESS){
    return status;
  }

  memcpy(pk, &encl_pk, sizeof(sgx_ec256_public_t));
  
  return status;  //SGX_SUCCESS
}
/*************************
 * END [2. E_A generates keypair]
 *************************/

/*************************
 * BEGIN [3. E_A computes shared DH key]
 *************************/
sgx_status_t compute_shared_key(sgx_ec256_public_t *pk_other){
  sgx_status_t status;

  status = sgx_ecc256_compute_shared_dhkey(&encl_sk, pk_other, &encl_K, handle);

  memcpy(half_key, encl_K.s, 16); //pick first 128 bits --> 16 bytes
  
  return status;
}
/*************************
 * END [3. E_A computes shared DH key]
 *************************/

/*************************
 * BEGIN [3. E_A computes encrypted PSK]
 *************************/
sgx_status_t getPSK(uint8_t *output_stream, size_t len){
  
  uint8_t PSK_A[] = "I AM ALICE";
  sgx_status_t status;

  status = sgx_aes_ctr_encrypt(&half_key, PSK_A, len, IV, 128, output_stream);

  return status;
}
/*************************
 * END [3. E_A computes encrypted PSK]
 *************************/

/*************************
 * BEGIN [3. E_A checks received encrypted PSK]
 *************************/
sgx_status_t checkPSK(uint8_t *input_stream, size_t len, int *cmp){
  
  uint8_t PSK_B[] = "I AM BOBOB";
  sgx_status_t status;

  uint8_t plaintext[11];  //PSK_LEN

  status = sgx_aes_ctr_decrypt(&half_key, input_stream, len, IV, 128, plaintext);

  if(status != SGX_SUCCESS) 
    return status;
  
  if(strcmp((char*)plaintext, (char*)PSK_B))
    *cmp = 0;
  else
    *cmp = 1;
  
  return status;
}
/*************************
 * END [3. E_A checks received encrypted PSK]
 *************************/

/*************************
* BEGIN [4. E_A generates and encrypts the challenge]
*************************/
sgx_status_t getEncryptedChallenge(uint8_t *c, size_t len){
  sgx_status_t status;

  status = sgx_read_rand((unsigned char*)&a, sizeof(int));
  if(status != SGX_SUCCESS)
    return status;
  
  status = sgx_read_rand((unsigned char*)&b, sizeof(int));
  if(status != SGX_SUCCESS)
    return status;

  // a || b
  uint8_t *p = (uint8_t*) malloc(2*sizeof(int));
  memcpy(p, &a, sizeof(int));
  memcpy(p+sizeof(int), &b, sizeof(int));

  status = sgx_aes_ctr_encrypt(&half_key, p, len, IV, 128, c);
  free(p);
  if(status != SGX_SUCCESS)
    return status;
  
  return status;
}
/*************************
* END [4. E_A generates and encrypts the challenge]
*************************/

/*************************
* BEGIN [5. E_A decrypts and verifies the response]
*************************/
sgx_status_t checkResult(uint8_t *result, size_t len, int *valid){
  sgx_status_t status;
  int p;

  status = sgx_aes_ctr_decrypt(&half_key, result, len, IV, 128, (uint8_t*)&p);
  if(status != SGX_SUCCESS)
    return status;
  
  if(a+b==p)
    *valid = 1;
  else
    *valid = 0;
  
  return status;
}
/*************************
* END [5. E_A decrypts and verifies the response]
*************************/

int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

sgx_status_t printSecret()
{
  char buf[BUFSIZ] = {"From Enclave: Hello from the enclave.\n"};
  ocall_print_string(buf);
  printf("From Enclave: Another way to print from the Enclave. My secret is %u.\n", enclave_secret);
  return SGX_SUCCESS;
}
