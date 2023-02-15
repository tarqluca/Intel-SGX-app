#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>

#include <sys/socket.h> /* socket, connect, close */
#include <sys/un.h>

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#define PSK_LEN 11
#define CHALLENGE_LEN 2*sizeof(int)
#define RESULT_LEN sizeof(int)
#define ATTEMPTS 20
#define DBG 0

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

// Based on: https://www.softprayog.in/programming/interprocess-communication-using-unix-domain-sockets
// Based on: https://stackoverflow.com/questions/5592747/bind-error-while-recreating-socket
// Based on: https://stackoverflow.com/questions/24194961/how-do-i-use-setsockoptso-reuseaddr
int init_socket() {

    int fd_new;

    struct stat statbuf;
    if (stat("/tmp/enclave.socket", &statbuf) == 0) {
        if (unlink("/tmp/enclave.socket") == -1){
	        perror("unlink");
            return -1;
        }
    }
    
    int listener;
    if ((listener = socket(AF_UNIX, SOCK_SEQPACKET, 0)) == -1){
	    perror("socket");
        return -1;
    }

    struct sockaddr_un socket_address;

    memset(&socket_address, 0, sizeof (struct sockaddr_un));
    socket_address.sun_family = AF_UNIX;
    strncpy(socket_address.sun_path, "/tmp/enclave.socket", sizeof(socket_address.sun_path) - 1);

    if (bind(listener, (const struct sockaddr *) &socket_address, sizeof (struct sockaddr_un)) == -1){
        perror("bind");
        return -1;
    }

    // Mark socket for accepting incoming connections using accept
    if (listen (listener, 10) == -1){
        perror("listen");
        return -1;
    }

    const int enable = 1;
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0){
        perror("setsockopt(SO_REUSEADDR) failed");
        return -1;
    }

    if ((fd_new = accept(listener, NULL, NULL)) == -1){
        perror("accept");
        return -1;
    }

    return fd_new;
}

/*************************
 * BEGIN [1. A_B sends information to A_A]
 *************************/
// Based on: https://www.softprayog.in/programming/interprocess-communication-using-unix-domain-sockets
void send(int fd, char* str, int size){
    if(write(fd, str, size) == -1) {
        perror("write");
        exit(-1);
    }
}
/*************************
 * END [1. A_B sends information to A_A]
 *************************/

/*************************
 * BEGIN [1. A_B receives information from A_A]
 *************************/
// Based on: https://www.softprayog.in/programming/interprocess-communication-using-unix-domain-sockets
void receive(int fd, char* str, int size){
    if(read(fd, str, size) == -1) {
        perror("read");
        exit(-1);
    }
}
/*************************
 * END [1. A_B receives information from A_A]
 *************************/

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);
    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enclave initialization failed.\n");
        return -1;
    }
    printf("From App B: Enclave creation success. \n");

    sgx_status_t sgx_status;

    int fd_new = init_socket();
    if(fd_new < 0) {
        printf("Socket initialization failed.\n");
        return -1;
    }

    /*************************
    * BEGIN [2. E_B generates keypair]
    *************************/
    sgx_ec256_public_t pk;
    create_key_pair(global_eid, &sgx_status, &pk);  // use enclave return ([out] arguments)
    if(sgx_status != SGX_SUCCESS){
        print_error_message(sgx_status);
        return -1;
    }
    /*************************
    * END [2. E_B generates keypair]
    *************************/

    #if DBG
        FILE* fd;
        fd = fopen("bob_output", "w+");

        fprintf(fd, "Bob's pk.gx: ");
        for(int i = 0; i < 32; i++) //256 bits --> 32 bytes
            fprintf(fd, "%02x", pk.gx[i]);
        
        fprintf(fd, "\n");
        fprintf(fd, "Bob's pk.gy: ");
        for(int i = 0; i < 32; i++)
            fprintf(fd, "%02x", pk.gy[i]);
    #endif

    #if DBG
        fprintf(fd, "\nReceive pk from Alice\n");
    #endif
    /*************************
    * BEGIN [1. A_B receives public key from A_A]
    *************************/
    sgx_ec256_public_t alice_pk;
    receive(fd_new, (char*)&alice_pk, sizeof(sgx_ec256_public_t));
    /*************************
    * END [1. A_B receives public key from A_A]
    *************************/

    #if DBG
        fprintf(fd, "Alice's pk.gx: ");
        for(int i = 0; i < 32; i++)
            fprintf(fd, "%02x", alice_pk.gx[i]);

        fprintf(fd, "\n");
        fprintf(fd, "Alice's pk.gy: ");
        for(int i = 0; i < 32; i++)
            fprintf(fd, "%02x", alice_pk.gy[i]);
    #endif

    #if DBG
        fprintf(fd, "\nComputing shared key: ");
    #endif
    /*************************
    * BEGIN [3. E_B computes shared DH key]
    *************************/
    compute_shared_key(global_eid, &sgx_status, &alice_pk);
    if(sgx_status != SGX_SUCCESS){
        print_error_message(sgx_status);
        return -1;
    }
    /*************************
    * END [3. E_B computes shared DH key]
    *************************/
    #if DBG
        fprintf(fd, "success\n");
    #endif

    #if DBG
        fprintf(fd, "Send pk to Alice\n");
    #endif
    /*************************
    * BEGIN [1. A_B sends public key to A_A]
    *************************/
    send(fd_new, (char*)&pk, sizeof(sgx_ec256_public_t));
    /*************************
    * END [1. A_B sends public key to A_A]
    *************************/

    #if DBG
        fprintf(fd, "Receive encrypted PSK from Alice\n");
    #endif
    /*************************
    * BEGIN [1. A_B receives encrypted PSK from A_A]
    *************************/
    uint8_t psk_a[PSK_LEN];
    receive(fd_new, (char*)psk_a, PSK_LEN);
    /*************************
    * END [1. A_B receives encrypted PSK from A_A]
    *************************/

    #if DBG
        fprintf(fd, "Alice's encrypted PSK: ");
        for(int i = 0; i < PSK_LEN; i++)
            fprintf(fd, "%02x", psk_a[i]);
    #endif

    #if DBG
        fprintf(fd, "\nChecking Alice's encrypted PSK: ");
    #endif
    /*************************
    * BEGIN [3. E_B checks received encrypted PSK]
    *************************/
    int cmp = 0;
    checkPSK(global_eid, &sgx_status, psk_a, PSK_LEN, &cmp);
    if(sgx_status != SGX_SUCCESS){
        print_error_message(sgx_status);
        return -1;
    }
    if(cmp == 0){
        printf("Not matching PSK!");
        return -1;
    }
    /*************************
    * END [3. E_B checks received encrypted PSK]
    *************************/
    #if DBG
        fprintf(fd, "success\n");
    #endif

    #if DBG
        fprintf(fd, "Computing Bob's encrypted PSK: ");
    #endif
    /*************************
    * BEGIN [3. E_B computes encrypted PSK]
    *************************/
    uint8_t psk_b[PSK_LEN];    //I AM BOBOB has length 11 (including \0)
    getPSK(global_eid, &sgx_status, psk_b, PSK_LEN);
    if(sgx_status != SGX_SUCCESS){
        print_error_message(sgx_status);
        return -1;
    }
    /*************************
    * END [3. E_B computes encrypted PSK]
    *************************/
    #if DBG
        fprintf(fd, "success\n");
    #endif

    #if DBG
        fprintf(fd, "Bob's encrypted PSK: ");
        for(int i = 0; i < PSK_LEN; i++)
            fprintf(fd, "%02x", psk_b[i]);
    #endif

    #if DBG
        fprintf(fd, "\nSend encrypted PSK to Alice\n");
    #endif
    /*************************
    * BEGIN [1. A_B sends encrypted PSK to A_A]
    *************************/
    send(fd_new, (char*)psk_b, PSK_LEN);
    /*************************
    * END [1. A_B sends encrypted PSK to A_A]
    *************************/

    uint8_t *c = (uint8_t*)malloc(CHALLENGE_LEN);
    uint8_t *result = (uint8_t*)malloc(RESULT_LEN);
    for(int i = 0; i < ATTEMPTS; i++){
        #if DBG
            fprintf(fd, "***** CHALLENGE %d *****\n", i);
        #endif

        #if DBG
            fprintf(fd, "Receive encrypted challenge from Alice\n");
        #endif
        /*************************
        * BEGIN [1. A_B receives encrypted challenge from A_A]
        *************************/
        receive(fd_new, (char*)c, CHALLENGE_LEN);
        /*************************
        * END [1. A_B receives encrypted challenge from A_A]
        *************************/

        #if DBG
            fprintf(fd, "Alice's encrypted challenge: ");
            for(int j = 0; j < CHALLENGE_LEN; j++)
                fprintf(fd, "%02x", c[j]);
        #endif

        #if DBG
            fprintf(fd, "\nComputing Bob's encrypted result: ");
        #endif
        /*************************
        * BEGIN [6., 7. E_B decrypts challenge, computes and encrypts the response]
        *************************/
        getEncryptedResult(global_eid, &sgx_status, c, result, CHALLENGE_LEN, RESULT_LEN);
        if(sgx_status != SGX_SUCCESS){
            print_error_message(sgx_status);
            return -1;
        }
        /*************************
        * END [6., 7. E_B decrypts challenge, computes and encrypts the response]
        *************************/
        #if DBG
            fprintf(fd, "success\n");
        #endif

        #if DBG
            fprintf(fd, "Bob's encrypted result: ");
            for(int j = 0; j < RESULT_LEN; j++)
                fprintf(fd, "%02x", result[j]);
        #endif

        #if DBG
            fprintf(fd, "\nSend encrypted result to Alice\n");
        #endif
        /*************************
        * BEGIN [1. A_B sends encrypted response to A_A]
        *************************/
        send(fd_new, (char*)result, RESULT_LEN);
        /*************************
        * END [1. A_B sends encrypted response to A_A]
        *************************/
    }

    #if DBG
        fclose(fd);
    #endif

    free(c);
    free(result);

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    printf("From App: Enclave destroyed.\n");
    return 0;
}

