#ifndef MISC_H
#define MISC_H

#include "APIResolve.h"
#include "RecycledGate.h"

#include "windows.h"

struct fPtrs {
    COPYMEMORY _CopyMemory;
    LSTRCATA _lstrcatA;
    LSTRLENA _lstrlenA;
    WSPRINTFA _wsprintfA;
    CREATEFILEA _CreateFileA;
    CLOSEHANDLE _CloseHandle;
    GETPROCESSID _GetProcessId;
    VIRTUALFREE _VirtualFree;
    LSTRCMPA _lstrcmpA;
    VIRTUALALLOC _VirtualAlloc;
    STRCMPW _strcmpW;
    STRSTRA _strstrA;
    GETMODULEFILENAMEXA _GetModuleFileNameExA;
    GETPROCESSIMAGEFILENAMEA _GetProcessImageFileNameA;
    PATHFINDFILENAMEA _PathFindFileNameA;
    WRITEFILE _WriteFile;
    HEAPALLOC _HeapAlloc;
    GETPROCESSHEAP _GetProcessHeap;
    HEAPFREE _HeapFree;
    HEAPREALLOC _HeapReAlloc;
    SETFILEPOINTER _SetFilePointer;
    LOADLIBRARYA _LoadLibrary;
    GETSYSTEMINFO _GetSystemInfo;
    FREELIBRARY _FreeLibrary;
    ISPROCESSORFEATUREPRESENT _IsProcessorFeaturePresent;
    LSTRLENW _lstrlenW;
    GETPROCADDRESS _GetProcAddress;
    VIRTUALQUERYEX _VirtualQueryEx;
    SETFILEPOINTEREX _SetFilePointerEx;
    GETFILEVERSIONINFOSIZEW _GetFileVersionInfoSizeW;
    GETFILEVERSIONINFOW _GetFileVersionInfoW;
    VERQUERYVALUEW _VerQueryValueW;
    LSTRCPYW _lstrcpyW;
    GETMODULEFILENAMEEXW _GetModuleFileNameExW;
    ENUMPROCESSMODULES _EnumProcessModules;
    GETMODULEINFORMATION _GetModuleInformation;
    GETMODULEBASENAMEW _GetModuleBaseNameW;
    LSTRCMPW _lstrcmpW;
    LOOKUPPRIVILEGEVALUEA _LookupPrivilegeValueA;
};

DWORD resolveFptrs(struct fPtrs* ptrs);
DWORD setDebugPrivilege(struct fPtrs *);
#endif
