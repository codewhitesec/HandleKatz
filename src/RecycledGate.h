#pragma once

#include "windows.h"
#include "Defines.h"

#ifdef _DEBUG
#include "stdio.h"
#endif

#define FAIL 0
#define SUCCESS 1

#define HASH_KEY 0x41424344
#define SYS_STUB_SIZE 32

#define UP -32
#define DOWN 32

typedef struct {

    DWORD dwSyscallNr;
    PVOID pRecycledGate;

} Syscall;

PVOID findNtDll(void);
WCHAR* toLower(WCHAR* str);

extern void PrepareSyscall(DWORD dwSycallNr, PVOID dw64Gate);
extern int DoSyscall();

PVOID findNtDll(void);
DWORD getSyscall(DWORD crypted_hash, Syscall* pSyscall);

unsigned long djb2_unicode(const wchar_t* str);
unsigned long djb2(unsigned char* str);
unsigned long xor_hash(unsigned long hash);
