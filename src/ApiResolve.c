#include "APIResolve.h"

static uint64_t getDllBase(unsigned long);
static uint64_t loadDll(unsigned long);
static uint64_t loadDll_byName(char*);
static uint64_t parseHdrForPtr(uint64_t, unsigned long);
static uint64_t followExport(char*, unsigned long);

static unsigned long djb2(unsigned char*);
static unsigned long unicode_djb2(const wchar_t* str);
static unsigned long xor_hash(unsigned long);
static WCHAR* toLower(WCHAR* str);

uint64_t
getFunctionPtr(unsigned long crypted_dll_hash, unsigned long crypted_function_hash) {

	uint64_t dll_base = 0x00;
	uint64_t ptr_function = 0x00;

	dll_base = getDllBase(crypted_dll_hash);
	if (dll_base == 0) {
		dll_base = loadDll(crypted_dll_hash);
		if (dll_base == 0)
			return FAIL;
	}

	ptr_function = parseHdrForPtr(dll_base, crypted_function_hash);

	return ptr_function;

}

static uint64_t
loadDll(unsigned long crypted_dll_hash) {

	uint64_t kernel32_base = 0x00;
	uint64_t fptr_loadLibary = 0x00;
	uint64_t ptr_loaded_dll = 0x00;

	kernel32_base = getDllBase(CRYPTED_HASH_KERNEL32);
	if (kernel32_base == 0x00)
		return FAIL;

	fptr_loadLibary = parseHdrForPtr(kernel32_base, CRYPTED_HASH_LOADLIBRARYA);
	if (fptr_loadLibary == 0x00)
		return FAIL;

	if (crypted_dll_hash == CRYPTED_HASH_USER32) {
		char dll_name[] = { 'U', 's', 'e', 'r', '3' ,'2' ,'.', 'd', 'l', 'l', 0x00 };
		ptr_loaded_dll = (uint64_t)((LOADLIBRARYA)fptr_loadLibary)(dll_name);
	} else if (crypted_dll_hash == CRYPTED_HASH_ADVAPI32) {
		char dll_name[] = { 'A', 'd', 'v', 'a', 'p', 'i', '3', '2','.','d','l','l',0x00 };
		ptr_loaded_dll = (uint64_t)((LOADLIBRARYA)fptr_loadLibary)(dll_name);
	} else if (crypted_dll_hash == CRYPTED_HASH_SHLWAPI) {
		char dll_name[] = { 'S', 'h', 'l', 'w', 'a', 'p', 'i', '.', 'd','l','l',0x00 };
		ptr_loaded_dll = (uint64_t)((LOADLIBRARYA)fptr_loadLibary)(dll_name);
	} else if (crypted_dll_hash == CRYPTED_HASH_PSAPI) {
		char dll_name[] = { 'P', 's', 'a', 'p', 'i', '.', 'd','l','l',0x00 };
		ptr_loaded_dll = (uint64_t)((LOADLIBRARYA)fptr_loadLibary)(dll_name);
	} else if (crypted_dll_hash == CRYPTED_HASH_API_MS_WIN_CORE_DLL) {
		char dll_name[] = { 'A','p','i','-','m','s','-','w','i','n','-','c','o','r','e','-','v','e','r','s','i','o','n','-','l','1','-','1','-','0','.','d','l','l', 0x00 };
		ptr_loaded_dll = (uint64_t)((LOADLIBRARYA)fptr_loadLibary)(dll_name);
	} 

	return ptr_loaded_dll;

}

static uint64_t
loadDll_byName(char* dll_name) {

	uint64_t kernel32_base = 0x00;
	uint64_t fptr_loadLibary = 0x00;
	uint64_t ptr_loaded_dll = 0x00;

	kernel32_base = getDllBase(CRYPTED_HASH_KERNEL32);
	if (kernel32_base == 0x00)
		return FAIL;

	fptr_loadLibary = parseHdrForPtr(kernel32_base, CRYPTED_HASH_LOADLIBRARYA);
	if (fptr_loadLibary == 0x00)
		return FAIL;

	ptr_loaded_dll = (uint64_t)((LOADLIBRARYA)fptr_loadLibary)(dll_name);

	return ptr_loaded_dll;

}


static uint64_t
parseHdrForPtr(uint64_t dll_base, unsigned long crypted_function_hash) {

	PIMAGE_NT_HEADERS nt_hdrs = NULL;
	PIMAGE_DATA_DIRECTORY data_dir = NULL;
	PIMAGE_EXPORT_DIRECTORY export_dir = NULL;

	uint32_t* ptr_exportadrtable = 0x00;
	uint32_t* ptr_namepointertable = 0x00;
	uint16_t* ptr_ordinaltable = 0x00;

	uint32_t idx_functions = 0x00;

	unsigned char* ptr_function_name = NULL;


	nt_hdrs = (PIMAGE_NT_HEADERS)(dll_base + (uint64_t)((PIMAGE_DOS_HEADER)(size_t)dll_base)->e_lfanew);
	data_dir = (PIMAGE_DATA_DIRECTORY)&nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	export_dir = (PIMAGE_EXPORT_DIRECTORY)(dll_base + (uint64_t)data_dir->VirtualAddress);

	ptr_exportadrtable = (uint32_t*)(dll_base + (uint64_t)export_dir->AddressOfFunctions);
	ptr_namepointertable = (uint32_t*)(dll_base + (uint64_t)export_dir->AddressOfNames);
	ptr_ordinaltable = (uint16_t*)(dll_base + (uint64_t)export_dir->AddressOfNameOrdinals);

	for (idx_functions = 0; idx_functions < export_dir->NumberOfNames; idx_functions++) {

		ptr_function_name = (unsigned char*)dll_base + (ptr_namepointertable[idx_functions]);
		if (djb2(ptr_function_name) == xor_hash(crypted_function_hash)) {

			WORD nameord = ptr_ordinaltable[idx_functions];
			DWORD rva = ptr_exportadrtable[nameord];


			if (dll_base + rva >= dll_base + data_dir->VirtualAddress && dll_base + rva <= dll_base + data_dir->VirtualAddress + (uint64_t)data_dir->Size) {
				// This is a forwarded export 

				char* ptr_forward = (char*)(dll_base + rva);
				return followExport(ptr_forward, crypted_function_hash);

			}


			return dll_base + rva;
		}

	}

	return FAIL;
}

static uint64_t followExport(char* ptr_forward, unsigned long crypted_function_hash) {

	STRSTRA _StrStrA = (STRSTRA)getFunctionPtr(CRYPTED_HASH_SHLWAPI, CRYPTED_HASH_STRSTRA);

	if (_StrStrA == 0x00)
		return FAIL;

	char del[] = { '.', 0x00 };
	char* pos_del = 0x00;
	char forward_dll[MAX_PATH] = { 0 };
	char forward_export[MAX_PATH] = { 0 };
	unsigned long forward_export_hash = 0x00;
	uint8_t i = 0;
	uint64_t fwd_dll_base = 0x00, forwarded_export = 0x00;

	while (*ptr_forward)
		forward_dll[i++] = *ptr_forward++;

	pos_del = (char*)_StrStrA(forward_dll, del);
	if (pos_del == 0)
		return FAIL;

	*(char*)(pos_del++) = 0x00;
	i = 0;
	while (*pos_del)
		forward_export[i++] = *pos_del++;

	forward_export_hash = xor_hash(djb2((unsigned char*)forward_export));

	fwd_dll_base = getDllBase(xor_hash(djb2((unsigned char*)forward_dll)));
	if (fwd_dll_base == 0x00) {
		fwd_dll_base = loadDll_byName(forward_dll);
		if (fwd_dll_base == 0x00)
			return FAIL;
	}

	forwarded_export = parseHdrForPtr(fwd_dll_base, forward_export_hash);

	return forwarded_export;

}

static uint64_t
getDllBase(unsigned long crypted_dll_hash) {

	_PPEB ptr_peb = NULL;
	PPEB_LDR_DATA ptr_ldr_data = NULL;
	PLDR_DATA_TABLE_ENTRY ptr_module_entry = NULL, ptr_start_module = NULL;
	PUNICODE_STR dll_name = NULL;

	ptr_peb = (_PPEB)__readgsqword(0x60);
	ptr_ldr_data = ptr_peb->pLdr;
	ptr_module_entry = ptr_start_module = (PLDR_DATA_TABLE_ENTRY)ptr_ldr_data->InMemoryOrderModuleList.Flink;

	do {

		dll_name = &ptr_module_entry->BaseDllName;

		if (dll_name->pBuffer == NULL)
			return FAIL;

		if ((uint64_t)dll_name->pBuffer == 0x400)
			continue;

		if (unicode_djb2(toLower(dll_name->pBuffer)) == xor_hash(crypted_dll_hash))
			return (uint64_t)ptr_module_entry->DllBase;

		ptr_module_entry = (PLDR_DATA_TABLE_ENTRY)ptr_module_entry->InMemoryOrderModuleList.Flink;

	} while (ptr_module_entry != ptr_start_module);

	return FAIL;

}

static unsigned long
djb2(unsigned char* str)
{
	unsigned long hash = 5381;
	int c;

	while ((c = *str++))
		hash = ((hash << 5) + hash) + c;

	return hash;
}

unsigned long
unicode_djb2(const wchar_t* str)
{

	unsigned long hash = 5381;
	DWORD val;

	while (*str != 0) {
		val = (DWORD)*str++;
		hash = ((hash << 5) + hash) + val;
	}

	return hash;

}

unsigned long
xor_hash(unsigned long hash) {
	return hash ^ CRYPT_KEY;
}

static WCHAR*
toLower(WCHAR* str)
{

	WCHAR* start = str;

	while (*str) {

		if (*str <= L'Z' && *str >= 'A') {
			*str += 32;
		}

		str += 1;

	}

	return start;

}
