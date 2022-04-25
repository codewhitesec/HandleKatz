
#include "windows.h"

#include "APIResolve.h"
#include "Misc.h"



PSYSTEM_HANDLE_INFORMATION get_handles(struct fPtrs* ptr_functions);
HANDLE check_handles(PSYSTEM_HANDLE_INFORMATION, DWORD, char*, struct fPtrs* ptr_functions);
