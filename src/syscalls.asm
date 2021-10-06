segment .text

global NtOpenProcessToken
global NtAdjustPrivilegesToken
global NtQuerySystemInformation
global NtOpenProcess
global NtDuplicateObject
global NtQueryObject
global NtReadVirtualMemory

NtAdjustPrivilegesToken:
	mov rax, [gs:0x60]                                 
NtAdjustPrivilegesToken_Check_X_X_XXXX:               
	cmp dword [rax+0x118], 6
	je  NtAdjustPrivilegesToken_Check_6_X_XXXX
	cmp dword [rax+0x118], 10
	je  NtAdjustPrivilegesToken_Check_10_0_XXXX
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown
NtAdjustPrivilegesToken_Check_6_X_XXXX:               
	cmp dword [rax+0x11c], 1
	je  NtAdjustPrivilegesToken_Check_6_1_XXXX
	cmp dword [rax+0x11c], 2
	je  NtAdjustPrivilegesToken_SystemCall_6_2_XXXX
	cmp dword [rax+0x11c], 3
	je  NtAdjustPrivilegesToken_SystemCall_6_3_XXXX
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown
NtAdjustPrivilegesToken_Check_6_1_XXXX:               
	cmp word [rax+0x120], 7600
	je  NtAdjustPrivilegesToken_SystemCall_6_1_7600
	cmp word [rax+0x120], 7601
	je  NtAdjustPrivilegesToken_SystemCall_6_1_7601
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown
NtAdjustPrivilegesToken_Check_10_0_XXXX:              
	cmp word [rax+0x120], 10240
	je  NtAdjustPrivilegesToken_SystemCall_10_0_10240
	cmp word [rax+0x120], 10586
	je  NtAdjustPrivilegesToken_SystemCall_10_0_10586
	cmp word [rax+0x120], 14393
	je  NtAdjustPrivilegesToken_SystemCall_10_0_14393
	cmp word [rax+0x120], 15063
	je  NtAdjustPrivilegesToken_SystemCall_10_0_15063
	cmp word [rax+0x120], 16299
	je  NtAdjustPrivilegesToken_SystemCall_10_0_16299
	cmp word [rax+0x120], 17134
	je  NtAdjustPrivilegesToken_SystemCall_10_0_17134
	cmp word [rax+0x120], 17763
	je  NtAdjustPrivilegesToken_SystemCall_10_0_17763
	cmp word [rax+0x120], 18362
	je  NtAdjustPrivilegesToken_SystemCall_10_0_18362
	cmp word [rax+0x120], 18363
	je  NtAdjustPrivilegesToken_SystemCall_10_0_18363
	cmp word [rax+0x120], 19041
	je  NtAdjustPrivilegesToken_SystemCall_10_0_19041
	cmp word [rax+0x120], 19042
	je  NtAdjustPrivilegesToken_SystemCall_10_0_19042
	jmp NtAdjustPrivilegesToken_SystemCall_Unknown
NtAdjustPrivilegesToken_SystemCall_6_1_7600:          
	mov eax, 0x003e
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_6_1_7601:          
	mov eax, 0x003e
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_6_2_XXXX:          
	mov eax, 0x003f
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_6_3_XXXX:          
	mov eax, 0x0040
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_10240:        
	mov eax, 0x0041
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_10586:        
	mov eax, 0x0041
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_14393:        
	mov eax, 0x0041
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_15063:        
	mov eax, 0x0041
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_16299:        
	mov eax, 0x0041
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_17134:        
	mov eax, 0x0041
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_17763:        
	mov eax, 0x0041
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_18362:        
	mov eax, 0x0041
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_18363:        
	mov eax, 0x0041
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_19041:        
	mov eax, 0x0041
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_10_0_19042:        
	mov eax, 0x0041
	jmp NtAdjustPrivilegesToken_Epilogue
NtAdjustPrivilegesToken_SystemCall_Unknown:           
	ret
NtAdjustPrivilegesToken_Epilogue:
	mov r10, rcx
	syscall
	ret


NtDuplicateObject:
	mov rax, [gs:0x60]                            
NtDuplicateObject_Check_X_X_XXXX:               
	cmp dword [rax+0x118], 6
	je  NtDuplicateObject_Check_6_X_XXXX
	cmp dword [rax+0x118], 10
	je  NtDuplicateObject_Check_10_0_XXXX
	jmp NtDuplicateObject_SystemCall_Unknown
NtDuplicateObject_Check_6_X_XXXX:               
	cmp dword [rax+0x11c], 1
	je  NtDuplicateObject_Check_6_1_XXXX
	cmp dword [rax+0x11c], 2
	je  NtDuplicateObject_SystemCall_6_2_XXXX
	cmp dword [rax+0x11c], 3
	je  NtDuplicateObject_SystemCall_6_3_XXXX
	jmp NtDuplicateObject_SystemCall_Unknown
NtDuplicateObject_Check_6_1_XXXX:               
	cmp word [rax+0x120], 7600
	je  NtDuplicateObject_SystemCall_6_1_7600
	cmp word [rax+0x120], 7601
	je  NtDuplicateObject_SystemCall_6_1_7601
	jmp NtDuplicateObject_SystemCall_Unknown
NtDuplicateObject_Check_10_0_XXXX:              
	cmp word [rax+0x120], 10240
	je  NtDuplicateObject_SystemCall_10_0_10240
	cmp word [rax+0x120], 10586
	je  NtDuplicateObject_SystemCall_10_0_10586
	cmp word [rax+0x120], 14393
	je  NtDuplicateObject_SystemCall_10_0_14393
	cmp word [rax+0x120], 15063
	je  NtDuplicateObject_SystemCall_10_0_15063
	cmp word [rax+0x120], 16299
	je  NtDuplicateObject_SystemCall_10_0_16299
	cmp word [rax+0x120], 17134
	je  NtDuplicateObject_SystemCall_10_0_17134
	cmp word [rax+0x120], 17763
	je  NtDuplicateObject_SystemCall_10_0_17763
	cmp word [rax+0x120], 18362
	je  NtDuplicateObject_SystemCall_10_0_18362
	cmp word [rax+0x120], 18363
	je  NtDuplicateObject_SystemCall_10_0_18363
	cmp word [rax+0x120], 19041
	je  NtDuplicateObject_SystemCall_10_0_19041
	cmp word [rax+0x120], 19042
	je  NtDuplicateObject_SystemCall_10_0_19042
	jmp NtDuplicateObject_SystemCall_Unknown
NtDuplicateObject_SystemCall_6_1_7600:          
	mov eax, 0x0039
	jmp NtDuplicateObject_Epilogue
NtDuplicateObject_SystemCall_6_1_7601:          
	mov eax, 0x0039
	jmp NtDuplicateObject_Epilogue
NtDuplicateObject_SystemCall_6_2_XXXX:          
	mov eax, 0x003a
	jmp NtDuplicateObject_Epilogue
NtDuplicateObject_SystemCall_6_3_XXXX:          
	mov eax, 0x003b
	jmp NtDuplicateObject_Epilogue
NtDuplicateObject_SystemCall_10_0_10240:        
	mov eax, 0x003c
	jmp NtDuplicateObject_Epilogue
NtDuplicateObject_SystemCall_10_0_10586:        
	mov eax, 0x003c
	jmp NtDuplicateObject_Epilogue
NtDuplicateObject_SystemCall_10_0_14393:        
	mov eax, 0x003c
	jmp NtDuplicateObject_Epilogue
NtDuplicateObject_SystemCall_10_0_15063:        
	mov eax, 0x003c
	jmp NtDuplicateObject_Epilogue
NtDuplicateObject_SystemCall_10_0_16299:        
	mov eax, 0x003c
	jmp NtDuplicateObject_Epilogue
NtDuplicateObject_SystemCall_10_0_17134:        
	mov eax, 0x003c
	jmp NtDuplicateObject_Epilogue
NtDuplicateObject_SystemCall_10_0_17763:        
	mov eax, 0x003c
	jmp NtDuplicateObject_Epilogue
NtDuplicateObject_SystemCall_10_0_18362:        
	mov eax, 0x003c
	jmp NtDuplicateObject_Epilogue
NtDuplicateObject_SystemCall_10_0_18363:        
	mov eax, 0x003c
	jmp NtDuplicateObject_Epilogue
NtDuplicateObject_SystemCall_10_0_19041:        
	mov eax, 0x003c
	jmp NtDuplicateObject_Epilogue
NtDuplicateObject_SystemCall_10_0_19042:        
	mov eax, 0x003c
	jmp NtDuplicateObject_Epilogue
NtDuplicateObject_SystemCall_Unknown:           
	ret
NtDuplicateObject_Epilogue:
	mov r10, rcx
	syscall
	ret


NtDuplicateToken:
	mov rax, [gs:0x60]                            
NtDuplicateToken_Check_X_X_XXXX:               
	cmp dword [rax+0x118], 6
	je  NtDuplicateToken_Check_6_X_XXXX
	cmp dword [rax+0x118], 10
	je  NtDuplicateToken_Check_10_0_XXXX
	jmp NtDuplicateToken_SystemCall_Unknown
NtDuplicateToken_Check_6_X_XXXX:               
	cmp dword [rax+0x11c], 1
	je  NtDuplicateToken_Check_6_1_XXXX
	cmp dword [rax+0x11c], 2
	je  NtDuplicateToken_SystemCall_6_2_XXXX
	cmp dword [rax+0x11c], 3
	je  NtDuplicateToken_SystemCall_6_3_XXXX
	jmp NtDuplicateToken_SystemCall_Unknown
NtDuplicateToken_Check_6_1_XXXX:               
	cmp word [rax+0x120], 7600
	je  NtDuplicateToken_SystemCall_6_1_7600
	cmp word [rax+0x120], 7601
	je  NtDuplicateToken_SystemCall_6_1_7601
	jmp NtDuplicateToken_SystemCall_Unknown
NtDuplicateToken_Check_10_0_XXXX:              
	cmp word [rax+0x120], 10240
	je  NtDuplicateToken_SystemCall_10_0_10240
	cmp word [rax+0x120], 10586
	je  NtDuplicateToken_SystemCall_10_0_10586
	cmp word [rax+0x120], 14393
	je  NtDuplicateToken_SystemCall_10_0_14393
	cmp word [rax+0x120], 15063
	je  NtDuplicateToken_SystemCall_10_0_15063
	cmp word [rax+0x120], 16299
	je  NtDuplicateToken_SystemCall_10_0_16299
	cmp word [rax+0x120], 17134
	je  NtDuplicateToken_SystemCall_10_0_17134
	cmp word [rax+0x120], 17763
	je  NtDuplicateToken_SystemCall_10_0_17763
	cmp word [rax+0x120], 18362
	je  NtDuplicateToken_SystemCall_10_0_18362
	cmp word [rax+0x120], 18363
	je  NtDuplicateToken_SystemCall_10_0_18363
	cmp word [rax+0x120], 19041
	je  NtDuplicateToken_SystemCall_10_0_19041
	cmp word [rax+0x120], 19042
	je  NtDuplicateToken_SystemCall_10_0_19042
	jmp NtDuplicateToken_SystemCall_Unknown
NtDuplicateToken_SystemCall_6_1_7600:          
	mov eax, 0x003f
	jmp NtDuplicateToken_Epilogue
NtDuplicateToken_SystemCall_6_1_7601:          
	mov eax, 0x003f
	jmp NtDuplicateToken_Epilogue
NtDuplicateToken_SystemCall_6_2_XXXX:          
	mov eax, 0x0040
	jmp NtDuplicateToken_Epilogue
NtDuplicateToken_SystemCall_6_3_XXXX:          
	mov eax, 0x0041
	jmp NtDuplicateToken_Epilogue
NtDuplicateToken_SystemCall_10_0_10240:        
	mov eax, 0x0042
	jmp NtDuplicateToken_Epilogue
NtDuplicateToken_SystemCall_10_0_10586:        
	mov eax, 0x0042
	jmp NtDuplicateToken_Epilogue
NtDuplicateToken_SystemCall_10_0_14393:        
	mov eax, 0x0042
	jmp NtDuplicateToken_Epilogue
NtDuplicateToken_SystemCall_10_0_15063:        
	mov eax, 0x0042
	jmp NtDuplicateToken_Epilogue
NtDuplicateToken_SystemCall_10_0_16299:        
	mov eax, 0x0042
	jmp NtDuplicateToken_Epilogue
NtDuplicateToken_SystemCall_10_0_17134:        
	mov eax, 0x0042
	jmp NtDuplicateToken_Epilogue
NtDuplicateToken_SystemCall_10_0_17763:        
	mov eax, 0x0042
	jmp NtDuplicateToken_Epilogue
NtDuplicateToken_SystemCall_10_0_18362:        
	mov eax, 0x0042
	jmp NtDuplicateToken_Epilogue
NtDuplicateToken_SystemCall_10_0_18363:        
	mov eax, 0x0042
	jmp NtDuplicateToken_Epilogue
NtDuplicateToken_SystemCall_10_0_19041:        
	mov eax, 0x0042
	jmp NtDuplicateToken_Epilogue
NtDuplicateToken_SystemCall_10_0_19042:        
	mov eax, 0x0042
	jmp NtDuplicateToken_Epilogue
NtDuplicateToken_SystemCall_Unknown:           
	ret
NtDuplicateToken_Epilogue:
	mov r10, rcx
	syscall
	ret


NtOpenProcess:
	mov rax, [gs:0x60]                      
NtOpenProcess_Check_X_X_XXXX:               
	cmp dword [rax+0x118], 6
	je  NtOpenProcess_Check_6_X_XXXX
	cmp dword [rax+0x118], 10
	je  NtOpenProcess_Check_10_0_XXXX
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_6_X_XXXX:               
	cmp dword [rax+0x11c], 1
	je  NtOpenProcess_Check_6_1_XXXX
	cmp dword [rax+0x11c], 2
	je  NtOpenProcess_SystemCall_6_2_XXXX
	cmp dword [rax+0x11c], 3
	je  NtOpenProcess_SystemCall_6_3_XXXX
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_6_1_XXXX:               
	cmp word [rax+0x120], 7600
	je  NtOpenProcess_SystemCall_6_1_7600
	cmp word [rax+0x120], 7601
	je  NtOpenProcess_SystemCall_6_1_7601
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_Check_10_0_XXXX:              
	cmp word [rax+0x120], 10240
	je  NtOpenProcess_SystemCall_10_0_10240
	cmp word [rax+0x120], 10586
	je  NtOpenProcess_SystemCall_10_0_10586
	cmp word [rax+0x120], 14393
	je  NtOpenProcess_SystemCall_10_0_14393
	cmp word [rax+0x120], 15063
	je  NtOpenProcess_SystemCall_10_0_15063
	cmp word [rax+0x120], 16299
	je  NtOpenProcess_SystemCall_10_0_16299
	cmp word [rax+0x120], 17134
	je  NtOpenProcess_SystemCall_10_0_17134
	cmp word [rax+0x120], 17763
	je  NtOpenProcess_SystemCall_10_0_17763
	cmp word [rax+0x120], 18362
	je  NtOpenProcess_SystemCall_10_0_18362
	cmp word [rax+0x120], 18363
	je  NtOpenProcess_SystemCall_10_0_18363
	cmp word [rax+0x120], 19041
	je  NtOpenProcess_SystemCall_10_0_19041
	cmp word [rax+0x120], 19042
	je  NtOpenProcess_SystemCall_10_0_19042
	jmp NtOpenProcess_SystemCall_Unknown
NtOpenProcess_SystemCall_6_1_7600:          
	mov eax, 0x0023
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_1_7601:          
	mov eax, 0x0023
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_2_XXXX:          
	mov eax, 0x0024
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_6_3_XXXX:          
	mov eax, 0x0025
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_10240:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_10586:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_14393:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_15063:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_16299:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_17134:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_17763:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_18362:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_18363:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_19041:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_10_0_19042:        
	mov eax, 0x0026
	jmp NtOpenProcess_Epilogue
NtOpenProcess_SystemCall_Unknown:           
	ret
NtOpenProcess_Epilogue:
	mov r10, rcx
	syscall
	ret


NtOpenProcessToken:
	mov rax, [gs:0x60]                            
NtOpenProcessToken_Check_X_X_XXXX:               
	cmp dword [rax+0x118], 6
	je  NtOpenProcessToken_Check_6_X_XXXX
	cmp dword [rax+0x118], 10
	je  NtOpenProcessToken_Check_10_0_XXXX
	jmp NtOpenProcessToken_SystemCall_Unknown
NtOpenProcessToken_Check_6_X_XXXX:               
	cmp dword [rax+0x11c], 1
	je  NtOpenProcessToken_Check_6_1_XXXX
	cmp dword [rax+0x11c], 2
	je  NtOpenProcessToken_SystemCall_6_2_XXXX
	cmp dword [rax+0x11c], 3
	je  NtOpenProcessToken_SystemCall_6_3_XXXX
	jmp NtOpenProcessToken_SystemCall_Unknown
NtOpenProcessToken_Check_6_1_XXXX:               
	cmp word [rax+0x120], 7600
	je  NtOpenProcessToken_SystemCall_6_1_7600
	cmp word [rax+0x120], 7601
	je  NtOpenProcessToken_SystemCall_6_1_7601
	jmp NtOpenProcessToken_SystemCall_Unknown
NtOpenProcessToken_Check_10_0_XXXX:              
	cmp word [rax+0x120], 10240
	je  NtOpenProcessToken_SystemCall_10_0_10240
	cmp word [rax+0x120], 10586
	je  NtOpenProcessToken_SystemCall_10_0_10586
	cmp word [rax+0x120], 14393
	je  NtOpenProcessToken_SystemCall_10_0_14393
	cmp word [rax+0x120], 15063
	je  NtOpenProcessToken_SystemCall_10_0_15063
	cmp word [rax+0x120], 16299
	je  NtOpenProcessToken_SystemCall_10_0_16299
	cmp word [rax+0x120], 17134
	je  NtOpenProcessToken_SystemCall_10_0_17134
	cmp word [rax+0x120], 17763
	je  NtOpenProcessToken_SystemCall_10_0_17763
	cmp word [rax+0x120], 18362
	je  NtOpenProcessToken_SystemCall_10_0_18362
	cmp word [rax+0x120], 18363
	je  NtOpenProcessToken_SystemCall_10_0_18363
	cmp word [rax+0x120], 19041
	je  NtOpenProcessToken_SystemCall_10_0_19041
	cmp word [rax+0x120], 19042
	je  NtOpenProcessToken_SystemCall_10_0_19042
	jmp NtOpenProcessToken_SystemCall_Unknown
NtOpenProcessToken_SystemCall_6_1_7600:          
	mov eax, 0x00f9
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_6_1_7601:          
	mov eax, 0x00f9
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_6_2_XXXX:          
	mov eax, 0x010b
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_6_3_XXXX:          
	mov eax, 0x010e
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_10240:        
	mov eax, 0x0114
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_10586:        
	mov eax, 0x0117
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_14393:        
	mov eax, 0x0119
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_15063:        
	mov eax, 0x011d
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_16299:        
	mov eax, 0x011f
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_17134:        
	mov eax, 0x0121
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_17763:        
	mov eax, 0x0122
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_18362:        
	mov eax, 0x0123
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_18363:        
	mov eax, 0x0123
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_19041:        
	mov eax, 0x0128
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_10_0_19042:        
	mov eax, 0x0128
	jmp NtOpenProcessToken_Epilogue
NtOpenProcessToken_SystemCall_Unknown:           
	ret
NtOpenProcessToken_Epilogue:
	mov r10, rcx
	syscall
	ret

NtQueryInformationToken:
	mov rax, [gs:0x60]                                
NtQueryInformationToken_Check_X_X_XXXX:               
	cmp dword [rax+0x118], 6
	je  NtQueryInformationToken_Check_6_X_XXXX
	cmp dword [rax+0x118], 10
	je  NtQueryInformationToken_Check_10_0_XXXX
	jmp NtQueryInformationToken_SystemCall_Unknown
NtQueryInformationToken_Check_6_X_XXXX:               
	cmp dword [rax+0x11c], 1
	je  NtQueryInformationToken_Check_6_1_XXXX
	cmp dword [rax+0x11c], 2
	je  NtQueryInformationToken_SystemCall_6_2_XXXX
	cmp dword [rax+0x11c], 3
	je  NtQueryInformationToken_SystemCall_6_3_XXXX
	jmp NtQueryInformationToken_SystemCall_Unknown
NtQueryInformationToken_Check_6_1_XXXX:               
	cmp word [rax+0x120], 7600
	je  NtQueryInformationToken_SystemCall_6_1_7600
	cmp word [rax+0x120], 7601
	je  NtQueryInformationToken_SystemCall_6_1_7601
	jmp NtQueryInformationToken_SystemCall_Unknown
NtQueryInformationToken_Check_10_0_XXXX:              
	cmp word [rax+0x120], 10240
	je  NtQueryInformationToken_SystemCall_10_0_10240
	cmp word [rax+0x120], 10586
	je  NtQueryInformationToken_SystemCall_10_0_10586
	cmp word [rax+0x120], 14393
	je  NtQueryInformationToken_SystemCall_10_0_14393
	cmp word [rax+0x120], 15063
	je  NtQueryInformationToken_SystemCall_10_0_15063
	cmp word [rax+0x120], 16299
	je  NtQueryInformationToken_SystemCall_10_0_16299
	cmp word [rax+0x120], 17134
	je  NtQueryInformationToken_SystemCall_10_0_17134
	cmp word [rax+0x120], 17763
	je  NtQueryInformationToken_SystemCall_10_0_17763
	cmp word [rax+0x120], 18362
	je  NtQueryInformationToken_SystemCall_10_0_18362
	cmp word [rax+0x120], 18363
	je  NtQueryInformationToken_SystemCall_10_0_18363
	cmp word [rax+0x120], 19041
	je  NtQueryInformationToken_SystemCall_10_0_19041
	cmp word [rax+0x120], 19042
	je  NtQueryInformationToken_SystemCall_10_0_19042
	jmp NtQueryInformationToken_SystemCall_Unknown
NtQueryInformationToken_SystemCall_6_1_7600:          
	mov eax, 0x001e
	jmp NtQueryInformationToken_Epilogue
NtQueryInformationToken_SystemCall_6_1_7601:          
	mov eax, 0x001e
	jmp NtQueryInformationToken_Epilogue
NtQueryInformationToken_SystemCall_6_2_XXXX:          
	mov eax, 0x001f
	jmp NtQueryInformationToken_Epilogue
NtQueryInformationToken_SystemCall_6_3_XXXX:          
	mov eax, 0x0020
	jmp NtQueryInformationToken_Epilogue
NtQueryInformationToken_SystemCall_10_0_10240:        
	mov eax, 0x0021
	jmp NtQueryInformationToken_Epilogue
NtQueryInformationToken_SystemCall_10_0_10586:        
	mov eax, 0x0021
	jmp NtQueryInformationToken_Epilogue
NtQueryInformationToken_SystemCall_10_0_14393:        
	mov eax, 0x0021
	jmp NtQueryInformationToken_Epilogue
NtQueryInformationToken_SystemCall_10_0_15063:        
	mov eax, 0x0021
	jmp NtQueryInformationToken_Epilogue
NtQueryInformationToken_SystemCall_10_0_16299:        
	mov eax, 0x0021
	jmp NtQueryInformationToken_Epilogue
NtQueryInformationToken_SystemCall_10_0_17134:        
	mov eax, 0x0021
	jmp NtQueryInformationToken_Epilogue
NtQueryInformationToken_SystemCall_10_0_17763:        
	mov eax, 0x0021
	jmp NtQueryInformationToken_Epilogue
NtQueryInformationToken_SystemCall_10_0_18362:        
	mov eax, 0x0021
	jmp NtQueryInformationToken_Epilogue
NtQueryInformationToken_SystemCall_10_0_18363:        
	mov eax, 0x0021
	jmp NtQueryInformationToken_Epilogue
NtQueryInformationToken_SystemCall_10_0_19041:        
	mov eax, 0x0021
	jmp NtQueryInformationToken_Epilogue
NtQueryInformationToken_SystemCall_10_0_19042:        
	mov eax, 0x0021
	jmp NtQueryInformationToken_Epilogue
NtQueryInformationToken_SystemCall_Unknown:           
	ret
NtQueryInformationToken_Epilogue:
	mov r10, rcx
	syscall
	ret

NtQueryObject:
	mov rax, [gs:0x60]                        
NtQueryObject_Check_X_X_XXXX:               
	cmp dword [rax+0x118], 6
	je  NtQueryObject_Check_6_X_XXXX
	cmp dword [rax+0x118], 10
	je  NtQueryObject_Check_10_0_XXXX
	jmp NtQueryObject_SystemCall_Unknown
NtQueryObject_Check_6_X_XXXX:               
	cmp dword [rax+0x11c], 1
	je  NtQueryObject_Check_6_1_XXXX
	cmp dword [rax+0x11c], 2
	je  NtQueryObject_SystemCall_6_2_XXXX
	cmp dword [rax+0x11c], 3
	je  NtQueryObject_SystemCall_6_3_XXXX
	jmp NtQueryObject_SystemCall_Unknown
NtQueryObject_Check_6_1_XXXX:               
	cmp word [rax+0x120], 7600
	je  NtQueryObject_SystemCall_6_1_7600
	cmp word [rax+0x120], 7601
	je  NtQueryObject_SystemCall_6_1_7601
	jmp NtQueryObject_SystemCall_Unknown
NtQueryObject_Check_10_0_XXXX:              
	cmp word [rax+0x120], 10240
	je  NtQueryObject_SystemCall_10_0_10240
	cmp word [rax+0x120], 10586
	je  NtQueryObject_SystemCall_10_0_10586
	cmp word [rax+0x120], 14393
	je  NtQueryObject_SystemCall_10_0_14393
	cmp word [rax+0x120], 15063
	je  NtQueryObject_SystemCall_10_0_15063
	cmp word [rax+0x120], 16299
	je  NtQueryObject_SystemCall_10_0_16299
	cmp word [rax+0x120], 17134
	je  NtQueryObject_SystemCall_10_0_17134
	cmp word [rax+0x120], 17763
	je  NtQueryObject_SystemCall_10_0_17763
	cmp word [rax+0x120], 18362
	je  NtQueryObject_SystemCall_10_0_18362
	cmp word [rax+0x120], 18363
	je  NtQueryObject_SystemCall_10_0_18363
	cmp word [rax+0x120], 19041
	je  NtQueryObject_SystemCall_10_0_19041
	cmp word [rax+0x120], 19042
	je  NtQueryObject_SystemCall_10_0_19042
	jmp NtQueryObject_SystemCall_Unknown
NtQueryObject_SystemCall_6_1_7600:          
	mov eax, 0x000d
	jmp NtQueryObject_Epilogue
NtQueryObject_SystemCall_6_1_7601:          
	mov eax, 0x000d
	jmp NtQueryObject_Epilogue
NtQueryObject_SystemCall_6_2_XXXX:          
	mov eax, 0x000e
	jmp NtQueryObject_Epilogue
NtQueryObject_SystemCall_6_3_XXXX:          
	mov eax, 0x000f
	jmp NtQueryObject_Epilogue
NtQueryObject_SystemCall_10_0_10240:        
	mov eax, 0x0010
	jmp NtQueryObject_Epilogue
NtQueryObject_SystemCall_10_0_10586:        
	mov eax, 0x0010
	jmp NtQueryObject_Epilogue
NtQueryObject_SystemCall_10_0_14393:        
	mov eax, 0x0010
	jmp NtQueryObject_Epilogue
NtQueryObject_SystemCall_10_0_15063:        
	mov eax, 0x0010
	jmp NtQueryObject_Epilogue
NtQueryObject_SystemCall_10_0_16299:        
	mov eax, 0x0010
	jmp NtQueryObject_Epilogue
NtQueryObject_SystemCall_10_0_17134:        
	mov eax, 0x0010
	jmp NtQueryObject_Epilogue
NtQueryObject_SystemCall_10_0_17763:        
	mov eax, 0x0010
	jmp NtQueryObject_Epilogue
NtQueryObject_SystemCall_10_0_18362:        
	mov eax, 0x0010
	jmp NtQueryObject_Epilogue
NtQueryObject_SystemCall_10_0_18363:        
	mov eax, 0x0010
	jmp NtQueryObject_Epilogue
NtQueryObject_SystemCall_10_0_19041:        
	mov eax, 0x0010
	jmp NtQueryObject_Epilogue
NtQueryObject_SystemCall_10_0_19042:        
	mov eax, 0x0010
	jmp NtQueryObject_Epilogue
NtQueryObject_SystemCall_Unknown:           
	ret
NtQueryObject_Epilogue:
	mov r10, rcx
	syscall
	ret

NtQuerySystemInformation:
	mov rax, [gs:0x60]                                
NtQuerySystemInformation_Check_X_X_XXXX:               
	cmp dword [rax+0x118], 6
	je  NtQuerySystemInformation_Check_6_X_XXXX
	cmp dword [rax+0x118], 10
	je  NtQuerySystemInformation_Check_10_0_XXXX
	jmp NtQuerySystemInformation_SystemCall_Unknown
NtQuerySystemInformation_Check_6_X_XXXX:               
	cmp dword [rax+0x11c], 1
	je  NtQuerySystemInformation_Check_6_1_XXXX
	cmp dword [rax+0x11c], 2
	je  NtQuerySystemInformation_SystemCall_6_2_XXXX
	cmp dword [rax+0x11c], 3
	je  NtQuerySystemInformation_SystemCall_6_3_XXXX
	jmp NtQuerySystemInformation_SystemCall_Unknown
NtQuerySystemInformation_Check_6_1_XXXX:               
	cmp word [rax+0x120], 7600
	je  NtQuerySystemInformation_SystemCall_6_1_7600
	cmp word [rax+0x120], 7601
	je  NtQuerySystemInformation_SystemCall_6_1_7601
	jmp NtQuerySystemInformation_SystemCall_Unknown
NtQuerySystemInformation_Check_10_0_XXXX:              
	cmp word [rax+0x120], 10240
	je  NtQuerySystemInformation_SystemCall_10_0_10240
	cmp word [rax+0x120], 10586
	je  NtQuerySystemInformation_SystemCall_10_0_10586
	cmp word [rax+0x120], 14393
	je  NtQuerySystemInformation_SystemCall_10_0_14393
	cmp word [rax+0x120], 15063
	je  NtQuerySystemInformation_SystemCall_10_0_15063
	cmp word [rax+0x120], 16299
	je  NtQuerySystemInformation_SystemCall_10_0_16299
	cmp word [rax+0x120], 17134
	je  NtQuerySystemInformation_SystemCall_10_0_17134
	cmp word [rax+0x120], 17763
	je  NtQuerySystemInformation_SystemCall_10_0_17763
	cmp word [rax+0x120], 18362
	je  NtQuerySystemInformation_SystemCall_10_0_18362
	cmp word [rax+0x120], 18363
	je  NtQuerySystemInformation_SystemCall_10_0_18363
	cmp word [rax+0x120], 19041
	je  NtQuerySystemInformation_SystemCall_10_0_19041
	cmp word [rax+0x120], 19042
	je  NtQuerySystemInformation_SystemCall_10_0_19042
	jmp NtQuerySystemInformation_SystemCall_Unknown
NtQuerySystemInformation_SystemCall_6_1_7600:          
	mov eax, 0x0033
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_6_1_7601:          
	mov eax, 0x0033
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_6_2_XXXX:          
	mov eax, 0x0034
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_6_3_XXXX:          
	mov eax, 0x0035
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_10240:        
	mov eax, 0x0036
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_10586:        
	mov eax, 0x0036
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_14393:        
	mov eax, 0x0036
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_15063:        
	mov eax, 0x0036
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_16299:        
	mov eax, 0x0036
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_17134:        
	mov eax, 0x0036
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_17763:        
	mov eax, 0x0036
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_18362:        
	mov eax, 0x0036
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_18363:        
	mov eax, 0x0036
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_19041:        
	mov eax, 0x0036
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_10_0_19042:        
	mov eax, 0x0036
	jmp NtQuerySystemInformation_Epilogue
NtQuerySystemInformation_SystemCall_Unknown:           
	ret
NtQuerySystemInformation_Epilogue:
	mov r10, rcx
	syscall
	ret

NtReadVirtualMemory:
	mov rax, [gs:0x60]                              
NtReadVirtualMemory_Check_X_X_XXXX:               
	cmp dword [rax+0x118], 6
	je  NtReadVirtualMemory_Check_6_X_XXXX
	cmp dword [rax+0x118], 10
	je  NtReadVirtualMemory_Check_10_0_XXXX
	jmp NtReadVirtualMemory_SystemCall_Unknown
NtReadVirtualMemory_Check_6_X_XXXX:               
	cmp dword [rax+0x11c], 1
	je  NtReadVirtualMemory_Check_6_1_XXXX
	cmp dword [rax+0x11c], 2
	je  NtReadVirtualMemory_SystemCall_6_2_XXXX
	cmp dword [rax+0x11c], 3
	je  NtReadVirtualMemory_SystemCall_6_3_XXXX
	jmp NtReadVirtualMemory_SystemCall_Unknown
NtReadVirtualMemory_Check_6_1_XXXX:               
	cmp word [rax+0x120], 7600
	je  NtReadVirtualMemory_SystemCall_6_1_7600
	cmp word [rax+0x120], 7601
	je  NtReadVirtualMemory_SystemCall_6_1_7601
	jmp NtReadVirtualMemory_SystemCall_Unknown
NtReadVirtualMemory_Check_10_0_XXXX:              
	cmp word [rax+0x120], 10240
	je  NtReadVirtualMemory_SystemCall_10_0_10240
	cmp word [rax+0x120], 10586
	je  NtReadVirtualMemory_SystemCall_10_0_10586
	cmp word [rax+0x120], 14393
	je  NtReadVirtualMemory_SystemCall_10_0_14393
	cmp word [rax+0x120], 15063
	je  NtReadVirtualMemory_SystemCall_10_0_15063
	cmp word [rax+0x120], 16299
	je  NtReadVirtualMemory_SystemCall_10_0_16299
	cmp word [rax+0x120], 17134
	je  NtReadVirtualMemory_SystemCall_10_0_17134
	cmp word [rax+0x120], 17763
	je  NtReadVirtualMemory_SystemCall_10_0_17763
	cmp word [rax+0x120], 18362
	je  NtReadVirtualMemory_SystemCall_10_0_18362
	cmp word [rax+0x120], 18363
	je  NtReadVirtualMemory_SystemCall_10_0_18363
	cmp word [rax+0x120], 19041
	je  NtReadVirtualMemory_SystemCall_10_0_19041
	cmp word [rax+0x120], 19042
	je  NtReadVirtualMemory_SystemCall_10_0_19042
	jmp NtReadVirtualMemory_SystemCall_Unknown
NtReadVirtualMemory_SystemCall_6_1_7600:          
	mov eax, 0x003c
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_6_1_7601:          
	mov eax, 0x003c
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_6_2_XXXX:          
	mov eax, 0x003d
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_6_3_XXXX:          
	mov eax, 0x003e
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_10240:        
	mov eax, 0x003f
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_10586:        
	mov eax, 0x003f
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_14393:        
	mov eax, 0x003f
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_15063:        
	mov eax, 0x003f
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_16299:        
	mov eax, 0x003f
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_17134:        
	mov eax, 0x003f
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_17763:        
	mov eax, 0x003f
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_18362:        
	mov eax, 0x003f
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_18363:        
	mov eax, 0x003f
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_19041:        
	mov eax, 0x003f
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_10_0_19042:        
	mov eax, 0x003f
	jmp NtReadVirtualMemory_Epilogue
NtReadVirtualMemory_SystemCall_Unknown:           
	ret
NtReadVirtualMemory_Epilogue:
	mov r10, rcx
	syscall
	ret