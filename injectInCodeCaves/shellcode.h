#pragma once
#include <windows.h>
#include "exe.h"

VOID shellcode(VOID);
LPVOID set_addrress_in_shellcode(EXE_file* , LPBYTE , DWORD );
DWORD get_shellcode_size();