#include <Windows.h>
#include "shellcode_header.h"

#define TO_LOWER(c){\
			if(c >= 'A' && c <= 'Z')\
				c -= 'A' - 'a';\
			}

__forceinline BOOL str_cmp(PWCHAR str1, PWCHAR str2)
{
	TO_LOWER(*str1);
	TO_LOWER(*str2);
	while (*str1 != 0 && *str2 != 0 && *str1 == *str2)
	{
		str1 += 1;
		str2 += 1;
		TO_LOWER(*str1);
		TO_LOWER(*str2);
	}
	if (*str1 == 0 && *str2 == 0)
		return TRUE;
	return FALSE;
}

__forceinline inline BOOL str_cmp2(PCHAR str1, PCHAR str2)
{
	while (*str1 != 0 && *str2 != 0 && *str1 == *str2)
	{
		str1 += 1;
		str2 += 1;
	}
	if (*str1 == 0 && *str2 == 0)
		return TRUE;
	return FALSE;
}

__forceinline LPVOID get_func_by_name(LPVOID dll, char* func_name)
{
	IMAGE_DOS_HEADER* dll_dos_header = (IMAGE_DOS_HEADER*)dll;
	if (dll_dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}
	IMAGE_NT_HEADERS* file_headers = (IMAGE_NT_HEADERS*)((BYTE*)dll + dll_dos_header->e_lfanew);
	IMAGE_DATA_DIRECTORY* export_directory = &(file_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	if (export_directory->VirtualAddress == NULL) {
		return NULL;
	}
	DWORD expAddr = export_directory->VirtualAddress;
	IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR)dll);
	SIZE_T namesCount = exp->NumberOfNames;
	DWORD funcsListRVA = exp->AddressOfFunctions;
	DWORD funcNamesListRVA = exp->AddressOfNames;
	DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;
	//go through names:
	for (SIZE_T i = 0; i < namesCount; i++) {
		DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*)dll + i * sizeof(DWORD));
		WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*)dll + i * sizeof(WORD));
		DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*)dll + (*nameIndex) * sizeof(DWORD));
		LPSTR curr_name = (LPSTR)(*nameRVA + (BYTE*)dll);
		if (str_cmp2(func_name, curr_name))
			//found
			return (BYTE*)dll + (*funcRVA);
	}
	return NULL;
}

__forceinline LPVOID get_module_by_name(PWCHAR module_name)
{
	PPEB peb;
	peb = 0;
	/*_asm
	{
		mov eax, fs: [0x30]
		mov[peb], eax
	}*/
#if defined(_WIN64)
	peb = (PPEB)__readgsqword(0x60);
#else
	peb = (PPEB)__readfsdword(0x30);
#endif
	PPEB_LDR_DATA ldr = peb->Ldr;
	LIST_ENTRY list = ldr->InLoadOrderModuleList;
	PLDR_DATA_TABLE_ENTRY Flink = *((PLDR_DATA_TABLE_ENTRY*)(&list));
	PLDR_DATA_TABLE_ENTRY curr_module = Flink;
	PWCHAR curr_name = NULL;
	while (curr_module != NULL && curr_module->BaseAddress != NULL) {
		if (curr_module->BaseDllName.Buffer == NULL) continue;
		curr_name = curr_module->BaseDllName.Buffer;
		if (str_cmp(curr_name, module_name))
			//found
			return curr_module->BaseAddress;
		// not found, try next:
		curr_module = (PLDR_DATA_TABLE_ENTRY)curr_module->InLoadOrderModuleList.Flink;
	}
	return NULL;
}

int main(VOID)
{
	HMODULE user32_dll;
	DWORD* dwptr;
	HANDLE hProcess;
	char msg_box_content[] = { 'e','x','p','l','o','r','e','r','.','e','x','e',0 };
	WCHAR user32_dll_name[] = { 'u', 's', 'e', 'r', '3','2','.','d','l','l', 0 };
	char msgbox_name[] = { 'M', 'e', 's', 's', 'a','g','e','B','o','x', 'A', 0 };


	user32_dll = get_module_by_name(user32_dll_name);
	DWORD(WINAPI * msgbox)(_In_opt_ HWND hwnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType) =
		(int (WINAPI*)(_In_opt_ HWND, _In_opt_ LPCSTR, _In_opt_ LPCSTR, _In_ UINT)) get_func_by_name(user32_dll, msgbox_name);
	msgbox(NULL, msg_box_content, msg_box_content, 0);
	MessageBoxA(NULL, msg_box_content, msg_box_content, 0);
	_asm
	{
		nop
	}
}