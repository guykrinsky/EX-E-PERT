#include <Windows.h>
#include <stdio.h>
#include "shellcode_test.h"

#define ORIGINAL_ENTERY_ADDRESS_PLACE_HOLDER 0xBBBBBBBB

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
	char current_char_a = '0';
	char current_char_b = '0';
	do
	{
		current_char_a = *str1;
		current_char_b = *str2;
		TO_LOWER(current_char_a);
		TO_LOWER(current_char_b);
		str1 += 1;
		str2 += 1;
	} 	while (*str1 != 0 && *str2 != 0 && current_char_a == current_char_b);
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
	_asm
	{
		mov eax, fs: [0x30]
		mov[peb], eax
	}
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
	HMODULE user32_dll = NULL;
	DWORD* dwptr;
	HANDLE hProcess;
	char msg_box_content[] = { 'e','x','p','l','o','r','e','r','.','e','x','e',0 };
	char user32_dll_name[] = { 'u', 's', 'e', 'r', '3','2','.','d','l','l', 0 };
	char msgbox_name[] = { 'M', 'e', 's', 's', 'a','g','e','B','o','x', 'A', 0 };
	char load_library_name[] = { 'l', 'o', 'a', 'd', 'l', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
	char get_proc_address_name[] = { 'g', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0 };
	WCHAR kernel32_dll_name[] = { 'K', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0 };
	HMODULE kernel32_dll;

	// Get kernel32.dll
	kernel32_dll = get_module_by_name(kernel32_dll_name);
	if (kernel32_dll == NULL)
		goto end;

	// Get load library function.
	HMODULE(WINAPI * M_loadLibraryA)(_In_opt_ LPCSTR lpLibFileName) =
		(HMODULE(WINAPI*)(_In_opt_ LPCSTR)) get_func_by_name(kernel32_dll, load_library_name);
	if (M_loadLibraryA == NULL)
		goto end;

	// Get getProcAddress's 
	FARPROC(WINAPI * M_getProcAddress)(_In_opt_ HMODULE hModule, _In_opt_ LPCSTR lProcName) =
		(FARPROC(WINAPI*)(_In_opt_ HMODULE, _In_opt_ LPCSTR)) get_func_by_name(kernel32_dll, get_proc_address_name);
	if (M_getProcAddress == NULL)
		goto end;

	// Get user32.dll
	user32_dll = M_loadLibraryA(user32_dll_name);
	if (user32_dll == NULL)
	{
		printf("%d", GetLastError());
		goto end;
	}
	// Get messageBoxA function
	DWORD(WINAPI * M_messageBoxA)(_In_opt_ HWND hwnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType) =
		(int (WINAPI*)(_In_opt_ HWND, _In_opt_ LPCSTR, _In_opt_ LPCSTR, _In_ UINT)) M_getProcAddress(user32_dll, msgbox_name);
	M_messageBoxA(NULL, msg_box_content, msg_box_content, 0);

	MessageBoxA(NULL, msg_box_content, msg_box_content, 0);
end:
	return 0;
}