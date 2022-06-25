#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>
#include <stdbool.h>
#include <string.h>

#pragma warning(disable : 4996)

#define VIRUS_NAME "C:\\Users\\User\\source\\repos\\virus\\anti_virus\\virus_scanner\\virus.bin"
#define SEARCH_DIRECTORY "C:\\Users\\User\\source\\repos\\virus\\programs_to_infect"
#define CHECK_FILE "C:\\Users\\User\\source\\repos\\virus\\programs_to_infect\\msgBox4.exe"
#define CLEAR_OUTPUT "clear.txt"
#define DANGEROUS_OUTPUT "dangerous.txt"


#define ERROR 0
#define SUCCESS 1

#define in_range(number, low, high) (number >= low && number < high)

// offset of AOEP in PE format.
#define ADDRESS_OF_ENTERY_POINT_OFFSET 0x110

int get_AOEP_raw_address(byte*);
void check_all_files(char*, byte*, int, FILE*, FILE*);
void* read_entire_file(char*, int*, int*);
bool check_file(char*, byte*, int);
bool is_equal(byte*, byte*, int);
void set_full_path(char*, char*, char*);

int get_AOEP_raw_address(byte* file_data)
{
	PIMAGE_SECTION_HEADER section_header = NULL;
	PIMAGE_DOS_HEADER dos_header = file_data;
	PIMAGE_NT_HEADERS nt_headers = NULL;
	int rva_AOEP = 0;
	int AOEP_raw_address = 0;
	int section_rva_start = 0;
	int section_rva_end = 0;

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("error in getting the right dos header\n");
		return ERROR;
	}
	nt_headers = file_data + dos_header->e_lfanew;

	if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("error in getting the right NT header\n");
		return ERROR;
	}

	rva_AOEP = nt_headers->OptionalHeader.AddressOfEntryPoint;
	
	// Turn the rva to raw address.
	for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
	{
		section_header = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(nt_headers) + i;
		section_rva_start = section_header->VirtualAddress;
		section_rva_end = section_header->VirtualAddress + section_header->Misc.VirtualSize;
		if (in_range(rva_AOEP, section_rva_start, section_rva_end))
		{
			AOEP_raw_address = rva_AOEP + section_header->PointerToRawData - section_header->VirtualAddress;
			return AOEP_raw_address;
		}
	}
}


void* read_entire_file(char* file_path, int* file_size, int* result)
{
	/// <param name="file_path"> path to file </param>
	/// **out**<param name="file_size"> return size of the file </param>
	/// **out**<param name="result"> result of function </param>
	/// <returns> buffer with all of file data </returns>
	void* file_data = NULL;
	HANDLE file_handle = CreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ,          // allow multiple readers
		NULL,                     // no security
		OPEN_ALWAYS,              // open or create
		FILE_ATTRIBUTE_NORMAL,    // normal file
		NULL);                    // no attr. template 
	*file_size = GetFileSize(file_handle, 0);
	if (*file_size == 0)
	{
		*result = ERROR;
		goto end;
	}

	file_data = malloc(file_size);
	if (file_data == NULL)
	{
		*result = ERROR;
		goto end;
	}

	if (!ReadFile(file_handle, file_data, file_size, 0, NULL))
	{
		result = ERROR;
		goto end;
	}

end:
	CloseHandle(file_handle);
	return file_data;
}


bool check_file(char* path_to_file, byte* virus_data, int virus_size)
{
	/// <summary>
	/// Return true if file is clear and false if the file has been infected.
	/// </summary>

	if (strstr(path_to_file, ".exe") == NULL)
		return TRUE;
	int file_size = 0;
	int AOEP = 0;
	bool dangerus = FALSE;
	int result = SUCCESS;
	byte* file_data = read_entire_file(path_to_file, &file_size, &result);
	if (result != SUCCESS)
		goto end;

	// If file size is smaller than virus size, it can't been infected yet.
	if (virus_size > file_size)
		goto end;

	AOEP = get_AOEP_raw_address(file_data);
	dangerus = is_equal(virus_data, (file_data + AOEP), virus_size - 10);
	end:
	if (file_data != NULL)
		free(file_data);
	return !dangerus;
}

void check_all_files(char* directory_path, byte* virus_data, int virus_size, FILE* dangours_ouptut, FILE* clear_output)
{
	WIN32_FIND_DATAA ffd;
	LARGE_INTEGER filesize;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	DWORD dwError = 0;
	char directory_search_name[MAX_PATH];
	char sub_file_full_path[MAX_PATH];
	

	// Prepare string for use with FindFile functions.  First, copy the
	// string to a buffer, then append '\*' to the directory name.
	strcpy(directory_search_name, directory_path);
	strcat(directory_search_name, "\\*");

	hFind = FindFirstFileA(directory_search_name, &ffd);

	if (INVALID_HANDLE_VALUE == hFind)
	{
		return false;
	}

	// List all the files in the directory.
	do
	{
		// Hidden file
		if (*ffd.cFileName == '.')
			continue;

		set_full_path(sub_file_full_path, directory_path, ffd.cFileName);

		// Directory
		if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			check_all_files(sub_file_full_path, virus_data, virus_size, dangours_ouptut, clear_output);
			continue;
		}

		// Regular file.
		if (check_file(sub_file_full_path, virus_data, virus_size))
		{
			// File is clear.
			fprintf(clear_output, "file %s is clear\n", ffd.cFileName);
			continue;
		}

		fprintf(dangours_ouptut ,"file %s is dangerous\n", ffd.cFileName);

	} while (FindNextFileA(hFind, &ffd) != 0);

	FindClose(hFind);
}

bool is_equal(byte* buffer1, byte* buffer2, int buffers_size)
{
	for (int i = 0; i < buffers_size; i++)
	{
		if (*(buffer1 + i) != *(buffer2 + i))
		{
			return FALSE;
		}
	}
	return TRUE;
}

void set_full_path(char* output, char* path_to_file, char* file_name)
{
	strcpy(output, path_to_file);
	strcat(output, "\\");
	strcat(output, file_name);
}


int main(int argc, char* argv[])
{	
	char* search_directory = NULL;

	// Got directory from cmd input.
	if (argc == 2)
	{
		search_directory = malloc(strlen(argv[1]));
		strcpy(search_directory, argv[1]);
	}
	// Default value.
	else
	{
		search_directory = malloc(strlen(SEARCH_DIRECTORY));
		strcpy(search_directory, SEARCH_DIRECTORY);
	}
	printf("search in %s\n", search_directory);
	FILE* dangerous_output;
	FILE* clear_output;
	clear_output = fopen(CLEAR_OUTPUT, "w");
	dangerous_output = fopen(DANGEROUS_OUTPUT, "w");
	int result = SUCCESS;
	int virus_size = 0;
	char* buffer = NULL;

	byte* virus_data = read_entire_file(VIRUS_NAME, &virus_size, &result);
	if (result != SUCCESS)
	{
		printf("Error reading virus");
		goto end;
	}

	check_all_files(search_directory, virus_data, virus_size, dangerous_output, clear_output);

	end:
	if (buffer != NULL)
		free(buffer);
	fclose(dangerous_output);
	fclose(clear_output);

	return result;
}