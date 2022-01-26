#pragma once

enum return_codes
{
	RC__UNINSTALLIZED = -1,
	RC__SUCCESS = 0,
	RC__ERROR_OPEN_FILE
};

typedef enum return_codes return_codes_t;