#pragma once
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <Psapi.h>
#include <cstring>
#include <array>
#include <thread>
#include <vector>
#include <iostream>
#include <filesystem>
#include <string>
#include <Windows.h>
#include "auth.hpp"
#include <string>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <Windows.h>
#include <tlhelp32.h>
#include <thread>
#include <filesystem>
#include <fstream>
#include <filesystem>
#include <tchar.h>
#include <comdef.h>
#include <iostream>
#include <string>
#include <windows.h>
#include <iostream>
#include <Memory.h>
#include "xorstr.hpp"
#include <iostream>
#include <fstream>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

#if defined _M_X64
#pragma comment(lib, "libMinHook-x64-v141-mdd.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook-x86-v141-mdd.lib")
#endif

#pragma comment(lib, "urlmon.lib")