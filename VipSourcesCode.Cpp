
#include <iostream>
#include "Memory.h"
#include "pch.h"               		                 // CREDIT BY VIPSOURCES CODE: t.me/vipsourcescode/19							         // CREDIT BY VIPSOURCES CODE: t.me/vipsourcescode/19
#include "resource.h"						         // CREDIT BY VIPSOURCES CODE: t.me/vipsourcescode/19
#include "termcolor.hpp"						     // CREDIT BY VIPSOURCES CODE: t.me/vipsourcescode/19
#include <filesystem>								 // CREDIT BY VIPSOURCES CODE: t.me/vipsourcescode/19
#include "mem.h"								     // CREDIT BY VIPSOURCES CODE: t.me/vipsourcescode/19
#include <fstream>									 // CREDIT BY VIPSOURCES CODE: t.me/vipsourcescode/19
#include <Windows.h>								 // CREDIT BY VIPSOURCES CODE: t.me/vipsourcescode/19
#include <tlhelp32.h>								 // CREDIT BY VIPSOURCES CODE: t.me/vipsourcescode/19
#include <thread>									 // CREDIT BY VIPSOURCES CODE: t.me/vipsourcescode/19
#include <filesystem>		                         // CREDIT BY VIPSOURCES CODE: t.me/vipsourcescode/19
#include "xorstr.hpp"						         // CREDIT BY VIPSOURCES CODE: t.me/vipsourcescode/19
#include "MD5.h"		                              
#include <Windows.h>
#include <string>
#include "api/skStr.h"                            
#pragma comment(lib, "urlmon.lib")					
                                              
#if defined _urlmon
#pragma comment(lib, ""urlmon.lib")
#elif defined _urlmon2
#pragma comment(lib, "urlmon.lib")
#endif
using namespace std;								
std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);

using namespace KeyAuth;

std::string name = ""; // application name. right above the blurred text aka the secret on the licenses tab among other tabs
std::string ownerid = ""; // ownerid, found in account settings. click your profile picture on top right of dashboard and then account settings.
std::string secret = ""; // app secret, the blurred text on licenses tab and other tabs
std::string version = "1.0"; // leave alone unless you've changed version on website
std::string url = "https://keyauth.win/api/1.2/"; // change if you're self-hosting

/*
	Video on what ownerid and secret are https://youtu.be/uJ0Umy_C6Fg

	Video on how to add KeyAuth to your own application https://youtu.be/GB4XW_TsHqA

	Video to use Web Loader (control loader from customer panel) https://youtu.be/9-qgmsUUCK4
*/

api KeyAuthApp(name, ownerid, secret, version, url);


string readFile(string location)                                        
{
	string myText;
	ifstream MyReadFile(location);
	while (getline(MyReadFile, myText)) {
		cout << myText;
	}
	MyReadFile.close();
	return myText;
}
void writeToFile(string filepath, string credentials)
{
	ofstream MyFile(filepath);
	MyFile << credentials;
	MyFile.close();
}

inline bool FileExist(const std::string& name) {
	FILE* file = nullptr;
	errno_t err = fopen_s(&file, name.c_str(), "r");
	if (err == 0 && file != nullptr) {
		fclose(file);
		return true;
	}
	else {
		return false;
	}
}

bool login() {
	static char str0[128] = "";
	std::string token = "";
	bool login = false;
	if (FileExist(("MyKey.lic")))
	{
		std::ifstream MyFile(("MyKey.lic"));
		getline(MyFile, token);
		MyFile.close();
		KeyAuthApp.license(token);
		if (!KeyAuthApp.data.success) {
			std::cout << ("[+] Wrong Key");
			Sleep(500);
			std::cout << (". ");
			Sleep(500);
			std::cout << (". ");
			Sleep(500);
			std::cout << (". ");
			Sleep(500);
			system(("cls"));
			system("del MyKey.lic");
			return false;
			goto again;
		}
		else if (KeyAuthApp.data.success)
		{
			std::cout << termcolor::bright_yellow << "License : " << token << std::endl;
			Sleep(500);
			std::cout << termcolor::bright_green << "Successfully logged in !!! \n";
			Sleep(500);


			time_t rawtime;
			struct tm* timeinfo;
			std::cout << termcolor::bright_yellow << "Expires on : " << tm_to_readable_time(timet_to_tm(string_to_timet(KeyAuthApp.data.expiry)));

			std::cout << termcolor::bright_yellow << "...............................................................................\n";
			return true;
		}

	
	}
	else {
		AllocConsole();
		FILE* fDummy;
		freopen_s(&fDummy, "CONOUT$", "w+", stdout);
		freopen_s(&fDummy, "CONIN$", "w+", stdin);
		freopen_s(&fDummy, "CONOUT$", "w", stderr);
	again:
		
		std::cout << termcolor::bright_blue << "Enter your key \n";
		std::cin >> token;
		KeyAuthApp.license(token);
		if (!KeyAuthApp.data.success) {
			std::cout << ("[+] Wrong Key");
			Sleep(500);
			std::cout << (". ");
			Sleep(500);
			std::cout << (". ");
			Sleep(500);
			std::cout << (". ");
			Sleep(500);
			system(("cls"));
			system("del MyKey.lic");
			return false;
			goto again;
		}
		else if (KeyAuthApp.data.success) {
			Sleep(500);
			std::cout << termcolor::bright_green << "Successfully logged in !!! \n";
			Sleep(500);
			time_t rawtime;
			struct tm* timeinfo;
			std::cout << termcolor::bright_yellow << "Expires on : " << tm_to_readable_time(timet_to_tm(string_to_timet(KeyAuthApp.data.expiry)));

			std::cout << termcolor::bright_yellow << "...............................................................................\n";
			Sleep(1000);
			std::ofstream MyFile(("MyKey.lic"));
			MyFile << token;
			MyFile.close();
			return true;
		}
	}
	return false;
}

void findAndReplaceAll(std::string& data, std::string toSearch, std::string replaceStr)
{
	size_t pos = data.find(toSearch);
	while (pos != std::string::npos)
	{
		data.replace(pos, toSearch.size(), replaceStr);
		pos = data.find(toSearch, pos + replaceStr.size());
	}
}

void cmdd(string text)
{
	string prim = "/c " + text;
	const char* primm = prim.c_str();
	ShellExecute(0, "open", "cmd.exe", (LPCSTR)primm, 0, SW_HIDE);
}

void firewallblock()
{
	cmdd("Reg.exe add HKCU\\Software\\Tencent\\MobileGamePC /v AdbDisable /t REG_DWORD /d 0 /f");
	cmdd("netsh advfirewall firewall add rule name=GameLoop protocol=ANY dir=out remoteip=203.205.239.243,123.151.71.34 action=block enable=yes");
}

void startEmulator(int choices)
{

	if (choices == 1)
	{
		WinExec("C:\\WINDOWS\\driver.exe", 0);
		if (FileExist("C:\\Program Files (x86)\\SmartGaGa\\ProjectTitan\\Engine\\ProjectTitan.exe"))
		{
			ShellExecute(NULL, "open", "C:\\Program Files (x86)\\SmartGaGa\\ProjectTitan\\Engine\\ProjectTitan.exe", NULL, NULL, SW_SHOWDEFAULT);
		}
		else if(FileExist("D:\\Program Files (x86)\\SmartGaGa\\ProjectTitan\\Engine\\ProjectTitan.exe"))
		{
			ShellExecute(NULL, "open", "D:\\Program Files (x86)\\SmartGaGa\\ProjectTitan\\Engine\\ProjectTitan.exe", NULL, NULL, SW_SHOWDEFAULT);
		}
		else if (FileExist("E:\\Program Files (x86)\\SmartGaGa\\ProjectTitan\\Engine\\ProjectTitan.exe"))
		{
			ShellExecute(NULL, "open", "E:\\Program Files (x86)\\SmartGaGa\\ProjectTitan\\Engine\\ProjectTitan.exe", NULL, NULL, SW_SHOWDEFAULT);
		}
		else if (FileExist("F:\\Program Files (x86)\\SmartGaGa\\ProjectTitan\\Engine\\ProjectTitan.exe"))
		{
			ShellExecute(NULL, "open", "F:\\Program Files (x86)\\SmartGaGa\\ProjectTitan\\Engine\\ProjectTitan.exe", NULL, NULL, SW_SHOWDEFAULT);
		}
		else
		{
			std::cout << termcolor::bright_red << "\n[!] Please install the emulator properly\n";
			return;
		}
	}
	if (choices == 2)
	{
		HKEY key;
		LONG succeeded;
		std::string keyname = "SOFTWARE\\WOW6432Node\\Tencent\\MobileGamePC\\";
		std::string processor_name;
		vector<string> processor_list;

		succeeded = RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyname.c_str(), NULL, KEY_READ, &key);
		if (succeeded == ERROR_SUCCESS)
		{
			const char* value = "";
			DWORD value_size = 0;
			char buf[255];
			HKEY key1;
			string name = keyname + "UI";
			succeeded = RegOpenKey(HKEY_LOCAL_MACHINE, name.c_str(), &key1);
			if (succeeded == ERROR_SUCCESS)
			{
				value_size = sizeof(buf);
				memset(buf, 0, sizeof(buf));
				succeeded = RegQueryValueEx(key1, "InstallPath", 0, 0, (unsigned char*)buf, &value_size);
				if (succeeded == ERROR_SUCCESS)
				{
					string emudir = buf;
					string aedir = emudir + "\\AndroidEmulator.exe";
					aedir.insert(0, 1, '"');
					findAndReplaceAll(aedir, ".exe", ".exe\"");
					string aedirx = aedir + " -vm 100";
					WinExec("C:\\WINDOWS\\driver.exe", 0);
					cmdd(aedirx.c_str());
				}
				RegCloseKey(key1);
			}
		}
		else
		{
			std::cout << termcolor::bright_red << "\n[!] Please install the emulator properly\n";
		}
		RegCloseKey(key);
	}
	if (choices == 3)
	{
		HKEY key;
		LONG succeeded;
		std::string keyname = "SOFTWARE\\WOW6432Node\\Tencent\\MobileGamePC\\";
		std::string processor_name;
		vector<string> processor_list;

		succeeded = RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyname.c_str(), NULL, KEY_READ, &key);
		if (succeeded == ERROR_SUCCESS)
		{
			const char* value = "";
			DWORD value_size = 0;
			char buf[255];
			HKEY key1;
			string name = keyname + "UI";
			succeeded = RegOpenKey(HKEY_LOCAL_MACHINE, name.c_str(), &key1);
			if (succeeded == ERROR_SUCCESS)
			{
				value_size = sizeof(buf);
				memset(buf, 0, sizeof(buf));
				succeeded = RegQueryValueEx(key1, "InstallPath", 0, 0, (unsigned char*)buf, &value_size);
				if (succeeded == ERROR_SUCCESS)
				{
					string emudir = buf;
					string aedir = emudir + "\\AndroidEmulatorEn.exe";
					aedir.insert(0, 1, '"');
					findAndReplaceAll(aedir, ".exe", ".exe\"");
					string aedirx = aedir + " -vm 100";
					WinExec("C:\\WINDOWS\\driver.exe", 0);
					cmdd(aedirx.c_str());
				}
				RegCloseKey(key1);
			}
		}
		else
		{
			std::cout << termcolor::bright_red << "\n[!] Please install the emulator properly\n";
		}
		RegCloseKey(key);
	}
}

string  gen_random(int len) {
	string s;
	static const char alphanum[] =
		"0123456789";
	for (int i = 0; i < len; ++i) {
		s += alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	return s;
}

string  gen_random2(int len) {
	string s;
	static const char alphanum[] =
		"0123456789"
		"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i) {
		s += alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	return s;
}

void fixemuid()
{
	/*if (choice == 1)
	{
		ShellExecute(0, "open", "C:\\Windows\\Global.bat", NULL, 0, SW_HIDE);
	}
	if (choice == 2)
	{
		ShellExecute(0, "open", "C:\\Windows\\Bgmi.bat", NULL, 0, SW_HIDE);
	}
	if (choice == 3)
	{
		ShellExecute(0, "open", "C:\\Windows\\Korea.bat", NULL, 0, SW_HIDE);
	}
	if (choice == 4)
	{
		ShellExecute(0, "open", "C:\\Windows\\vietnam.bat", NULL, 0, SW_HIDE);
	}
	if (choice == 5)
	{
		ShellExecute(0, "open", "C:\\Windows\\Tiwan.bat", NULL, 0, SW_HIDE);
	}*/
}

void startGame(int choice, int mode)
{
	if (choice == 1)
	{
		system("adb shell rm -rf /data/data/com.tencent.ig/app_bugly");
		system("adb shell rm -rf /data/data/com.tencent.ig/databases");
		system("adb shell rm -rf /data/data/com.tencent.ig/app_crashrecord");
		system("adb shell rm -rf /data/data/com.tencent.ig/app_texures");
		system("adb shell rm -rf /data/data/com.tencent.ig/app_webview");
		system("adb shell rm -rf /data/data/com.tencent.ig/cache");
		system("adb shell rm -rf /data/data/com.tencent.ig/code_cache");
		system("adb shell rm -rf /data/data/com.tencent.ig/files");
		system("adb shell rm -rf /data/data/com.tencent.ig/no_backup");
		system("adb shell rm -rf /data/data/com.tencent.ig/shared_prefs");
		system("adb shell touch /data/data/com.tencent.ig/{app_bugly,app_crashrecord,files}");
		system("adb shell chmod 771 /data/data/com.tencent.ig/{app_bugly,app_crashrecord,files}");
		system("adb shell chown root:root /data/data/com.tencent.ig/{app_bugly,app_crashrecord,files}");
		system("adb shell rm -rf /storage/emulated/0/.backups");
		system("adb shell rm -rf /storage/emulated/0/ASD");
		system("adb shell rm -rf /storage/emulated/0/*_*_*.dat");
		system("adb shell rm -rf /storage/emulated/0/.sys");
		system("adb shell rm -rf /storage/emulated/0/.zzz");
		system("adb shell rm -rf /storage/emulated/0/Android/{.sys,.system_android_l2}");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/cache");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/*_*_*.dat");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/log");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/ProgramBinaryCache");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/TGPA");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/.fff");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/system_android_l2");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/ca-bundle.pem");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/hawk_data");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/login-identifier.txt");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/Engine");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Intermediate");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Avatar");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Demos");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/ImageDownload");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Logs");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/MMKV");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/MoviesPaksDir");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Pandora");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferEifs0");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferEifs1");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferTmpDir");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/rawdata");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/RoleInfo");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/SaveGames/{Login,LoginBackUp,*.json,Chaced.sav}");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/TableDatas");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/UpdateInfo");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/coverversion.ini");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/GameErrorNoRecords");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.tencent.ig/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/StatEventReportedFlag");
		cmdd("adb shell am start -n com.tencent.ig/com.epicgames.ue4.SplashActivity");
	}
	if (choice == 2)
	{
		system("adb shell rm -rf /data/data/com.pubg.imobile/app_*");
		system("adb shell rm -rf /data/data/com.pubg.imobile/app_*_*");
		system("adb shell rm -rf /data/data/com.pubg.imobile/app_*_*_*");
		system("adb shell rm -rf /data/data/com.pubg.imobile/cache");
		system("adb shell rm -rf /data/data/com.pubg.imobile/code_cache");
		system("adb shell rm -rf /data/data/com.pubg.imobile/databases");
		system("adb shell rm -rf /data/data/com.pubg.imobile/files");
		system("adb shell rm -rf /data/data/com.pubg.imobile/no_backup");
		system("adb shell rm -rf /data/data/com.pubg.imobile/shared_prefs");
		system("adb shell touch /data/data/com.pubg.imobile/{app_bugly,app_crashrecord,files}");
		system("adb shell chmod 771 /data/data/com.pubg.imobile/{app_bugly,app_crashrecord,files}");
		system("adb shell chown root:root /data/data/com.pubg.imobile/{app_bugly,app_crashrecord,files}");
		system("adb shell rm -rf /storage/emulated/0/.backups");
		system("adb shell rm -rf /storage/emulated/0/ASD");
		system("adb shell rm -rf /storage/emulated/0/*_*_*.dat");
		system("adb shell rm -rf /storage/emulated/0/.sys");
		system("adb shell rm -rf /storage/emulated/0/.zzz");
		system("adb shell rm -rf /storage/emulated/0/Android/{.sys,.system_android_l2}");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/cache");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/*_*_*.dat");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/log");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/ProgramBinaryCache");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/TGPA");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/.fff");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/system_android_l2");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/ca-bundle.pem");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/hawk_data");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/login-identifier.txt");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/UE4Game/ShadowTrackerExtra/Engine");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Intermediate");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Avatar");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Demos");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/ImageDownload");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Logs");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/MMKV");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/MoviesPaksDir");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Pandora");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferEifs0");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferEifs1");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferTmpDir");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/rawdata");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/RoleInfo");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/SaveGames/{Login,LoginBackUp,*.json,Chaced.sav}");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/TableDatas");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/UpdateInfo");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/coverversion.ini");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/GameErrorNoRecords");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.imobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/StatEventReportedFlag");
		cmdd("adb shell am start -n com.pubg.imobile/com.epicgames.ue4.SplashActivity");
	}
	if (choice == 3)
	{
		system("adb shell rm -rf /data/data/com.pubg.krmobile/app_*");
		system("adb shell rm -rf /data/data/com.pubg.krmobile/app_*_*");
		system("adb shell rm -rf /data/data/com.pubg.krmobile/app_*_*_*");
		system("adb shell rm -rf /data/data/com.pubg.krmobile/cache");
		system("adb shell rm -rf /data/data/com.pubg.krmobile/code_cache");
		system("adb shell rm -rf /data/data/com.pubg.krmobile/databases");
		system("adb shell rm -rf /data/data/com.pubg.krmobile/files");
		system("adb shell rm -rf /data/data/com.pubg.krmobile/no_backup");
		system("adb shell rm -rf /data/data/com.pubg.krmobile/shared_prefs");
		system("adb shell touch /data/data/com.pubg.krmobile/{app_bugly,app_crashrecord,files}");
		system("adb shell chmod 771 /data/data/com.pubg.krmobile/{app_bugly,app_crashrecord,files}");
		system("adb shell chown root:root /data/data/com.pubg.krmobile/{app_bugly,app_crashrecord,files}");
		system("adb shell rm -rf /storage/emulated/0/.backups");
		system("adb shell rm -rf /storage/emulated/0/ASD");
		system("adb shell rm -rf /storage/emulated/0/*_*_*.dat");
		system("adb shell rm -rf /storage/emulated/0/.sys");
		system("adb shell rm -rf /storage/emulated/0/.zzz");
		system("adb shell rm -rf /storage/emulated/0/Android/{.sys,.system_android_l2}");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/cache");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/*_*_*.dat");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/log");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/ProgramBinaryCache");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/TGPA");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/.fff");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/system_android_l2");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/ca-bundle.pem");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/hawk_data");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/login-identifier.txt");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/Engine");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Intermediate");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Avatar");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Demos");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/ImageDownload");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Logs");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/MMKV");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/MoviesPaksDir");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Pandora");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferEifs0");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferEifs1");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferTmpDir");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/rawdata");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/RoleInfo");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/SaveGames/{Login,LoginBackUp,*.json,Chaced.sav}");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/TableDatas");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/UpdateInfo");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/coverversion.ini");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/GameErrorNoRecords");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.pubg.krmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/StatEventReportedFlag");
	}
	if (choice == 4)
	{
		system("adb shell rm -rf /data/data/com.vng.pubgmobile/app_*");
		system("adb shell rm -rf /data/data/com.vng.pubgmobile/app_*_*");
		system("adb shell rm -rf /data/data/com.vng.pubgmobile/app_*_*_*");
		system("adb shell rm -rf /data/data/com.vng.pubgmobile/cache");
		system("adb shell rm -rf /data/data/com.vng.pubgmobile/code_cache");
		system("adb shell rm -rf /data/data/com.vng.pubgmobile/databases");
		system("adb shell rm -rf /data/data/com.vng.pubgmobile/files");
		system("adb shell rm -rf /data/data/com.vng.pubgmobile/no_backup");
		system("adb shell rm -rf /data/data/com.vng.pubgmobile/shared_prefs");
		system("adb shell touch /data/data/com.vng.pubgmobile/{app_bugly,app_crashrecord,files}");
		system("adb shell chmod 771 /data/data/com.vng.pubgmobile/{app_bugly,app_crashrecord,files}");
		system("adb shell chown root:root /data/data/com.vng.pubgmobile/{app_bugly,app_crashrecord,files}");
		system("adb shell rm -rf /storage/emulated/0/.backups");
		system("adb shell rm -rf /storage/emulated/0/ASD");
		system("adb shell rm -rf /storage/emulated/0/*_*_*.dat");
		system("adb shell rm -rf /storage/emulated/0/.sys");
		system("adb shell rm -rf /storage/emulated/0/.zzz");
		system("adb shell rm -rf /storage/emulated/0/Android/{.sys,.system_android_l2}");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/cache");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/*_*_*.dat");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/log");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/ProgramBinaryCache");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/TGPA");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/.fff");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/system_android_l2");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/ca-bundle.pem");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/hawk_data");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/login-identifier.txt");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/Engine");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Intermediate");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Avatar");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Demos");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/ImageDownload");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Logs");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/MMKV");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/MoviesPaksDir");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Pandora");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferEifs0");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferEifs1");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferTmpDir");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/rawdata");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/RoleInfo");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/SaveGames/{Login,LoginBackUp,*.json,Chaced.sav}");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/TableDatas");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/UpdateInfo");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/coverversion.ini");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/GameErrorNoRecords");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.vng.pubgmobile/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/StatEventReportedFlag");
		cmdd("adb shell am start -n com.vng.pubgmobile/com.epicgames.ue4.SplashActivity");
	}
	if (choice == 5)
	{
		system("adb shell rm -rf /data/data/com.rekoo.pubgm/app_*");
		system("adb shell rm -rf /data/data/com.rekoo.pubgm/app_*_*");
		system("adb shell rm -rf /data/data/com.rekoo.pubgm/app_*_*_*");
		system("adb shell rm -rf /data/data/com.rekoo.pubgm/cache");
		system("adb shell rm -rf /data/data/com.rekoo.pubgm/code_cache");
		system("adb shell rm -rf /data/data/com.rekoo.pubgm/databases");
		system("adb shell rm -rf /data/data/com.rekoo.pubgm/files");
		system("adb shell rm -rf /data/data/com.rekoo.pubgm/no_backup");
		system("adb shell rm -rf /data/data/com.rekoo.pubgm/shared_prefs");
		system("adb shell touch /data/data/com.rekoo.pubgm/{app_bugly,app_crashrecord,files}");
		system("adb shell chmod 771 /data/data/com.rekoo.pubgm/{app_bugly,app_crashrecord,files}");
		system("adb shell chown root:root /data/data/com.rekoo.pubgm/{app_bugly,app_crashrecord,files}");
		system("adb shell rm -rf /storage/emulated/0/.backups");
		system("adb shell rm -rf /storage/emulated/0/ASD");
		system("adb shell rm -rf /storage/emulated/0/*_*_*.dat");
		system("adb shell rm -rf /storage/emulated/0/.sys");
		system("adb shell rm -rf /storage/emulated/0/.zzz");
		system("adb shell rm -rf /storage/emulated/0/Android/{.sys,.system_android_l2}");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/cache");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/*_*_*.dat");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/log");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/ProgramBinaryCache");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/TGPA");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/.fff");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/system_android_l2");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/ca-bundle.pem");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/hawk_data");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/login-identifier.txt");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/Engine");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Intermediate");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Avatar");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Demos");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/ImageDownload");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Logs");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/MMKV");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/MoviesPaksDir");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Pandora");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferEifs0");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferEifs1");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/PufferTmpDir");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/rawdata");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/RoleInfo");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/SaveGames/{Login,LoginBackUp,*.json,Chaced.sav}");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/TableDatas");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/UpdateInfo");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/coverversion.ini");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/GameErrorNoRecords");
		system("adb shell rm -rf /storage/emulated/0/Android/data/com.rekoo.pubgm/files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/StatEventReportedFlag");
		cmdd("adb shell am start -n com.rekoo.pubgm/com.epicgames.ue4.SplashActivity");
	}
}

int getEmuID() {
	int pid = 0;
	int threadCount = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnap, &pe);
	while (Process32Next(hSnap, &pe)) {
		if (strcmp(pe.szExeFile, "AndroidEmulatorEx.exe") == 0) {
			if ((int)pe.cntThreads > threadCount) {
				threadCount = pe.cntThreads;
				pid = pe.th32ProcessID;
			}
		}
	}

	return pid;
}

int getEmuID2() {
	int pid = 0;
	int threadCount = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnap, &pe);
	while (Process32Next(hSnap, &pe)) {
		if (strcmp(pe.szExeFile, "ProjectTitan.exe") == 0) {
			if ((int)pe.cntThreads > threadCount) {
				threadCount = pe.cntThreads;
				pid = pe.th32ProcessID;
			}
		}
	}

	return pid;
}

int getEmuProcID()
{
	int pid = 0;
	int gameloop = 0;
	int smartgaga = 0;
	gameloop = getEmuID();
	smartgaga = getEmuID2();
	if (smartgaga == 0 || smartgaga == 1)
	{
		if (gameloop == 0 || gameloop == 1)
		{
			return gameloop;
		}
		else
		{
			return gameloop;
		}
	}
	else
	{
		return smartgaga;
	}
}



std::string executee(const char* cmd) {
	std::array<char, 128> buffer;
	std::string result;
	std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd, "r"), _pclose);
	if (!pipe) {
		throw std::runtime_error("popen() failed!");
	}
	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
		result += buffer.data();
	}
	return result;
}

int isSubstring(string s1, string s2)
{
	int M = s1.length();
	int N = s2.length();
	for (int i = 0; i <= N - M; i++) {
		int j;
		for (j = 0; j < M; j++)
			if (s2[i + j] != s1[j])
				break;

		if (j == M)
			return i;
	}

	return -1;
}

typedef LONG(NTAPI* NtSuspendProcess)(IN HANDLE ProcessHandle);

typedef LONG(WINAPI* RtlAdjustPrivilege)(DWORD, BOOL, INT, PBOOL);


void suspend(DWORD processId)
{
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	NtSuspendProcess pfnNtSuspendProcess = (NtSuspendProcess)GetProcAddress(
		GetModuleHandleA("ntdll"), "NtSuspendProcess");

	pfnNtSuspendProcess(processHandle);
	CloseHandle(processHandle);
}

typedef LONG(NTAPI* NtResumeProcess)(IN HANDLE ProcessHandle);

typedef LONG(WINAPI* RtlAdjustPrivilege)(DWORD, BOOL, INT, PBOOL);

void resume(DWORD processId)
{
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	NtResumeProcess pfnNtResumeProcess = (NtResumeProcess)GetProcAddress(
		GetModuleHandleA("ntdll"), "NtResumeProcess");

	pfnNtResumeProcess(processHandle);
	CloseHandle(processHandle);
}

int getue4header()
{
	int libue4header = 0;
	BYTE ue4head[] = { 0x7F, 0x45, 0x4C, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x24, 0x26, 0x8A, 0x07, 0x00, 0x02, 0x00, 0x05, 0x34, 0x00, 0x20, 0x00, 0x0A, 0x00, 0x28, 0x00, 0x1A, 0x00, 0x19, 0x00, 0x06, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x74, 0x01, 0x00, 0x00, 0x74, 0x01, 0x00, 0x00, 0x74, 0x01, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	libue4header = SINGLEAOBSCAN(ue4head, sizeof(ue4head));
	return libue4header;
}

int getlibtersafeheader()
{
	int libtersafeheader = 0;
	BYTE tersafehead[] = { 0x7F,0x45,0x4C,0x46,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,0x00,0x28,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x58,0xCD,0x3C,0x00,0x00,0x02,0x00,0x05,0x34,0x00,0x20,0x00,0x08,0x00,0x28,0x00,0x1D,0x00,0x1C,0x00,0x06,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x34,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x04,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	libtersafeheader = SINGLEAOBSCAN2(tersafehead, sizeof(tersafehead));
	return libtersafeheader;
}
void offsetsearch(int offset, int header, int parameter)
{

	DWORD pid = getProcId();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	int addr = header + offset + parameter;
	BYTE ok;
	ReadProcessMemory(phandle, (LPCVOID)addr, &ok, 1, nullptr);
	if (ok != 0xE1)
	{
		MessageBoxA(0, "wtf", 0, 0);
	}
	BYTE write[] = { 0xE3 };
	unsigned long OldProtect;
	unsigned long OldProtect2;
	VirtualProtectEx(phandle, (BYTE*)addr, 1, PAGE_EXECUTE_READWRITE, &OldProtect);
	WriteProcessMemory(phandle, (BYTE*)addr, write, 1, NULL);
	VirtualProtectEx(phandle, (BYTE*)addr, 1, OldProtect, NULL);
}
HANDLE phandle;
void ReplaceOffset(int offset, BYTE write[], SIZE_T size, int header)
{
	int addr = header + offset;
	unsigned long OldProtect;
	unsigned long OldProtect2;
	VirtualProtectEx(phandle, (BYTE*)addr, size, PAGE_EXECUTE_READWRITE, &OldProtect);
	WriteProcessMemory(phandle, (BYTE*)addr, write, size, NULL);
	VirtualProtectEx(phandle, (BYTE*)addr, size, OldProtect, NULL);
}

void print(string text, int colorchoice)
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    // you can loop k higher to see more color choices
    // pick the colorattribute k you want
    SetConsoleTextAttribute(hConsole, colorchoice);
    // cout << text;
    for (int j = 0; j < text.size(); j++)
    {
        Sleep(15);
        cout << text[j];
    }
}

int getbgmiheader()
{
	int libue4header = 0;
	BYTE ue4head[] = { 0x7F, 0x45, 0x4C, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x24, 0x66, 0x67, 0x07, 0x00, 0x02, 0x00, 0x05, 0x34, 0x00, 0x20, 0x00, 0x0A, 0x00, 0x28, 0x00 };
	libue4header = SINGLEAOBSCAN(ue4head, sizeof(ue4head));
	return libue4header;
}

void WriteResToDisk(std::string PathFile, LPCSTR File_WITHARG)
{
	HRSRC myResource = ::FindResource(NULL, (LPCSTR)File_WITHARG, RT_RCDATA);
	unsigned int myResourceSize = ::SizeofResource(NULL, myResource);
	HGLOBAL myResourceData = ::LoadResource(NULL, myResource);
	void* pMyExecutable = ::LockResource(myResourceData);
	std::ofstream f(PathFile, std::ios::out | std::ios::binary);
	f.write((char*)pMyExecutable, myResourceSize);
	f.close();
}

void bgmisafemode(int bgmiheader, int libtersafeheader)
{

}

void bgmibrutalmode(int bgmiheader, int libtersafeheader)
{

}


std::vector<std::string> SplitString(const std::string& str, const std::string& delimeter)
{
	std::vector<std::string> Return;
	auto start = 0U;
	auto end = str.find(delimeter);
	while (end != std::string::npos)
	{
		Return.push_back(str.substr(start, end - start));
		start = end + delimeter.length();
		end = str.find(delimeter, start);
	}

	Return.push_back(str.substr(start, end));
	return Return;
}
//MUST JOIN : t.me/vipsourcecode
struct Aob_byte {
	int x;
	bool f;
};

std::vector<Aob_byte> convert_pattern(const std::string& pattern)
{
	std::vector<Aob_byte> ret;
	auto parts = SplitString(pattern, " ");
	for (const auto& part : parts)
	{
		if (part == "??")
		{
			ret.emplace_back(Aob_byte{ 0, false });
		}
		else
		{
			ret.emplace_back(Aob_byte{ static_cast<BYTE>(std::stoi(part, nullptr, 16)), true });
		}
	}

	return ret;
}
int libue4header;
int libtersafeheader;
int bgmiheader;
void writeBytess(int offsets, string bytearray)
{
	std::vector<Aob_byte> shit = convert_pattern(bytearray);
	int size = shit.size();
	BYTE* tmp = new BYTE[size];
	for (int i = 0; i < size; i++)
	{
		tmp[i] = shit[i].x;
	}
	if (libue4header > 0x1000)
	{
		ReplaceOffset(offsets, tmp, size, libue4header);
	}
	else
	{
		ReplaceOffset(offsets, tmp, size, bgmiheader);
	}
	delete[] tmp;
}

void safeExit()
{
	ShellExecute(0, "open", "C:\\Windows\\Exit.bat", NULL, 0, SW_HIDE);
	Sleep(1000);
	exit(0);
}

void sitflyop()
{
	/*BYTE sitfly[] = {  };
	BYTE sitflyop[] = {  };
	AOBREPSILENT2(sitfly, sitflyop, sizeof(sitfly), sizeof(sitflyop), 0);*/
}

int checks;
int offset;
vector<DWORD_PTR> tmpbuff;
bool patcherr(long addr, BYTE write[], SIZE_T sizee) {
	unsigned long OldProtect;
	unsigned long OldProtect2;
	VirtualProtectEx(phandle, (void*)addr, sizee, PAGE_EXECUTE_READWRITE, &OldProtect);
	WriteProcessMemory(phandle, (void*)addr, write, sizee, NULL);
	VirtualProtectEx(phandle, (void*)addr, sizee, OldProtect, NULL);
	return true;
}

void writeBytes() {
	int size = tmpbuff.size();
	BYTE* tmp = new BYTE[size];
	for (int i = 0; i < size; i++)
	{
		tmp[i] = tmpbuff[i];
	}
	patcherr(offset, tmp, sizeof(tmp));
	delete[] tmp;
	//clear stacks
	offset = 0;
	checks = 0;
	tmpbuff.clear();
}

template<typename First, typename ... Strings>
void writeBytes(First arg, const Strings&... rest) {
	if (checks == 0)
	{
		offset = (unsigned int)arg;
		//cout << offset << endl;
		checks++;
	}
	else
	{
		tmpbuff.push_back((unsigned int)arg);
	}
	writeBytes(rest...);
}
#pragma endregion
//MUST JOIN : t.me/vipsourcecode
HANDLE GetProcessByName(PCSTR name)
{
	DWORD pid = 0;

	// Create toolhelp snapshot.
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 process;
	ZeroMemory(&process, sizeof(process));
	process.dwSize = sizeof(process);

	// Walkthrough all processes.
	if (Process32First(snapshot, &process))
	{
		do
		{
			if (string(process.szExeFile) == string(name))
			{
				pid = process.th32ProcessID;
				break;
			}
		} while (Process32Next(snapshot, &process));
	}

	CloseHandle(snapshot);

	if (pid != 0)
	{
		return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	}

	return NULL;
}

int main()
{
    SetConsoleTitleA("USMAN AKHTAR BYPASS");
    HWND console = GetConsoleWindow();
    RECT ConsoleRect;
    GetWindowRect(console, &ConsoleRect);
    MoveWindow(console, ConsoleRect.top, ConsoleRect.left, 680, 600, TRUE); //can change console size from here
	std::cout << termcolor::bright_blue << R"(
         _   _                              ___  _    _     _             
        | | | |                            / _ \| |  | |   | |            
        | | | |___ _ __ ___   __ _ _ __   / /_\ \ | _| |__ | |_ __ _ _ __ 
        | | | / __| '_ ` _ \ / _` | '_ \  |  _  | |/ / '_ \| __/ _` | '__|
        | |_| \__ \ | | | | | (_| | | | | | | | |   <| | | | || (_| | |   
         \___/|___/_| |_| |_|\__,_|_| |_| \_| |_/_|\_\_| |_|\__\__,_|_| 
)" << '\n';

	std::cout << termcolor::bright_green << "-------------------------------------------------------------------------------\n";
    std::cout << termcolor::bright_yellow << "                      Pubg ver = ";
    std::cout << termcolor::bright_green << "2.0     ";
    std::cout << termcolor::bright_yellow << "     BP Ver = ";
    std::cout << termcolor::bright_green << "1.0 \n";
    std::cout << termcolor::bright_green << "-------------------------------------------------------------------------------\n";

    KeyAuthApp.init();
    if (!login())
        exit(0);

    if (!FileExist("C:\\hookdrv.sys"))
    {
       // HRESULT hr = URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/899968134805598208/961116635278741514/hookdrv.sys"), _T("C:\\hookdrv.sys"), 0, NULL);
    }

    cmdd(("sc create driver binPath=\"C:\\hookdrv.sys\" type=filesys"));
    cmdd(("sc start driver"));

    remove("C:\\Windows\\Exit.bat");

    if (!FileExist("C:\\Windows\\adb.exe"))
    {
       // HRESULT hr = URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/900270366964989982/905386597707563038/adb.exe"), _T("C:\\Windows\\adb.exe"), 0, NULL);
    }
    if (!FileExist("C:\\Windows\\AdbWinApi.dll"))
    {
       // HRESULT hr = URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/900270366964989982/905386592909271070/AdbWinApi.dll"), _T("C:\\Windows\\AdbWinApi.dll"), 0, NULL);
    }
    if (!FileExist("C:\\Windows\\Exit.bat"))
    {
      //  HRESULT hr = URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/899968134805598208/961116692379992084/Kill_All.bat"), _T("C:\\Windows\\Exit.bat"), 0, NULL);
    }
    if (!FileExist("C:\\Windows\\UserCustom.ini"))
    {
      //  HRESULT hr = URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/899968134805598208/961116746457178142/UserCustom.ini"), _T("C:\\Windows\\UserCustom.ini"), 0, NULL);
    }

	if (!FileExist("C:\\Windows\\driver.exe"))
	{
		//HRESULT hr = URLDownloadToFile(NULL, _T("https://cdn.discordapp.com/attachments/933395385966297148/961322792010276916/driver.sys"), _T("C:\\Windows\\driver.exe"), 0, NULL);
	}

    int emu;
    int game;
    /*int IPAD;*/
	/*int nohead;*/
	/*int fixflash;*/
	/*int slowmotion;*/
    std::cout << termcolor::bright_green << "Select emulator : 1- SmartGaga     2- Gamelop 7.1 {Ch}     3- Gamelop 7.1 {En} \n";
    std::cout << termcolor::bright_yellow << "Your Choice : ";
    cin >> emu;
    std::cout << termcolor::bright_green<< "Select Game : 1 - GLOBAL   2 - BGMI   3 - KOREA   4 - VIETNAM   5 - TIWAN\n";
    std::cout << termcolor::bright_yellow << "Your Choice : ";
    cin >> game;
    /*std::cout << termcolor::bright_red << "Do you want to enable IPAD View ?  " << termcolor::bright_green << "1. Yes    " << termcolor::bright_red << "2. No\n";
    std::cout << termcolor::bright_grey << "Your Choice : ";
    cin >> IPAD;*/
	/*std::cout << termcolor::bright_red << "Do you want to enable No Headshot ?  " << termcolor::bright_green << "1. Yes    " << termcolor::bright_red << "2. No\n";
    std::cout << termcolor::bright_grey << "Your Choice : ";
    cin >> nohead;*/
	/*std::cout << termcolor::bright_red << "Do you want to enable Fix Speed ?  " << termcolor::bright_green << "1. Yes    " << termcolor::bright_red << "2. No\n";
    std::cout << termcolor::bright_grey << "Your Choice : ";
    cin >> fixflash;*/
	/*std::cout << termcolor::bright_red << "Do you want to enable Slow Motion ?  " << termcolor::bright_green << "1. Yes    " << termcolor::bright_red << "2. No\n";
    std::cout << termcolor::bright_grey << "Your Choice : ";
    cin >> slowmotion;*/

    //check if emu was already open
    system("adb kill-server");
    cmdd("taskkill /F /IM AndroidProcess.exe");
    cmdd("taskkill /F /IM ProjectTitan.exe");
    cmdd("taskkill /F /im AndroidEmulator.exe");
    cmdd("taskkill /F /im AndroidEmulatorEn.exe");
    cmdd("taskkill /F /im AndroidEmulatorEx.exe");
    cmdd("taskkill /F /im Gameloop.exe");
    string output = executee("adb devices");
    string substring = "emulator";
    int checks = isSubstring(substring, output);
    if (checks != -1)
    {
        std::cout << termcolor::bright_yellow << "[+] Emulator is already running";
        goto gamepointer;
    }
    std::cout << termcolor::bright_green << "[+] Driver service started";
    Sleep(50);
    std::cout << (".");
    Sleep(50);
    std::cout << (".");
    Sleep(50);
    std::cout << (".");
    Sleep(500);
    std::cout << termcolor::bright_yellow<< "\n[+] Starting emulator";

    startEmulator(emu);
    //check if emu loaded
    while (true)
    {
        int pid = getEmuProcID();
        if (pid > 2)
        {
            system("adb kill-server");
            string output = executee("adb devices");
            string substring = "emulator";
            int checks = isSubstring(substring, output);
            if (checks != -1)
            {
                Sleep(10000);
                std::cout << termcolor::bright_green << "\n[+] Emulator is ready";
                break;
            }
        }
        Sleep(3000);
    }
gamepointer:
    std::cout << termcolor::bright_yellow << "\n[+] Preparing files...";
    Sleep(30);
    std::cout << (".");
    Sleep(3500);
    std::cout << (".");
    Sleep(3500);
    std::cout << (". ");
    std::cout << termcolor::bright_yellow << "\n[+] Starting game...";
    Sleep(50);
    std::cout << (".");
    Sleep(50);
    std::cout << (".");
    Sleep(50);
    std::cout << (". ");
    startGame(game, 1);
	Sleep(6300);
        int pid = getProcId();
        if (pid != 0 && pid != 1)
        {
            //mem injections
            Sleep(4200);
            std::cout << termcolor::bright_green << "\n[+] Checing Game Memory...";
            Sleep(50);
            std::cout << (".");
			Sleep(50);
			std::cout << (".");
			Sleep(50);
			std::cout << (". ");
            phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
            Sleep(11000);
            suspend(pid);
            std::cout << termcolor::bright_yellow << "\n[+] Aow Found PID : " << termcolor::bright_green << pid;
            Sleep(500);
            //libue4header = 0; //changed this
            //int libtersafeheader = 0;
            libue4header = getue4header();
            libtersafeheader = getlibtersafeheader();
			std::cout << termcolor::bright_green << "\n[+] UE4 Base Header Found: " << libue4header;
			std::cout << termcolor::bright_yellow << "\n[+] AGNOS Base Header Found" << libtersafeheader;
			Sleep(500);
            std::cout << termcolor::bright_green << "\n[+] Freezing game Memory...";
            Sleep(500);
            std::cout << (".");
            Sleep(500);
            std::cout << (".");
            Sleep(500);
			std::cout << (".");
            phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
            if (libue4header != 0 && libtersafeheader != 0)
            {
                // patch offset in here

            }
			else
			{
				cout << termcolor::red << "\n[!] Bypass Failed Try Again...";
				Sleep(3000);
				exit(0);
			}
            resume(pid);
        }
		else
		{
			cout << termcolor::red << "\n[!] Cannot Found Aow Game Try Again...";
			Sleep(3000);
			exit(0);
		}
        Sleep(1000);
    
    int hackop2;
    std::cout << termcolor::bright_green << "\n-------------------------------------------------------------------------------";
    std::cout << termcolor::bright_green << "\n                [+] Memory patches successfully. Emulator Bypass Done [+] \n";
    std::cout << termcolor::bright_green << "-------------------------------------------------------------------------------\n";
hackloop:


    std::cout << termcolor::bright_green << "Press [0]-(Safe Exit)\n";
	std::cout << termcolor::bright_yellow << "Your Choice : ";
    cin >> hackop2;
    if (hackop2 == 0)
    {
		std::thread safex(&safeExit);
		safex.detach();

    }
    cmdd(("sc stop driver"));
    cmdd(("sc delete driver"));
    remove("C:\\hookdrv.sys");
}
std::string tm_to_readable_time(tm ctx) {
	char buffer[80];

	strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);

	return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp) {
	auto cv = strtol(timestamp.c_str(), NULL, 10); // long

	return (time_t)cv;
}

static std::tm timet_to_tm(time_t timestamp) {
	std::tm context;

	localtime_s(&context, &timestamp);

	return context;
}
