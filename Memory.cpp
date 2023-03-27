#pragma once
#define MY_HEADER_H
#include "Memory.h"
#include "pch.h"

using namespace std;

typedef struct _MEMORY_REGION {
	DWORD_PTR dwBaseAddr;
	DWORD_PTR dwMemorySize;
}MEMORY_REGION;

int getAowProcId()
{
	int pid = 0;
	PROCESS_MEMORY_COUNTERS ProcMC;
	PROCESSENTRY32 ProcEntry;
	ProcEntry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE ProcHandle;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(snapshot, &ProcEntry) == TRUE)
	{
		while (Process32Next(snapshot, &ProcEntry) == TRUE)
		{
			if (strcmp(ProcEntry.szExeFile, "aow_exe.exe") == 0)
			{
				ProcHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcEntry.th32ProcessID);

				if (NULL == ProcHandle)
					continue;

				if (GetProcessMemoryInfo(ProcHandle, &ProcMC, sizeof(ProcMC)))
				{
					if (ProcMC.WorkingSetSize > 300000000)
					{
						pid = ProcEntry.th32ProcessID;
						return pid;
						break;
					}

				}

				CloseHandle(ProcHandle);
			}
		}
	}

	CloseHandle(snapshot);
}

int getGagaProcId()
{
	int pid = 0;
	PROCESS_MEMORY_COUNTERS ProcMC;
	PROCESSENTRY32 ProcEntry;
	ProcEntry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE ProcHandle;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(snapshot, &ProcEntry) == TRUE)
	{
		while (Process32Next(snapshot, &ProcEntry) == TRUE)
		{
			if (strcmp(ProcEntry.szExeFile, "AndroidProcess.exe") == 0)
			{
				ProcHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcEntry.th32ProcessID);

				if (NULL == ProcHandle)
					continue;

				if (GetProcessMemoryInfo(ProcHandle, &ProcMC, sizeof(ProcMC)))
				{
					if (ProcMC.WorkingSetSize > 300000000)
					{
						pid = ProcEntry.th32ProcessID;
						return pid;
						break;
					}

				}

				CloseHandle(ProcHandle);
			}
		}
	}

	CloseHandle(snapshot);
}

int getProcId()
{
	int aow = 0;
	int gaga = 0;
	aow = getAowProcId();
	gaga = getGagaProcId();
	if (gaga == 0 || gaga == 1)
	{
		if (aow == 0 || aow == 1)
		{
			return 0;
		}
		else
		{
			return aow;
		}
	}
	else
	{
		return gaga;
	}
}

bool patcher(long addr, BYTE write[], SIZE_T sizee)
{
	DWORD pid = getProcId();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	unsigned long OldProtect;
	unsigned long OldProtect2;
	VirtualProtectEx(phandle, (void*)addr, sizee, PAGE_EXECUTE_READWRITE, &OldProtect);
	WriteProcessMemory(phandle, (void*)addr, write, sizee, NULL);
	VirtualProtectEx(phandle, (void*)addr, sizee, OldProtect, NULL);
	return true;
}

std::string exec(const char* cmd)
{
	char buffer[128]; std::string result = "";
	FILE* pipe = _popen(cmd, "r");
	if (!pipe)
		throw std::runtime_error("popen() failed!");
	try {
		while (fgets(buffer, sizeof buffer, pipe) != NULL)
		{
			result += buffer;
		}
	}
	catch (...)
	{
		_pclose(pipe);
		throw;
	}
	_pclose(pipe);
	return result;
}

std::string removeSpaces(std::string str)
{
	str.erase(remove(str.begin(), str.end(), ' '), str.end());
	return str;
}

std::vector<DWORD> MagicBulletList;
uintptr_t MagicBulletHook;

int MemFind(BYTE* buffer, int dwBufferSize, BYTE* bstr, DWORD dwStrLen)
{
	if (dwBufferSize < 0)
	{
		return -1;
	}
	DWORD  i, j;
	for (i = 0; i < dwBufferSize; i++)
	{
		for (j = 0; j < dwStrLen; j++)
		{
			if (buffer[i + j] != bstr[j] && bstr[j] != '?')
				break;
		}
		if (j == dwStrLen)
			return i;
	}
	return -1;
}

int SundaySearch(BYTE* bStartAddr, int dwSize, BYTE* bSearchData, DWORD dwSearchSize)
{
	if (dwSize < 0)
	{
		return -1;
	}
	int iIndex[256] = { 0 };
	int i, j;
	DWORD k;

	for (i = 0; i < 256; i++)
	{
		iIndex[i] = -1;
	}

	j = 0;
	for (i = dwSearchSize - 1; i >= 0; i--)
	{
		if (iIndex[bSearchData[i]] == -1)
		{
			iIndex[bSearchData[i]] = dwSearchSize - i;
			if (++j == 256)
				break;
		}
	}
	i = 0;
	BOOL bFind = FALSE;
	//j=dwSize-dwSearchSize+1;
	j = dwSize - dwSearchSize + 1;
	while (i < j)
	{
		for (k = 0; k < dwSearchSize; k++)
		{
			if (bStartAddr[i + k] != bSearchData[k])
				break;
		}
		if (k == dwSearchSize)
		{
			//ret=bStartAddr+i;
			bFind = TRUE;
			break;
		}
		if (i + dwSearchSize >= dwSize)
		{

			return -1;
		}
		k = iIndex[bStartAddr[i + dwSearchSize]];
		if (k == -1)
			i = i + dwSearchSize + 1;
		else
			i = i + k;
	}
	if (bFind)
	{
		return i;
	}
	else
		return -1;

}

BOOL MemSearch(BYTE* bSearchData, int nSearchSize, DWORD_PTR dwStartAddr, DWORD_PTR dwEndAddr, BOOL bIsCurrProcess, int iSearchMode, std::vector<DWORD_PTR>& vRet)
{
	DWORD pid = getProcId();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	BYTE* pCurrMemoryData = NULL;
	MEMORY_BASIC_INFORMATION	mbi;
	std::vector<MEMORY_REGION> m_vMemoryRegion;
	mbi.RegionSize = 0x1000;
	DWORD dwAddress = dwStartAddr;

	while (VirtualQueryEx(phandle, (LPCVOID)dwAddress, &mbi, sizeof(mbi)) && (dwAddress < dwEndAddr) && ((dwAddress + mbi.RegionSize) > dwAddress))
	{

		if ((mbi.State == MEM_COMMIT) && ((mbi.Protect & PAGE_GUARD) == 0) && (mbi.Protect != PAGE_NOACCESS) && ((mbi.AllocationProtect & PAGE_NOCACHE) != PAGE_NOCACHE))
		{

			MEMORY_REGION mData = { 0 };
			mData.dwBaseAddr = (DWORD_PTR)mbi.BaseAddress;
			mData.dwMemorySize = mbi.RegionSize;
			m_vMemoryRegion.push_back(mData);

		}
		dwAddress = (DWORD)mbi.BaseAddress + mbi.RegionSize;

	}


	std::vector<MEMORY_REGION>::iterator it;
	for (it = m_vMemoryRegion.begin(); it != m_vMemoryRegion.end(); it++)
	{
		MEMORY_REGION mData = *it;


		DWORD_PTR dwNumberOfBytesRead = 0;

		if (bIsCurrProcess)
		{
			pCurrMemoryData = (BYTE*)mData.dwBaseAddr;
			dwNumberOfBytesRead = mData.dwMemorySize;
		}
		else
		{

			pCurrMemoryData = new BYTE[mData.dwMemorySize];
			ZeroMemory(pCurrMemoryData, mData.dwMemorySize);
			ReadProcessMemory(phandle, (LPCVOID)mData.dwBaseAddr, pCurrMemoryData, mData.dwMemorySize, &dwNumberOfBytesRead);

			if ((int)dwNumberOfBytesRead <= 0)
			{
				delete[] pCurrMemoryData;
				continue;
			}
		}
		if (iSearchMode == 0)
		{
			DWORD_PTR dwOffset = 0;
			int iOffset = MemFind(pCurrMemoryData, dwNumberOfBytesRead, bSearchData, nSearchSize);
			while (iOffset != -1)
			{
				dwOffset += iOffset;
				vRet.push_back(dwOffset + mData.dwBaseAddr);
				dwOffset += nSearchSize;
				iOffset = MemFind(pCurrMemoryData + dwOffset, dwNumberOfBytesRead - dwOffset - nSearchSize, bSearchData, nSearchSize);
			}
		}
		else if (iSearchMode == 1)
		{

			DWORD_PTR dwOffset = 0;
			int iOffset = SundaySearch(pCurrMemoryData, dwNumberOfBytesRead, bSearchData, nSearchSize);

			while (iOffset != -1)
			{
				dwOffset += iOffset;
				vRet.push_back(dwOffset + mData.dwBaseAddr);
				dwOffset += nSearchSize;
				iOffset = MemFind(pCurrMemoryData + dwOffset, dwNumberOfBytesRead - dwOffset - nSearchSize, bSearchData, nSearchSize);
			}

		}

		if (!bIsCurrProcess && (pCurrMemoryData != NULL))
		{
			delete[] pCurrMemoryData;
			pCurrMemoryData = NULL;
		}

	}
	return TRUE;
}

int SINGLEAOBSCAN(BYTE BypaRep[], SIZE_T size)
{
	DWORD pid = getProcId();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	std::vector<DWORD_PTR> Bypassdo;
	MemSearch(BypaRep, size, 0x26000000, 0xB0000000, false, 0, Bypassdo);

	if (Bypassdo.size() != 0) {
		return Bypassdo[0];
	}
}

int SINGLEAOBSCAN2(BYTE BypaRep[], SIZE_T size)
{
	DWORD pid = getProcId();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	std::vector<DWORD_PTR> Bypassdo;
	MemSearch(BypaRep, size, 0, 0xB0000000, false, 0, Bypassdo);

	if (Bypassdo.size() != 0) {
		return Bypassdo[0];
	}
}

int SINGLEAOBSCAN3(BYTE BypaRep[], SIZE_T size)
{
	DWORD pid = getProcId();
	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	std::vector<DWORD_PTR> Bypassdo;
	MemSearch(BypaRep, size, 0, 0xB0000000, false, 0, Bypassdo);

	if (Bypassdo.size() != 0) {
		return Bypassdo[Bypassdo.size() - 1];
	}
	return 0;

}