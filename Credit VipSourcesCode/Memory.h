#pragma once
#include "pch.h"
int getProcId();
int getAowProcId();
bool patcher(long addr, BYTE write[], SIZE_T sizee);
int SINGLEAOBSCAN2(BYTE BypaRep[], SIZE_T size);
int SINGLEAOBSCAN3(BYTE BypaRep[], SIZE_T size);
int SINGLEAOBSCAN(BYTE BypaRep[], SIZE_T size);
BOOL MemSearch(BYTE* bSearchData, int nSearchSize, DWORD_PTR dwStartAddr, DWORD_PTR dwEndAddr, BOOL bIsCurrProcess, int iSearchMode, std::vector<DWORD_PTR>& vRet);