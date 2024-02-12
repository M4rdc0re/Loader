#include "Common.h"

extern HMODULE hNtdll;

FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {

	if (hModule == NULL || dwApiNameHash == NULL)
		return NULL;

	PBYTE pBase = (PBYTE)hModule;

	PIMAGE_DOS_HEADER       pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS       pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	IMAGE_OPTIONAL_HEADER   ImgOptHdr = pImgNtHdrs->OptionalHeader;
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD			FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	PDWORD			FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	PWORD			FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
		PCHAR pFunctionName = (PCHAR)(pBase + FunctionNameArray[i]);
		PVOID	pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		if (dwApiNameHash == HASHA(pFunctionName)) {
			return pFunctionAddress;
		}
	}

	return NULL;
}

HMODULE GetModuleHandleH(PCHAR dwModuleNameHash) {

	if (dwModuleNameHash == NULL)
		return NULL;

#ifdef _WIN64
	PPEB			pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB			pPeb = (PEB*)(__readfsdword(0x30));
#endif

	PPEB_LDR_DATA		    pLdr = (PPEB_LDR_DATA)(pPeb->LoaderData);
	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {

		if (pDte->FullDllName.Length != NULL && pDte->FullDllName.Length < MAX_PATH) {

			CHAR UpperCaseDllName[MAX_PATH];

			DWORD i = 0;
			while (pDte->FullDllName.Buffer[i]) {
				UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);
				i++;
			}
			UpperCaseDllName[i] = '\0';

			if (HASHA(UpperCaseDllName) == dwModuleNameHash)
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);

		}
		else {
			break;
		}

		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
	}

	return NULL;
}

HMODULE LoadLibraryH(LPSTR DllName) {

	UNICODE_STRING	Ustr = { 0 };
	WCHAR			wDllName[MAX_PATH] = { 0 };
	NTSTATUS		STATUS = 0x00;
	HMODULE			hModule = NULL;

	_CharToWchar(wDllName, DllName, _StrlenA(DllName));

	USHORT DestSize = _StrlenW(wDllName) * sizeof(WCHAR);
	Ustr.Length = DestSize;
	Ustr.MaximumLength = DestSize + sizeof(WCHAR);
	Ustr.Buffer = wDllName;

	fnLdrLoadDll pLdrLoadDll = (fnLdrLoadDll)GetProcAddressH(hNtdll, LdrLoadDll_JOAA);
	if (pLdrLoadDll != NULL && (STATUS = pLdrLoadDll(NULL, 0, &Ustr, &hModule)) == 0x0) {
		return hModule;
	}

	return NULL;
}