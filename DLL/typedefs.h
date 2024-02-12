#include <Windows.h>
#include <wininet.h>
#include "Structs.h"

typedef HINTERNET (WINAPI* fnInternetOpenW)(
	LPCWSTR lpszAgent,
	DWORD   dwAccessType,
	LPCWSTR lpszProxy,
	LPCWSTR lpszProxyBypass,
	DWORD   dwFlags
);

typedef HINTERNET (WINAPI* fnInternetOpenUrlW)(
	HINTERNET hInternet,
	LPCWSTR   lpszUrl,
	LPCWSTR   lpszHeaders,
	DWORD     dwHeadersLength,
	DWORD     dwFlags,
	DWORD_PTR dwContext
);

typedef HLOCAL (WINAPI* fnLocalAlloc)(
	UINT   uFlags,
	SIZE_T uBytes
);

typedef BOOL (WINAPI* fnInternetReadFile)(
	HINTERNET hFile,
	LPVOID    lpBuffer,
	DWORD     dwNumberOfBytesToRead,
	LPDWORD   lpdwNumberOfBytesRead
);

typedef HLOCAL (WINAPI* fnLocalReAlloc)(
	HLOCAL	hMem,
	SIZE_T	uBytes,
	UINT	uFlags
);

typedef BOOL (WINAPI* fnInternetCloseHandle)(
	HINTERNET hInternet
);

typedef BOOL (WINAPI* fnInternetSetOptionW)(
	HINTERNET hInternet,
	DWORD     dwOption,
	LPVOID    lpBuffer,
	DWORD     dwBufferLength
);

typedef HLOCAL (WINAPI* fnLocalFree)(
	HLOCAL hMem
);

typedef HANDLE(WINAPI* fnCreateEventA)(
	LPSECURITY_ATTRIBUTES lpEventAttributes,
	BOOL                  bManualReset,
	BOOL                  bInitialState,
	LPCSTR                lpName
);


typedef NTSTATUS(NTAPI* fnTpAllocWait)(
	TP_WAIT** out, 
	PTP_WAIT_CALLBACK callback, 
	PVOID userdata, 
	TP_CALLBACK_ENVIRON* environment
);
typedef void(NTAPI* fnTpSetWait)(
	TP_WAIT* wait, 
	HANDLE handle, 
	LARGE_INTEGER* timeout
);

typedef NTSTATUS(NTAPI* fnLdrLoadDll)(
	PWCHAR             PathToFile,
	ULONG              Flags,
	PUNICODE_STRING    ModuleFileName,
	PHANDLE            ModuleHandle
);