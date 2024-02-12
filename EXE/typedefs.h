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
	HLOCAL hMem,
	SIZE_T                 uBytes,
	UINT                   uFlags
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

typedef LRESULT(WINAPI* fnCallNextHookEx)(
	HHOOK hhk, 
	int nCode, 
	WPARAM wParam, 
	LPARAM lParam
);

typedef ULONGLONG(WINAPI* fnGetTickCount64)(
);

typedef HHOOK(WINAPI* fnSetWindowsHookExW)(
	int idHook, 
	HOOKPROC lpfn, 
	HINSTANCE hmod, 
	DWORD dwThreadId
);

typedef BOOL(WINAPI* fnGetMessageW)(
	LPMSG lpMsg, 
	HWND hWnd, 
	UINT wMsgFilterMin, 
	UINT wMsgFilterMax
);

typedef LRESULT(WINAPI* fnDefWindowProcW)(
	HWND hWnd, 
	UINT Msg, 
	WPARAM wParam, 
	LPARAM lParam
);

typedef BOOL(WINAPI* fnUnhookWindowsHookEx)(
	HHOOK hhk
);

typedef DWORD(WINAPI* fnGetModuleFileNameW)(
	HMODULE hModule, 
	LPWSTR lpFilename, 
	DWORD nSize
);

typedef HANDLE(WINAPI* fnCreateFileW)(
	LPCWSTR lpFileName, 
	DWORD dwDesiredAccess, 
	DWORD dwShareMode, 
	LPSECURITY_ATTRIBUTES lpSecurityAttributes, 
	DWORD dwCreationDisposition, 
	DWORD dwFlagsAndAttributes, 
	HANDLE hTemplateFile
);

typedef BOOL(WINAPI* fnSetFileInformationByHandle)(
	HANDLE hFile, 
	FILE_INFO_BY_HANDLE_CLASS FileInformationClass, 
	LPVOID lpFileInformation, 
	DWORD dwBufferSize
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