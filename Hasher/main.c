#include <Windows.h>
#include <stdio.h>

#define STR "_JOAA"
#define INITIAL_SEED 12

UINT32 HashStringJenkinsOneAtATime32BitA(PCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenA(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}

int main() {

	printf("-----------------------------EXE-----------------------------\n");
	printf("#define %s%s \t0x%0.8X \n", "InternetOpenW", STR, HashStringJenkinsOneAtATime32BitA("InternetOpenW"));
	printf("#define %s%s \t0x%0.8X \n", "InternetOpenUrlW", STR, HashStringJenkinsOneAtATime32BitA("InternetOpenUrlW"));
	printf("#define %s%s \t0x%0.8X \n", "InternetSetOptionW", STR, HashStringJenkinsOneAtATime32BitA("InternetSetOptionW"));
	printf("#define %s%s \t0x%0.8X \n", "InternetReadFile", STR, HashStringJenkinsOneAtATime32BitA("InternetReadFile"));
	printf("#define %s%s \t0x%0.8X \n", "InternetCloseHandle", STR, HashStringJenkinsOneAtATime32BitA("InternetCloseHandle"));
	printf("#define %s%s \t0x%0.8X \n", "LocalAlloc", STR, HashStringJenkinsOneAtATime32BitA("LocalAlloc"));
	printf("#define %s%s \t0x%0.8X \n", "LocalReAlloc", STR, HashStringJenkinsOneAtATime32BitA("LocalReAlloc"));
	printf("#define %s%s \t0x%0.8X \n", "LocalFree", STR, HashStringJenkinsOneAtATime32BitA("LocalFree"));
	printf("#define %s%s \t0x%0.8X \n", "NtAddBootEntry", STR, HashStringJenkinsOneAtATime32BitA("NtAddBootEntry"));
	printf("#define %s%s \t0x%0.8X \n", "CreateEventA", STR, HashStringJenkinsOneAtATime32BitA("CreateEventA"));
	printf("#define %s%s \t0x%0.8X \n", "ZwAllocateVirtualMemory", STR, HashStringJenkinsOneAtATime32BitA("ZwAllocateVirtualMemory"));
	printf("#define %s%s \t0x%0.8X \n", "NtProtectVirtualMemory", STR, HashStringJenkinsOneAtATime32BitA("NtProtectVirtualMemory"));
	printf("#define %s%s \t0x%0.8X \n", "TpAllocWait", STR, HashStringJenkinsOneAtATime32BitA("TpAllocWait"));
	printf("#define %s%s \t0x%0.8X \n", "TpSetWait", STR, HashStringJenkinsOneAtATime32BitA("TpSetWait"));
	printf("#define %s%s \t0x%0.8X \n", "NtWaitForSingleObject", STR, HashStringJenkinsOneAtATime32BitA("NtWaitForSingleObject"));
	printf("#define %s%s \t0x%0.8X \n", "LdrLoadDll", STR, HashStringJenkinsOneAtATime32BitA("LdrLoadDll"));
	printf("#define %s%s \t0x%0.8X \n", "CallNextHookEx", STR, HashStringJenkinsOneAtATime32BitA("CallNextHookEx"));
	printf("#define %s%s \t0x%0.8X \n", "SetWindowsHookExW", STR, HashStringJenkinsOneAtATime32BitA("SetWindowsHookExW"));
	printf("#define %s%s \t0x%0.8X \n", "DefWindowProcW", STR, HashStringJenkinsOneAtATime32BitA("DefWindowProcW"));
	printf("#define %s%s \t0x%0.8X \n", "GetModuleFileNameW", STR, HashStringJenkinsOneAtATime32BitA("GetModuleFileNameW"));
	printf("#define %s%s \t0x%0.8X \n", "CreateFileW", STR, HashStringJenkinsOneAtATime32BitA("CreateFileW"));
	printf("#define %s%s \t0x%0.8X \n", "SetFileInformationByHandle", STR, HashStringJenkinsOneAtATime32BitA("SetFileInformationByHandle"));
	printf("#define %s%s \t0x%0.8X \n", "GetTickCount64", STR, HashStringJenkinsOneAtATime32BitA("GetTickCount64"));
	printf("#define %s%s \t0x%0.8X \n", "UnhookWindowsHookEx", STR, HashStringJenkinsOneAtATime32BitA("UnhookWindowsHookEx"));
	printf("#define %s%s \t0x%0.8X \n", "GetMessageW", STR, HashStringJenkinsOneAtATime32BitA("GetMessageW"));
	printf("#define %s%s \t0x%0.8X \n", "NtClose", STR, HashStringJenkinsOneAtATime32BitA("NtClose"));
	printf("#define %s%s \t0x%0.8X \n", "NtDelayExecution", STR, HashStringJenkinsOneAtATime32BitA("NtDelayExecution"));
	printf("#define %s%s \t0x%0.8X \n", "NtCreateThreadEx", STR, HashStringJenkinsOneAtATime32BitA("NtCreateThreadEx"));
	
	printf("#define %s%s \t0x%0.8X \n", "KERNEL32DLL", STR, HashStringJenkinsOneAtATime32BitA("KERNEL32.DLL"));
	printf("#define %s%s \t0x%0.8X \n", "WININETDLL", STR, HashStringJenkinsOneAtATime32BitA("WININET.DLL"));
	printf("#define %s%s \t0x%0.8X \n", "NTDLLDLL", STR, HashStringJenkinsOneAtATime32BitA("NTDLL.DLL"));
	printf("#define %s%s \t0x%0.8X \n", "USER32DLL", STR, HashStringJenkinsOneAtATime32BitA("USER32.DLL"));

	printf("-----------------------------DLL-----------------------------\n");
	printf("#define %s%s \t0x%0.8X \n", "InternetOpenW", STR, HashStringJenkinsOneAtATime32BitA("InternetOpenW"));
	printf("#define %s%s \t0x%0.8X \n", "InternetOpenUrlW", STR, HashStringJenkinsOneAtATime32BitA("InternetOpenUrlW"));
	printf("#define %s%s \t0x%0.8X \n", "InternetSetOptionW", STR, HashStringJenkinsOneAtATime32BitA("InternetSetOptionW"));
	printf("#define %s%s \t0x%0.8X \n", "InternetReadFile", STR, HashStringJenkinsOneAtATime32BitA("InternetReadFile"));
	printf("#define %s%s \t0x%0.8X \n", "InternetCloseHandle", STR, HashStringJenkinsOneAtATime32BitA("InternetCloseHandle"));
	printf("#define %s%s \t0x%0.8X \n", "LocalAlloc", STR, HashStringJenkinsOneAtATime32BitA("LocalAlloc"));
	printf("#define %s%s \t0x%0.8X \n", "LocalReAlloc", STR, HashStringJenkinsOneAtATime32BitA("LocalReAlloc"));
	printf("#define %s%s \t0x%0.8X \n", "LocalFree", STR, HashStringJenkinsOneAtATime32BitA("LocalFree"));
	printf("#define %s%s \t0x%0.8X \n", "NtAddBootEntry", STR, HashStringJenkinsOneAtATime32BitA("NtAddBootEntry"));
	printf("#define %s%s \t0x%0.8X \n", "CreateEventA", STR, HashStringJenkinsOneAtATime32BitA("CreateEventA"));
	printf("#define %s%s \t0x%0.8X \n", "ZwAllocateVirtualMemory", STR, HashStringJenkinsOneAtATime32BitA("ZwAllocateVirtualMemory"));
	printf("#define %s%s \t0x%0.8X \n", "NtProtectVirtualMemory", STR, HashStringJenkinsOneAtATime32BitA("NtProtectVirtualMemory"));
	printf("#define %s%s \t0x%0.8X \n", "TpAllocWait", STR, HashStringJenkinsOneAtATime32BitA("TpAllocWait"));
	printf("#define %s%s \t0x%0.8X \n", "TpSetWait", STR, HashStringJenkinsOneAtATime32BitA("TpSetWait"));
	printf("#define %s%s \t0x%0.8X \n", "NtWaitForSingleObject", STR, HashStringJenkinsOneAtATime32BitA("NtWaitForSingleObject"));
	printf("#define %s%s \t0x%0.8X \n", "LdrLoadDll", STR, HashStringJenkinsOneAtATime32BitA("LdrLoadDll"));
	printf("#define %s%s \t0x%0.8X \n", "NtClose", STR, HashStringJenkinsOneAtATime32BitA("NtClose"));
	printf("#define %s%s \t0x%0.8X \n", "NtCreateThreadEx", STR, HashStringJenkinsOneAtATime32BitA("NtCreateThreadEx"));

	printf("#define %s%s \t0x%0.8X \n", "KERNEL32DLL", STR, HashStringJenkinsOneAtATime32BitA("KERNEL32.DLL"));
	printf("#define %s%s \t0x%0.8X \n", "WININETDLL", STR, HashStringJenkinsOneAtATime32BitA("WININET.DLL"));
	printf("#define %s%s \t0x%0.8X \n", "NTDLLDLL", STR, HashStringJenkinsOneAtATime32BitA("NTDLL.DLL"));
	printf("#define %s%s \t0x%0.8X \n", "USER32DLL", STR, HashStringJenkinsOneAtATime32BitA("USER32.DLL"));

	getchar();

	return 0;
}