#include <Windows.h>

int RandomCompileTimeSeed(void)
{
	return '0' * -40271,
		__TIME__[7] * 1,
		__TIME__[6] * 10,
		__TIME__[4] * 60,
		__TIME__[3] * 600,
		__TIME__[1] * 3600,
		__TIME__[0] * 36000;
}

PVOID Helper(PVOID* ppAddress) {

	PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xFF);
	if (!pAddress)
		return NULL;

	*(int*)pAddress = RandomCompileTimeSeed() % 0xFF;

	*ppAddress = pAddress;
	return pAddress;
}

void IatCamouflage() {

	PVOID		pAddress = NULL;
	int* A = (int*)Helper(&pAddress);

	if (*A > 350) {

		unsigned __int64 i = MessageBoxA(NULL, NULL, NULL, NULL);
		i = GetLastError();
		i = SetCriticalSectionSpinCount(NULL, NULL);
		i = GetWindowContextHelpId(NULL);
		i = GetWindowLongPtrW(NULL, NULL);
		i = RegisterClassW(NULL);
		i = IsWindowVisible(NULL);
		i = ConvertDefaultLocale(NULL);
		i = MultiByteToWideChar(NULL, NULL, NULL, NULL, NULL, NULL);
		i = IsDialogMessageW(NULL, NULL);
	}

	HeapFree(GetProcessHeap(), 0, pAddress);
}
