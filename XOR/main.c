#include <Windows.h>
#include <stdio.h>
#include <wchar.h>

void XorByInputKey(LPWSTR szString, SIZE_T sStringSize, PBYTE bKey, SIZE_T sKeySize) {
    size_t wStringSize = sStringSize / sizeof(wchar_t);

    for (size_t i = 0, j = 0; i < wStringSize; i++, j++) {
        if (j >= sKeySize) {
            j = 0;
        }

        szString[i] ^= bKey[j];
    }
}

int main() {

    LPCWSTR szUrl = L"http://127.0.0.1/payload.bin";
    size_t szUrlSize = wcslen(szUrl) * sizeof(wchar_t);
    BYTE key[] = { 0x04, 0x01, 0x03, 0x02 };
    size_t keySize = sizeof(key);
    LPWSTR encodedUrl = _wcsdup(szUrl);

    XorByInputKey(encodedUrl, szUrlSize, key, keySize);

    wprintf(L"Encoded message: %s\n", encodedUrl);

    XorByInputKey(encodedUrl, szUrlSize, key, keySize);

    wprintf(L"Decoded message: %s\n", encodedUrl);

    getchar();

    free(encodedUrl);

    return 0;
}