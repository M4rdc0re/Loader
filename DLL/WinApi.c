#include "Common.h"

CHAR _toUpper(CHAR C)
{
	if (C >= 'a' && C <= 'z')
		return C - 'a' + 'A';

	return C;
}

PVOID _memcpy(PVOID Destination, PVOID Source, SIZE_T Size)
{
	for (volatile INT i = 0; i < Size; i++) {
		((BYTE*)Destination)[i] = ((BYTE*)Source)[i];
	}
	return Destination;
}

SIZE_T _CharToWchar(PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed)
{
	INT Length = (INT)MaximumAllowed;

	while (--Length >= 0) {
		if (!(*Destination++ = *Source++))
			return MaximumAllowed - Length - 1;
	}

	return MaximumAllowed - Length;
}

SIZE_T _StrlenA(LPCSTR String)
{

	LPCSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

SIZE_T _StrlenW(LPCWSTR String)
{

	LPCWSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

UINT32 HashStringJenkinsOneAtATime32BitA(PCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = _StrlenA(String);

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

extern PVOID __cdecl memset(PVOID, INT, size_t);

#pragma intrinsic(memset)
#pragma function(memset)

PVOID __cdecl memset(PVOID Destination, INT Value, size_t Size) {
	PUCHAR p = (PUCHAR)Destination;
	while (Size > 0) {
		*p = (UCHAR)Value;
		p++;
		Size--;
	}
	return Destination;
	}

#ifdef __cplusplus
extern "C" {
#endif
	INT _fltused = 0;
#ifdef __cplusplus
}
#endif