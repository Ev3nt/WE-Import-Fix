#include <Windows.h>

uintptr_t nWE = (uintptr_t)GetModuleHandle(NULL);

LPCSTR lpPrefix = "";

bool patch(uintptr_t nAddress, DWORD dwBYTES, size_t nSize)
{
	DWORD dwOldProtect;
	if (VirtualProtect((LPVOID)nAddress, nSize, PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		memcpy((LPVOID)nAddress, (LPVOID)&dwBYTES, nSize);
		VirtualProtect((LPVOID)nAddress, nSize, dwOldProtect, NULL);

		return true;
	}

	return false;
}

bool call(uintptr_t nAddress, LPVOID lpFunction)
{
	return patch(nAddress, 0xE8, 1) ? patch(nAddress + 1, (uintptr_t)lpFunction - (nAddress + 5), 4) : false;
}

bool fill(uintptr_t nAddress, DWORD dwBYTE, size_t nSize)
{
	bool ret = true;
	for (size_t i = 0; i < nSize && ret; i++)
		ret = patch(nAddress + i, dwBYTE, 1);

	return ret;
}

// Proxies

LPVOID CALLBACK memcpy000000001(LPVOID p1, LPVOID p2, size_t p3)
{
	memcpy(p1, p2, p3);
	memset((LPVOID)((uintptr_t)p1 + p3), 0, 1);

	return p1;
}

size_t CALLBACK strlen00000001(LPCSTR p1)
{
	return strlen(p1);
}

void _declspec(naked) f00000001()
{
	_asm {
		mov byte ptr[eax], 6
		mov byte ptr[eax + 1], 0
		mov byte ptr[eax + 0x218], 6
		push eax
		mov eax, esp
		add eax, 0x14
		push eax
		call strlen00000001
		mov ebx, eax
		pop eax
		push ebx
		push ebx
		mov ebx, esp
		add ebx, 0x18
		push ebx
		add eax, 0x105
		push eax
		call memcpy000000001
		add eax, 0x218
		mov ebx, esp
		add ebx, 0x14
		push ebx
		push eax
		call memcpy000000001
		sub eax, 0x31d
		ret
	}
}

BOOL APIENTRY DllMain(HMODULE hModule, UINT ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
		if (!GetModuleHandle("Game.dll"))
		{
			call(nWE + 0x10529f, f00000001);
			fill(nWE + 0x1052a4, 0x90, 9);

			patch(nWE + 0x104520, 0x68, 1);
			patch(nWE + 0x104521, (uintptr_t)lpPrefix, 4);
			patch(nWE + 0x104525, 0x9090, 2);
		}

	return TRUE;
}