#include <Windows.h>
#include <iostream>
#include <vector>

int Health = 107;
DWORD jumpBack;
typedef void(__cdecl* fnTestFunc)();
fnTestFunc oTestFunc;

bool Hook(void* hookAddress, void* myFunc, void** arg3)
{
	DWORD protec;
	VirtualProtect(hookAddress, 10, PAGE_EXECUTE_READWRITE, &protec);

	std::cout << "target func: " << std::hex << (DWORD)hookAddress << std::endl;
	std::cout << "MyFunc: " << std::hex << (DWORD)myFunc << std::endl;

	// save the original instructions
	auto allocated = VirtualAlloc(nullptr, 12, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!allocated) return false;

	memcpy(allocated, hookAddress, 7);
	*arg3 = allocated;

	DWORD relativeAllocated = ((DWORD)hookAddress - (DWORD)allocated) - 5;

	// add jmp at the end of copied instructions
	*(BYTE*)((DWORD)allocated + 7) = 0xE9;
	*(DWORD*)((DWORD)allocated + 8) = relativeAllocated;

	// add detour to original functions
	DWORD relativeAddress = ((DWORD)myFunc - (DWORD)hookAddress) - 5;

	*(BYTE*)hookAddress = 0xE9;
	*(DWORD*)((DWORD)hookAddress + 1) = relativeAddress;
	
	DWORD tmp;
	VirtualProtect(hookAddress, 10, protec, &tmp);

	return true;
}

__declspec(noinline) void myFunc()
{
	Health += 7;
	oTestFunc();
}

__declspec(noinline) void reduce_health()
{
	MessageBoxA(0, "Reduced HP by 7", "fish", {});
	Health -= 7;
	return;
}

bool doHook()
{
	if(Hook(&reduce_health, &myFunc, reinterpret_cast<void**>(&oTestFunc)))
	{
		std::cout << "Successfully hooked!\n";
		return true;
	}

	std::cout << "hookError\n";
	return false;
}

int main()
{
	bool pressed{};
	bool hooked{};

	while(true)
	{
		if (!hooked)
		{
			hooked = doHook();
		}

		if (pressed)
		{
			if (!GetAsyncKeyState(VK_F2)) pressed = false;
		}
		else if(GetAsyncKeyState(VK_F2))
		{
			reduce_health();

			std::cout << std::dec << "Health: " << Health << std::endl;
			pressed = true;

		}
	}
}