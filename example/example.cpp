#include "example.h"

void FindProcessHandle(::LPCSTR lpProcessName, ::HANDLE &processHandle)
{
	::PROCESSENTRY32 processEntry{0};
	processEntry.dwSize = sizeof(::PROCESSENTRY32);

	::HANDLE tlhelpSnapshot{::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL)};
	if (::Process32First(tlhelpSnapshot, &processEntry))
	{
		while (::Process32Next(tlhelpSnapshot, &processEntry))
		{
			if (!std::strcmp(processEntry.szExeFile, lpProcessName))
			{
				processHandle = ::OpenProcess(PROCESS_ALL_ACCESS, 
					FALSE, processEntry.th32ProcessID);

				break;
			}
		}
	}

	::CloseHandle(tlhelpSnapshot);
}

void InjectLibraryErrorHandler(MANUALMAP_ERROR_CODE errorCode, ::NTSTATUS ntError)
{
	std::printf("The library load function returned an error code: %d; NTSTATUS: %d\n", errorCode, ntError);
	std::printf("The GetLastError function returned an error code: %x\n", ::GetLastError());
}

int main()
{
	::HANDLE processHandle{0};
	FindProcessHandle("gta_sa.exe", processHandle);

	if (NULL != processHandle)
	{
		std::puts("GTA process was found =) Library is going to load right now...");
		if (manualmap::inject(processHandle, example, InjectLibraryErrorHandler)) {
			std::puts("Library was successfully loaded! Thank you for use this injector =)");
		}

		::CloseHandle(processHandle);
	}
	else {
		std::puts("GTA was not found =(\n");
	}
	
	std::system("pause");
	return 0;
}