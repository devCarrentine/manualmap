#include "manualmap.h"

struct stLoaderParams
{
	::DWORD dwGetProcAddress;
	::DWORD dwLoadLibrary;
	::DWORD dwModuleBase;
	::DWORD dwRtlZeroMemory;
	::PIMAGE_NT_HEADERS imageNtHeader;
	::PIMAGE_BASE_RELOCATION imageBaseRelocation;
	::PIMAGE_IMPORT_DESCRIPTOR imageImportDescriptor;
};

MANUALMAP_ERROR_CODE WINAPI LibraryInitializationRemoteThread(::LPVOID lpThreadParameter)
{
	auto loaderParams{reinterpret_cast<stLoaderParams *>(lpThreadParameter)};

	auto dwGetProcAddress{loaderParams->dwGetProcAddress};
	auto dwLoadLibrary{loaderParams->dwLoadLibrary};
	auto moduleBase{loaderParams->dwModuleBase};

	auto getProcAddress{reinterpret_cast<decltype(&GetProcAddress)>(dwGetProcAddress)};
	auto loadLibrary{reinterpret_cast<decltype(&LoadLibraryA)>(dwLoadLibrary)};
	
	const ::DWORD dwDelta{moduleBase - loaderParams->imageNtHeader->OptionalHeader.ImageBase};
	auto imageBaseRelocation{loaderParams->imageBaseRelocation};

	while (imageBaseRelocation->VirtualAddress)
	{
		if (imageBaseRelocation->SizeOfBlock >= sizeof(::IMAGE_BASE_RELOCATION))
		{
			::DWORD dwCount{(imageBaseRelocation->SizeOfBlock - 
				sizeof(::IMAGE_BASE_RELOCATION)) / sizeof(::WORD)};

			auto relocationInfo{::PWORD(imageBaseRelocation + 1)};

			for (::DWORD i{0}; i < dwCount; i++)
			{
				if (relocationInfo[i] >> 12 == IMAGE_REL_BASED_HIGHLOW)
				{
					*reinterpret_cast<::PDWORD>(moduleBase + (
						imageBaseRelocation->VirtualAddress + 
						(relocationInfo[i] & 0xFFF))) += dwDelta;
				}
			}
		}

		imageBaseRelocation = reinterpret_cast<::PIMAGE_BASE_RELOCATION>(
			::LPBYTE(imageBaseRelocation) + imageBaseRelocation->SizeOfBlock);
	}
	
	auto imageImportDescriptor{loaderParams->imageImportDescriptor};

	while (imageImportDescriptor->Characteristics)
	{
		auto originalFirstThunk{reinterpret_cast<::PIMAGE_THUNK_DATA>(
			moduleBase + imageImportDescriptor->OriginalFirstThunk)};

		auto firstThunk{reinterpret_cast<::PIMAGE_THUNK_DATA>(
			moduleBase + imageImportDescriptor->FirstThunk)};

		::HMODULE libraryModule{loadLibrary(reinterpret_cast<::LPCSTR>(
			moduleBase + imageImportDescriptor->Name))};

		if (!libraryModule) {
			return MANUALMAP_ERROR_CODE::MODULE_MISSING_IMPORTED_MODULE;
		}

		while (originalFirstThunk->u1.AddressOfData)
		{
			auto importedFunction{::DWORD(getProcAddress(libraryModule,
				originalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG ? ::LPCSTR(originalFirstThunk->u1.Ordinal & 0xFFFF) : 
				(::PIMAGE_IMPORT_BY_NAME(moduleBase + originalFirstThunk->u1.AddressOfData))->Name))};

			if (!importedFunction) {
				return MANUALMAP_ERROR_CODE::MODULE_MISSING_IMPORTED_FUNCTION;
			}

			firstThunk->u1.Function = importedFunction;
			originalFirstThunk++;
			firstThunk++;
		}

		imageImportDescriptor++;
	}

	if (!loaderParams->imageNtHeader->OptionalHeader.AddressOfEntryPoint) {
		return MANUALMAP_ERROR_CODE::MODULE_HAS_NO_ENTRYPOINT;
	}

	using DllMain_t = ::BOOL(WINAPI *)(::HMODULE, ::DWORD, ::LPVOID);
	using RtlZeroMemory_t = void(WINAPI *)(::LPVOID, ::SIZE_T);

	auto dllMain{reinterpret_cast<DllMain_t>(moduleBase +
		loaderParams->imageNtHeader->OptionalHeader.AddressOfEntryPoint)};

	dllMain(::HMODULE(moduleBase), DLL_PROCESS_ATTACH, nullptr);

	auto rtlZeroMemory{reinterpret_cast<RtlZeroMemory_t>(loaderParams->dwRtlZeroMemory)};

	rtlZeroMemory(::LPVOID(moduleBase + loaderParams->imageNtHeader->OptionalHeader.AddressOfEntryPoint), 32);
	rtlZeroMemory(::LPVOID(moduleBase), loaderParams->imageNtHeader->OptionalHeader.SizeOfHeaders);

	return MANUALMAP_ERROR_CODE::EVERYTHING_IS_OK;
}

bool manualmap::inject(::HANDLE targetProcess, ::LPBYTE staticBytecode, MANUALMAP_ERROR_HANDLER errorHandler)
{
	::LPBYTE libraryBytecode{staticBytecode};

	if (!libraryBytecode) 
	{
		errorHandler(MANUALMAP_ERROR_CODE::MODULE_DOES_NOT_EXIST);
		return false;
	}

	auto imageDosHeader{reinterpret_cast<::PIMAGE_DOS_HEADER>(libraryBytecode)};
	if (imageDosHeader->e_magic != 0x5A4D) 
	{
		errorHandler(MANUALMAP_ERROR_CODE::MODULE_UNKNOWN_ARCHITECTURE);
		return false;
	}

	auto imageNtHeader{reinterpret_cast<::PIMAGE_NT_HEADERS>(
		reinterpret_cast<::DWORD>(libraryBytecode) + imageDosHeader->e_lfanew)};

	::PIMAGE_OPTIONAL_HEADER imageOptionalHeader{&imageNtHeader->OptionalHeader};
	::PIMAGE_FILE_HEADER imageFileHeader{&imageNtHeader->FileHeader};

	::LPVOID imageVirtualMemory{::VirtualAllocEx(targetProcess, nullptr, 
		imageOptionalHeader->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};

	if (!imageVirtualMemory) 
	{
		errorHandler(MANUALMAP_ERROR_CODE::MODULE_VIRTUAL_MEMORY_ALLOCATION);
		return false;
	}

	if (!::WriteProcessMemory(targetProcess, imageVirtualMemory,
		libraryBytecode, imageOptionalHeader->SizeOfHeaders, NULL))
	{
		errorHandler(MANUALMAP_ERROR_CODE::MODULE_VIRTUAL_MEMORY_INITIALIZATION);
		::VirtualFreeEx(targetProcess, imageVirtualMemory, 0, MEM_RELEASE);

		return false;
	}

	::PIMAGE_SECTION_HEADER imageSectionHeader{IMAGE_FIRST_SECTION(imageNtHeader)};
	for (::DWORD i{0}; i < imageFileHeader->NumberOfSections; ++i)
	{
		if (imageSectionHeader[i].SizeOfRawData)
		{
			const BOOL sectionWriteResult{
				::WriteProcessMemory(targetProcess,
					reinterpret_cast<::LPVOID>(
						reinterpret_cast<::DWORD>(imageVirtualMemory) +
						imageSectionHeader[i].VirtualAddress),
					reinterpret_cast<::LPCVOID>(
						reinterpret_cast<::DWORD>(libraryBytecode) +
						imageSectionHeader[i].PointerToRawData),
					imageSectionHeader[i].SizeOfRawData, nullptr)};

			if (FALSE == sectionWriteResult) 
			{
				errorHandler(MANUALMAP_ERROR_CODE::MODULE_MAPPING_SECTION_INVALID);
				::VirtualFreeEx(targetProcess, imageVirtualMemory, 0, MEM_RELEASE);

				return false;
			}
		}
	}

	const ::SIZE_T oneVirtualPageSize{4096};
	::LPVOID shellcodeVirtualMemory{::VirtualAllocEx(targetProcess, nullptr, 
		oneVirtualPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};

	if (!shellcodeVirtualMemory) 
	{
		errorHandler(MANUALMAP_ERROR_CODE::SHELLCODE_VIRTUAL_MEMORY_ALLOCATION);
		::VirtualFreeEx(targetProcess, imageVirtualMemory, 0, MEM_RELEASE);

		return false;
	}

	auto pairFree = [&]()
	{
		::VirtualFreeEx(targetProcess, imageVirtualMemory, 0, MEM_RELEASE);
		::VirtualFreeEx(targetProcess, shellcodeVirtualMemory, 0, MEM_RELEASE);
	};

	if (!::WriteProcessMemory(targetProcess, shellcodeVirtualMemory,
		reinterpret_cast<::LPCVOID>(&LibraryInitializationRemoteThread), oneVirtualPageSize, nullptr))
	{
		errorHandler(MANUALMAP_ERROR_CODE::SHELLCODE_VIRTUAL_MEMORY_INITIALIZATION);
		pairFree();

		return false;
	}

	::LPVOID paramsVirtualMemory{::VirtualAllocEx(targetProcess, nullptr,
		sizeof(stLoaderParams), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)};

	if (!paramsVirtualMemory) 
	{
		errorHandler(MANUALMAP_ERROR_CODE::PARAMS_VIRTUAL_MEMORY_ALLOCATION);
		pairFree();

		return false;
	}

	auto fullyFree = [&]()
	{
		::VirtualFreeEx(targetProcess, imageVirtualMemory, 0, MEM_RELEASE);
		::VirtualFreeEx(targetProcess, shellcodeVirtualMemory, 0, MEM_RELEASE);
		::VirtualFreeEx(targetProcess, paramsVirtualMemory, 0, MEM_RELEASE);
	};

	stLoaderParams loaderParams;

	loaderParams.dwGetProcAddress = reinterpret_cast<::DWORD>(&::GetProcAddress);
	loaderParams.dwLoadLibrary = reinterpret_cast<::DWORD>(&::LoadLibraryA);
	loaderParams.dwModuleBase = reinterpret_cast<::DWORD>(imageVirtualMemory);

	::HMODULE ntdllLibrary{::LoadLibraryA("ntdll.dll")};
	if (!ntdllLibrary) 
	{
		errorHandler(MANUALMAP_ERROR_CODE::NTMODULE_DOES_NOT_EXIST);
		fullyFree();

		return false;
	}

	loaderParams.dwRtlZeroMemory = ::DWORD(::GetProcAddress(ntdllLibrary, "RtlZeroMemory"));

	loaderParams.imageBaseRelocation = reinterpret_cast<::PIMAGE_BASE_RELOCATION>(
		reinterpret_cast<::DWORD>(imageVirtualMemory) + 
		imageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	loaderParams.imageImportDescriptor = reinterpret_cast<::PIMAGE_IMPORT_DESCRIPTOR>(
		reinterpret_cast<::DWORD>(imageVirtualMemory) +
		imageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	loaderParams.imageNtHeader = reinterpret_cast<::PIMAGE_NT_HEADERS>(
		reinterpret_cast<::DWORD>(imageVirtualMemory) + imageDosHeader->e_lfanew);

	if (!::WriteProcessMemory(targetProcess, paramsVirtualMemory,
		reinterpret_cast<::LPCVOID>(&loaderParams), sizeof(stLoaderParams), nullptr))
	{
		errorHandler(MANUALMAP_ERROR_CODE::PARAMS_VIRTUAL_MEMORY_INITIALIZATION);
		fullyFree();

		return false;
	}

	const ::HANDLE threadHandle{::CreateRemoteThread(targetProcess, nullptr, 0,
		reinterpret_cast<::LPTHREAD_START_ROUTINE>(shellcodeVirtualMemory), paramsVirtualMemory, 0, nullptr)};

	if (INVALID_HANDLE_VALUE == threadHandle || !threadHandle)
	{
		errorHandler(MANUALMAP_ERROR_CODE::REMOTE_THREAD_CREATION);
		fullyFree();

		return false;
	}

	const ::DWORD waitCode{::WaitForSingleObject(threadHandle, INFINITE)};
	if (WAIT_FAILED == waitCode) 
	{
		errorHandler(MANUALMAP_ERROR_CODE::WAIT_FOR_SINGLE_OBJECT);
		fullyFree();

		::CloseHandle(threadHandle);
		return false;
	}

	::DWORD threadExitCode{EXIT_SUCCESS};
	if (!::GetExitCodeThread(threadHandle, &threadExitCode))
	{
		errorHandler(MANUALMAP_ERROR_CODE::GET_EXIT_CODE_THREAD);
		fullyFree();

		::CloseHandle(threadHandle);
		return false;
	}

	if (EXIT_SUCCESS != threadExitCode)
	{
		errorHandler(MANUALMAP_ERROR_CODE(threadExitCode));
		fullyFree();

		::CloseHandle(threadHandle);
		return false;
	}

	::VirtualFreeEx(targetProcess, shellcodeVirtualMemory, 0, MEM_RELEASE);
	::VirtualFreeEx(targetProcess, paramsVirtualMemory, 0, MEM_RELEASE);

	::CloseHandle(threadHandle);

	return true;
}