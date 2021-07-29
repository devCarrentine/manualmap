#include "winapi.h"

std::uintptr_t win32::getProcAddress(::HMODULE hModule, const char *szAPIName)
{
	unsigned char *lpBase = reinterpret_cast<unsigned char *>(hModule);
	IMAGE_DOS_HEADER *idhDosHeader = reinterpret_cast<IMAGE_DOS_HEADER *>(lpBase);

	if (idhDosHeader->e_magic == 0x5A4D)
	{
		IMAGE_NT_HEADERS32 *inhNtHeader = reinterpret_cast<IMAGE_NT_HEADERS32 *>(lpBase + idhDosHeader->e_lfanew);

		if (inhNtHeader->Signature == 0x4550)
		{
			IMAGE_EXPORT_DIRECTORY *iedExportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY *>(lpBase +
				inhNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

			for (unsigned int uiIter = 0; uiIter < iedExportDirectory->NumberOfNames; ++uiIter)
			{
				char *szNames = reinterpret_cast<char *>(lpBase +
					reinterpret_cast<unsigned long *>(lpBase +
						iedExportDirectory->AddressOfNames)[uiIter]);

				if (!strcmp(szNames, szAPIName))
				{
					unsigned short usOrdinal = reinterpret_cast<unsigned short *>(
						lpBase + iedExportDirectory->AddressOfNameOrdinals)[uiIter];

					return reinterpret_cast<std::uintptr_t>(lpBase +
						reinterpret_cast<unsigned long *>(lpBase +
							iedExportDirectory->AddressOfFunctions)[usOrdinal]);
				}
			}
		}
	}

	return 0;
}

wchar_t *GetFileNameFromPath(wchar_t *Path)
{
	wchar_t *LastSlash = NULL;
	for (DWORD i = 0; Path[i] != NULL; i++)
	{
		if (Path[i] == '\\')
			LastSlash = &Path[i + 1];
	}
	return LastSlash;
}

wchar_t *RemoveFileExtension(wchar_t *FullFileName, wchar_t *OutputBuffer, DWORD OutputBufferSize)
{
	wchar_t *LastDot = NULL;
	for (DWORD i = 0; FullFileName[i] != NULL; i++)
		if (FullFileName[i] == '.')
			LastDot = &FullFileName[i];

	for (DWORD j = 0; j < OutputBufferSize; j++)
	{
		OutputBuffer[j] = FullFileName[j];
		if (&FullFileName[j] == LastDot)
		{
			OutputBuffer[j] = NULL;
			break;
		}
	}
	OutputBuffer[OutputBufferSize - 1] = NULL;
	return OutputBuffer;
}

HMODULE WINAPI GetModuleW(_In_opt_ LPCWSTR lpModuleName)
{
	struct PEB_LDR_DATA
	{
		ULONG Length;
		BOOLEAN Initialized;
		HANDLE SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID EntryInProgress;
		BOOLEAN ShutdownInProgress;
		HANDLE ShutdownThreadId;
	};

	struct PEB
	{
		BOOLEAN InheritedAddressSpace;
		BOOLEAN ReadImageFileExecOptions;
		BOOLEAN BeingDebugged;
		union
		{
			BOOLEAN BitField;
#pragma warning (disable : 4201)
			struct
			{
				BOOLEAN ImageUsesLargePages : 1;
				BOOLEAN IsProtectedProcess : 1;
				BOOLEAN IsImageDynamicallyRelocated : 1;
				BOOLEAN SkipPatchingUser32Forwarders : 1;
				BOOLEAN IsPackagedProcess : 1;
				BOOLEAN IsAppContainer : 1;
				BOOLEAN IsProtectedProcessLight : 1;
				BOOLEAN SpareBits : 1;
			};
		};
		HANDLE Mutant;
		PVOID ImageBaseAddress;
		PEB_LDR_DATA *Ldr;
		//...
	};

	struct CLIENT_ID
	{
		HANDLE UniqueProcess;
		HANDLE UniqueThread;
	};

	struct TEB
	{
		NT_TIB NtTib;
		PVOID EnvironmentPointer;
		CLIENT_ID ClientId;
		PVOID ActiveRpcHandle;
		PVOID ThreadLocalStoragePointer;
		struct PEB *ProcessEnvironmentBlock;
		//...
	};

	struct UNICODE_STRING
	{
		USHORT Length;
		USHORT MaximumLength;
		PWCH Buffer;
	};

	struct LDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		union
		{
			LIST_ENTRY InInitializationOrderLinks;
			LIST_ENTRY InProgressLinks;
		};
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		//...
	};

	PEB *ProcessEnvironmentBlock = ((PEB *)((TEB *)((TEB *)NtCurrentTeb())->ProcessEnvironmentBlock));
	if (lpModuleName == nullptr)
		return (HMODULE)(ProcessEnvironmentBlock->ImageBaseAddress);

	PEB_LDR_DATA *Ldr = ProcessEnvironmentBlock->Ldr;

	LIST_ENTRY *ModuleLists[3] = {0,0,0};
	ModuleLists[0] = &Ldr->InLoadOrderModuleList;
	ModuleLists[1] = &Ldr->InMemoryOrderModuleList;
	ModuleLists[2] = &Ldr->InInitializationOrderModuleList;
	for (int j = 0; j < 3; j++)
	{
		for (LIST_ENTRY *pListEntry = ModuleLists[j]->Flink;
			pListEntry != ModuleLists[j];
			pListEntry = pListEntry->Flink)
		{
			LDR_DATA_TABLE_ENTRY *pEntry = (LDR_DATA_TABLE_ENTRY *)((BYTE *)pListEntry - sizeof(LIST_ENTRY) * j); //= CONTAINING_RECORD( pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );

			if (_wcsicmp(pEntry->BaseDllName.Buffer, lpModuleName) == 0)
				return (HMODULE)pEntry->DllBase;

			wchar_t *FileName = GetFileNameFromPath(pEntry->FullDllName.Buffer);
			if (!FileName)
				continue;

			if (_wcsicmp(FileName, lpModuleName) == 0)
				return (HMODULE)pEntry->DllBase;

			wchar_t FileNameWithoutExtension[256];
			RemoveFileExtension(FileName, FileNameWithoutExtension, 256);

			if (_wcsicmp(FileNameWithoutExtension, lpModuleName) == 0)
				return (HMODULE)pEntry->DllBase;
		}
	}
	return nullptr;
}