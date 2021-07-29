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
