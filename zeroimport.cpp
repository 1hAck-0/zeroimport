#include "pch.h" // if you are using pre-compiled headers
#include "zeroimport.h"



bool zeroimport::init()
{
	using namespace detail;

	auto NtoskrnlEntry = GetSystemModuleEntry(L"ntoskrnl.exe");
	if (!NtoskrnlEntry || !NtoskrnlEntry->DllBase)
		return false;

	NtoskrnlBase = (uintptr_t)NtoskrnlEntry->DllBase;

	IMAGE_NT_HEADERS* pNtHeader = (IMAGE_NT_HEADERS*)(NtoskrnlBase + *(LONG*)(NtoskrnlBase + 0x3C));

	uintptr_t ExportDirRVA = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (!ExportDirRVA)
		return false;

	NtoskrnlExportDir = NtoskrnlBase + ExportDirRVA;

	return true;
}

PVOID zeroimport::detail::GetNtoskrnlExport(HashType Hash)
{
	IMAGE_EXPORT_DIRECTORY* ExportDir = (IMAGE_EXPORT_DIRECTORY*)NtoskrnlExportDir;

	DWORD* NameRVAs = (DWORD*)(NtoskrnlBase + ExportDir->AddressOfNames);
	for (DWORD i = 0; i < ExportDir->NumberOfNames; i++)
	{
		if (HashString((char*)(NtoskrnlBase + NameRVAs[i])) != Hash)
			continue;

		WORD* Ordinals = (WORD*)(NtoskrnlBase + ExportDir->AddressOfNameOrdinals);
		DWORD* FunctionRVAs = (DWORD*)(NtoskrnlBase + ExportDir->AddressOfFunctions);

		return (PVOID)(NtoskrnlBase + FunctionRVAs[Ordinals[i]]);
	}

	return 0;
}

zeroimport::detail::LDR_DATA_TABLE_ENTRY* zeroimport::detail::GetSystemModuleEntry(const wchar_t* ModuleName)
{
	if (!ModuleName || !ModuleName[0])
		return 0;

	auto RtlInitUnicodeString = [](PUNICODE_STRING DestinationString, PCWSTR SourceString)->void
	{
		DestinationString->Buffer = (wchar_t*)SourceString;

		WORD StrLen = 0;
		while (SourceString[StrLen])
			StrLen++;

		DestinationString->Length = StrLen * sizeof(wchar_t);
		DestinationString->MaximumLength = ++StrLen * sizeof(wchar_t);
	};

	auto wcscimp = [](const wchar_t* str1, const wchar_t* str2)->bool
	{
		for (; *str1 || *str2; str1++, str2++)
		{
			wchar_t c1 = *str1;
			c1 += ('a' - 'A') * (c1 >= 'A' && c1 <= 'Z'); // make lowercase

			wchar_t c2 = *str2;
			c2 += ('a' - 'A') * (c2 >= 'A' && c2 <= 'Z'); // make lowercase

			if (c1 != c2)
				return false;
		}

		return true;
	};

	static PLIST_ENTRY pModuleList = 0;
	if (!pModuleList)
	{
		UNICODE_STRING UnicodeBuf;
		RtlInitUnicodeString(&UnicodeBuf, L"PsLoadedModuleList");

		pModuleList = (PLIST_ENTRY)MmGetSystemRoutineAddress(&UnicodeBuf);
		if (!pModuleList)
			return 0;
	}

	for (PLIST_ENTRY pLink = pModuleList; pLink != pModuleList->Blink; pLink = pLink->Flink)
	{
		LDR_DATA_TABLE_ENTRY* pEntry = CONTAINING_RECORD(pLink, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
		if (!pEntry->BaseDllName.Buffer)
			continue;

		if (wcscimp(pEntry->BaseDllName.Buffer, ModuleName))
			return pEntry;
	}

	return 0;
}
