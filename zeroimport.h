/*
https://github.com/1hAck-0/zeroimport
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org>
*/
#if _MSC_VER >= 1200
#pragma once
#endif

#ifndef ZERO_IMPORT_H
#define ZERO_IMPORT_H

#include <ntdef.h> // type definitions
#include <wdm.h> // function prototypes (needed for MmGetSystemRoutineAddress)



#define ZR_IMP_ENABLE_FORCEINLINE true

// change this to generate unique hashes!
#define ZR_IMP_UNIQUE_KEY 0x738CE813D989
// the key is not randomly generated at compile by using macros such as __TIME__,
// because it breaks the hashing algorithm for whatever reason,
// try it for yourself

#define ZR_IMP_PTR_NOT_CACHED(imp) (zeroimport::detail::GetNtoskrnlExport(zeroimport::detail::HashString(imp)))
#define ZR_IMP_PTR_CACHED(imp) (zeroimport::detail::GetNtoskrnlExport<zeroimport::detail::HashString(imp)>())

#define ZR_IMP_NOT_CACHED(imp) ((decltype(&imp))ZR_IMP_PTR_NOT_CACHED(#imp))
#define ZR_IMP_CACHED(imp) ((decltype(&imp))ZR_IMP_PTR_CACHED(#imp))

// default zeroimport macro
#define ZR_IMP ZR_IMP_CACHED



#if ZR_IMP_ENABLE_FORCEINLINE
#define ZR_IMP_FORCEINLINE __forceinline
#else
#define ZR_IMP_FORCEINLINE inline
#endif

namespace zeroimport
{
	bool init();

	namespace detail
	{
		extern uintptr_t NtoskrnlBase;
		extern uintptr_t NtoskrnlExportDir;

		typename typedef uintptr_t HashType;
		ZR_IMP_FORCEINLINE constexpr auto HashString(const char* Str)
		{
			HashType Hash = ZR_IMP_UNIQUE_KEY;

			for (size_t i = 0; Str[i]; i++)
			{
				HashType c = Str[i];

				Hash ^= (c * c) << ((i + 1) % 8);
				Hash *= i + 1;
			}

			return Hash;
		}


		// PE header structures
		typedef struct _IMAGE_FILE_HEADER {
			WORD  Machine;
			WORD  NumberOfSections;
			DWORD TimeDateStamp;
			DWORD PointerToSymbolTable;
			DWORD NumberOfSymbols;
			WORD  SizeOfOptionalHeader;
			WORD  Characteristics;
		} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

		typedef struct _IMAGE_DATA_DIRECTORY {
			DWORD   VirtualAddress;
			DWORD   Size;
		} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

		typedef struct _IMAGE_OPTIONAL_HEADER {
			WORD        Magic;
			BYTE        MajorLinkerVersion;
			BYTE        MinorLinkerVersion;
			DWORD       SizeOfCode;
			DWORD       SizeOfInitializedData;
			DWORD       SizeOfUninitializedData;
			DWORD       AddressOfEntryPoint;
			DWORD       BaseOfCode;
			ULONGLONG   ImageBase;
			DWORD       SectionAlignment;
			DWORD       FileAlignment;
			WORD        MajorOperatingSystemVersion;
			WORD        MinorOperatingSystemVersion;
			WORD        MajorImageVersion;
			WORD        MinorImageVersion;
			WORD        MajorSubsystemVersion;
			WORD        MinorSubsystemVersion;
			DWORD       Win32VersionValue;
			DWORD       SizeOfImage;
			DWORD       SizeOfHeaders;
			DWORD       CheckSum;
			WORD        Subsystem;
			WORD        DllCharacteristics;
			ULONGLONG   SizeOfStackReserve;
			ULONGLONG   SizeOfStackCommit;
			ULONGLONG   SizeOfHeapReserve;
			ULONGLONG   SizeOfHeapCommit;
			DWORD       LoaderFlags;
			DWORD       NumberOfRvaAndSizes;
			IMAGE_DATA_DIRECTORY DataDirectory[16];
		} IMAGE_OPTIONAL_HEADER, * PIMAGE_OPTIONAL_HEADER;

		typedef struct _IMAGE_NT_HEADERS {
			DWORD                   Signature;
			IMAGE_FILE_HEADER       FileHeader;
			IMAGE_OPTIONAL_HEADER OptionalHeader;
		} IMAGE_NT_HEADERS, * PIMAGE_NT_HEADERS;

		typedef struct _IMAGE_EXPORT_DIRECTORY {
			DWORD   Characteristics;
			DWORD   TimeDateStamp;
			WORD    MajorVersion;
			WORD    MinorVersion;
			DWORD   Name;
			DWORD   Base;
			DWORD   NumberOfFunctions;
			DWORD   NumberOfNames;
			DWORD   AddressOfFunctions;     // RVA from base of image
			DWORD   AddressOfNames;         // RVA from base of image
			DWORD   AddressOfNameOrdinals;  // RVA from base of image
		} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory


		ZR_IMP_FORCEINLINE PVOID GetNtoskrnlExport(HashType Hash)
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

		template<HashType Hash>
		ZR_IMP_FORCEINLINE PVOID GetNtoskrnlExport()
		{
			static PVOID pCached = 0;
			if (!pCached)
				pCached = GetNtoskrnlExport(Hash);

			return pCached;
		}


		// module entry (needed for ntoskrnl.exe base)
		typedef struct _LDR_DATA_TABLE_ENTRY
		{
			LIST_ENTRY InLoadOrderModuleList;
			LIST_ENTRY InMemoryOrderModuleList;
			LIST_ENTRY InInitializationOrderModuleList;
			PVOID DllBase;
			PVOID EntryPoint;
			ULONG SizeOfImage;
			UNICODE_STRING FullDllName;
			UNICODE_STRING BaseDllName;
			ULONG Flags;
			WORD LoadCount;
			WORD TlsIndex;
			LIST_ENTRY HashLinks;
			PVOID SectionPointer;
			ULONG CheckSum;
			ULONG TimeDateStamp;
		} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
		PLDR_DATA_TABLE_ENTRY GetSystemModuleEntry(const wchar_t* ModuleName);
	}
}

#endif // ZERO_IMPORT_H
