#ifndef ZERO_IMPORT_H
#define ZERO_IMPORT_H

#include <ntdef.h> // TYPE DEFINITIONS
#include <wdm.h> // FUNCTION PROTOTYPES (needed for MmGetSystemRoutineAddress)



#define ZR_IMP_NOT_CACHED(imp) ((decltype(&imp))zeroimport::detail::GetNtoskrnlExport(zeroimport::detail::HashString(#imp)))
#define ZR_IMP_CACHED(imp) ((decltype(&imp))zeroimport::detail::GetNtoskrnlExport<zeroimport::detail::HashString(#imp)>())

#define ZR_IMP ZR_IMP_CACHED

#define ZR_IMP_UNIQUE_KEY 0xF572458C39B10 // TO DO: change this number to generate unique hashes

namespace zeroimport
{
	bool init();

	namespace detail
	{
		static uintptr_t NtoskrnlBase = 0;
		static uintptr_t NtoskrnlExportDir = 0;

		typename typedef uintptr_t HashType;

		PVOID GetNtoskrnlExport(HashType Hash);

		template<HashType Hash>
		inline PVOID GetNtoskrnlExport()
		{
			static PVOID pCached = 0;
			if (!pCached)
				pCached = GetNtoskrnlExport(Hash);

			return pCached;
		}

		inline constexpr auto HashString(const char* Str)
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



		// MODULE ENTRY (needed for ntoskrnl.exe base)
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
		LDR_DATA_TABLE_ENTRY* GetSystemModuleEntry(const wchar_t* ModuleName);



		// PE HEADER STRUCTURES
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
	}
}

#endif // ZERO_IMPORT_H
