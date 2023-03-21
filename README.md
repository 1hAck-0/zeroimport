# ZeroImport for Windows Kernel Drivers
ZeroImport is a super-lightweight and easy to use C++ library for Windows Kernel Drivers. It allows you to hide any function or variable import in your kernel driver by importing them at runtime.

## Use Example
First **initialize ZeroImport** at the very beginning of your driver (DriverEntry)
```cpp
if (!zeroimport::init())
{
   // error handling (normally zeroimport::init() should never fail!)
}
```

The following example shows how you could for example call `MmIsAddressValid` without statically importing the function in your driver. This can be, of course, applied to any imported function you want to call.
```cpp
PVOID Address = 0;

// import and cache MmIsAddressValid at runtime and then call it
if (ZR_IMP_CACHED(MmIsAddressValid)(Address))
{
   // ...
}

// import (without caching) MmIsAddressValid at runtime and then call it
if (ZR_IMP_NOT_CACHED(MmIsAddressValid)(Address))
{
   // ...
}

// using the default shorter macro
if (ZR_IMP(MmIsAddressValid)(Address))
{
   // ...
}
```
It's important to note that ZeroImport can import any type of exported symbol, not just functions. For example variables such as `PsLoadedModuleList` or `PsInitialSystemProcess`.
```cpp
LIST_ENTRY PsLoadedModuleList; // We need to define PsLoadedModuleList manually so that ZeroImport knows the type of import
PLIST_ENTRY pPsLoadedModuleList = ZR_IMP(PsLoadedModuleList);
// ...

PEPROCESS InitialProcess = *ZR_IMP(PsInitialSystemProcess); // PsInitialSystemProcess is already defined in ntddk.h
if (!InitialProcess)
// ...
```

## Support
- **All Windows version** should be supported (literally all)
- **C++11** and higher

## How it Works
Most if not all imports you will ever need in a kernelmode driver on Windows are inside `ntoskrnl.exe` so ZeroImport just searches ntoskrnl.exe's exported symbols at runtime and finds the right symbol by its name through hash-comparing. The names of the symbols that we want to import inside our code are hashed at compile-time for faster runtime and better security (see `zeroimport::detail::HashString()`).

## Use Purposes
- **Difficult Static Analysis** of your driver
- Avoids **unwanted IAT (Import Address Table) Hooks** inside your driver placed by other loaded drivers

## Credits
Inspired by [lazy-importer](https://github.com/JustasMasiulis/lazy_importer) which does the same thing but only for usermode applications
