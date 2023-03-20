# ZeroImport for Windows Kernel Drivers
ZeroImport is a super lightweight C++ library for Windows Kernel Drivers. It allows you to hide any function import in your kernel driver by importing the functions at runtime.

# Use Example
The following example shows how you could call `MmIsAddressValid` without importing the function. This can be, of course, applied to any imported function you want to call.
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

# Support
- **Any Windows version** should be supported
- **C++11** and higher

# How it Works
Most if not all function imports you will ever need in a kernelmode driver on Windows are inside `ntoskrnl.exe`, ZeroImport just searches ntoskrnl.exe's exported functions at runtime and finds the right function through hashing. The names of the functions that we call inside our code are hashed at compile-time.

# Use Purposes
- **Difficult Static Analysis** of your driver
- Avoids **unwanted IAT (Import Address Table) Hooks** inside your driver placed by other loaded drivers
