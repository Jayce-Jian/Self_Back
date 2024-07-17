# adduser

Programmatically creates a 'local admin' Windows user. Requires admin rights. The created user is hardcoded to the following:

Login: `audit`
Password: `Test123456789!` (this should be good enough to fit most password policies)

This standalone piece code can run in many contexts:
- As a command-line EXE.
- As a DLL (the user will be created on DLL load). This is useful to exploit "DLL Preloading" issues.
- As a DLL, requires admin rights through `rundll32.exe adduser.dll,CreateAdminUser`. This is useful to bypass mandatory code signing applied to EXE files only.

## Compiling
### Using MinGW (tested on Linux)

- Linux安装gcc包:
`sudo apt install gcc-mingw-w64 -y`
- Create a 32-bit EXE file:
`i686-w64-mingw32-gcc -o adduser32.exe adduser.c -l netapi32`
- Create a 32-bit DLL file:
`i686-w64-mingw32-gcc -shared -o adduser32.dll adduser.c -l netapi32`
- Create a 64-bit EXE file:
`x86_64-w64-mingw32-gcc -o adduser64.exe adduser.c -l netapi32`
- Create a 64-bit DLL file:
`x86_64-w64-mingw32-gcc -shared -o adduser64.dll adduser.c -l netapi32`

### Using Visual Studio (tested with VS2013)

- Create an EXE file:
`cl.exe adduser.c /link /DEFAULTLIB:ADVAPI32 /DEFAULTLIB:NETAPI32`
- Create a DLL file:
`cl.exe adduser.c /LD /link /DEFAULTLIB:ADVAPI32 /DEFAULTLIB:NETAPI32`
### 修改引用相对路径中的头文件
- `#include <xxx.h>`
**改为**
`#include "xxx.h"`
### 头文件下载
- [exefiles](https://www.exefiles.com/en/h/windows-h/)
### 查看引用头文件位置
- *C：*
`gcc -print-prog-name=cc1 -v`
- *C++：*
`gcc -print-prog-name=cc1plus -v`
