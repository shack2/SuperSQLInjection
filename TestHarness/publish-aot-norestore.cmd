@echo off
set HOME=C:\Users\asus
set HOMEDRIVE=C:
set HOMEPATH=\Users\asus
set USERPROFILE=C:\Users\asus
set APPDATA=C:\Users\asus\AppData\Roaming
set LOCALAPPDATA=C:\Users\asus\AppData\Local
set ProgramData=C:\ProgramData
set PUBLIC=C:\Users\Public
set SystemRoot=C:\Windows
set windir=C:\Windows
set OS=Windows_NT
set TEMP=C:\Users\asus\AppData\Local\Temp
set TMP=C:\Users\asus\AppData\Local\Temp
set ProgramFiles=C:\Program Files
set "ProgramFiles(x86)=C:\Program Files (x86)"
set ProgramW6432=C:\Program Files
set MSVCDIR=C:\Program Files\Microsoft Visual Studio\18\Professional\VC\Tools\MSVC\14.44.35207
set SDKDIR=C:\Program Files (x86)\Windows Kits\10
set INCLUDE=%MSVCDIR%\include;%SDKDIR%\Include\10.0.26100.0\ucrt;%SDKDIR%\Include\10.0.26100.0\um;%SDKDIR%\Include\10.0.26100.0\shared;%SDKDIR%\Include\10.0.26100.0\winrt
set LIB=%MSVCDIR%\lib\x64;%SDKDIR%\Lib\10.0.26100.0\ucrt\x64;%SDKDIR%\Lib\10.0.26100.0\um\x64
set PATH=%MSVCDIR%\bin\HostX64\x64;%SDKDIR%\bin\10.0.26100.0\x64;C:\Program Files\dotnet;C:\Windows\system32;C:\Windows
set PUBDIR=F:\MyCoding\c#\AI\SuperSQLInjectionV2\SuperSQLInjectionV2.Desktop\bin\Release\net10.0\win-x64\publish
if exist "%PUBDIR%" rmdir /s /q "%PUBDIR%"
"C:\Program Files\dotnet\dotnet.exe" publish F:\MyCoding\c#\AI\SuperSQLInjectionV2\SuperSQLInjectionV2.Desktop\SuperSQLInjectionV2.Desktop.csproj -c Release -r win-x64 --no-restore -p:PublishAot=true -p:PublishTrimmed=true -p:IlcUseEnvironmentalTools=true
del /q "%PUBDIR%\*.pdb" 2>/dev/null
echo PUBDIR=%PUBDIR%
