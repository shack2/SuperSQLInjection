@echo off
set HOME=C:\Users\asus
set USERPROFILE=C:\Users\asus
set APPDATA=C:\Users\asus\AppData\Roaming
set LOCALAPPDATA=C:\Users\asus\AppData\Local
set ProgramData=C:\ProgramData
set ProgramFiles=C:\Program Files
set "ProgramFiles(x86)=C:\Program Files (x86)"
set ProgramW6432=C:\Program Files
set SystemRoot=C:\Windows
set windir=C:\Windows
set OS=Windows_NT
set PATH=C:\Program Files\dotnet;C:\Windows\system32;C:\Windows
"C:\Program Files\Microsoft Visual Studio\18\Professional\MSBuild\Current\Bin\MSBuild.exe" F:\MyCoding\c#\AI\SuperSQLInjectionV2\SuperSQLInjectionV2.Desktop\SuperSQLInjectionV2.Desktop.csproj -t:restore -v:m -nologo -p:RestoreForce=true -p:RestoreForceEvaluate=true -p:RuntimeIdentifier=win-x64 -p:PublishAot=true -p:PublishTrimmed=true
