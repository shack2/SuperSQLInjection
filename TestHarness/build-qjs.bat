@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d C:\Users\asus\AppData\Local\Temp\qjs-amg
if errorlevel 1 (echo CD_FAIL & exit /b 1)
cl /nologo /LD /O2 /MT /std:c17 /experimental:c11atomics /DBUILDING_QJS_SHARED /DWIN32_LEAN_AND_MEAN quickjs-amalgam.c /Fe:libquickjs.dll /link /NOLOGO
echo CL_EXIT=%errorlevel%
