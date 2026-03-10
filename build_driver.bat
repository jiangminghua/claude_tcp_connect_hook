@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
MSBuild.exe WfpDriver\WfpDriver.vcxproj /p:Configuration=Release /p:Platform=x64 /v:minimal /t:Rebuild
echo EXIT_CODE=%ERRORLEVEL%
