@echo off

REM Configuration file containing allowed USB devices
set ALLOWED_USB_FILE=allowed_usb.txt

REM Monitor USB devices
:monitor
for /f "tokens=2,4,7" %%a in ('reg query HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR /s /f "FriendlyName" ^| findstr /i /c:"USB Disk" /c:"USB Flash Drive"') do (
    set "vid=%%a"
    set "pid=%%b"
    set "device=%%c"
    set "device=!device:~0,-8!"
    set "bus=!device:~-4!"

    REM Check if the device is in the allowed USB list
    findstr /c:"!vid!:!pid!" %ALLOWED_USB_FILE% >nul
    if %errorlevel% neq 0 (
        REM Disable the unauthorized USB device
        echo Disabling USB device !vid!:!pid! with bus ID !bus!...
        devcon disable "@USB\VID_!vid!&PID_!pid!\!bus!\*"
    )
)

REM Wait 5 seconds before checking again
ping 127.0.0.1 -n 6 >nul

REM Go back to monitoring
goto monitor
