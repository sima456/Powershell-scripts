# Configuration file containing allowed USB devices
$allowedUsbFile = "allowed_usb.txt"

# Get list of allowed USB IDs from configuration file
$allowedUsb = Get-Content $allowedUsbFile

# Monitor USB devices
while ($true) {
    # Get list of connected USB devices
    $usbDevices = Get-PnpDevice -Class "USB" | Where-Object {$_.Status -ne "OK"}

    # Loop through all the USB devices
    foreach ($device in $usbDevices) {
        # Get the device's Vendor ID and Product ID
        $vidPid = $device.HardwareId.Split('\')[-2]
        $vid, $pid = $vidPid.Split("_")

        # Check if the device is allowed
        if ($allowedUsb -notcontains "$vid:$pid") {
            # Disable the device by uninstalling it
            Write-Host "Disabling unauthorized USB device $($device.Description)"
            $device.Uninstall()
        }
    }

    # Wait for 5 seconds before checking again
    Start-Sleep -Seconds 5
}
