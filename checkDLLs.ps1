# Get the DLL file path from user input
$dllPath = Read-Host "Enter the DLL file path"

# Get all running processes
$processes = Get-Process

# Loop through each process
foreach ($process in $processes) {
    $processName = $process.ProcessName

    # Check if the DLL is loaded in the process
    try {
        $loadedModules = Get-Process -Id $process.Id -Module -ErrorAction Stop
        $isDllLoaded = $loadedModules.ModuleName -contains (Get-Item -Path $dllPath).Name
    } catch {
        # Handle access denied error gracefully
        if ($_.Exception.Message -like "*Cannot enumerate the modules*") {
            Write-Host "Access denied for process '$processName'"
            continue
        } else {
            Write-Host "Failed to retrieve modules for process '$processName': $($_.Exception.Message)"
            continue
        }
    }

    if (!$isDllLoaded) {
        Write-Host "DLL not loaded in process '$processName'"
    }
}
