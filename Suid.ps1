param(
  [Parameter(Mandatory=$true, Position=0)]
  [string]$Sid
)

try {
  # Convert the SID string to a SID object
  $sid_obj = New-Object System.Security.Principal.SecurityIdentifier($Sid)

  # Look up the account name and domain name for the SID
  $account = $sid_obj.Translate([System.Security.Principal.NTAccount])

  # Return the fully-qualified account name
  Write-Output $account.Value
} catch {
  # If the SID could not be translated, return an error message
  Write-Output "Error: $_"
}
