using namespace System.Management.Automation
function Search-SysmonCommandline
{
    [CmdletBinding(DefaultParameterSetName='InProcess')]
    
    Param(
        [Parameter(Mandatory = $True)]
        [string[]]$CommandLine,

        [Parameter(Mandatory = $False)]
        [datetime]$StartTime = (Get-Date).AddMinutes(-10),

        [Parameter(Mandatory = $False)]
        [datetime]$EndTime = (Get-Date),

        [Parameter(ParameterSetName = 'Session')]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Runspaces.PSSession[]]
        ${Session},

        [Parameter(ParameterSetName = 'ComputerName')]
        [Alias('Cn')]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${ComputerName},

        [Parameter(ParameterSetName = 'ComputerName', ValueFromPipelineByPropertyName = $True)]
        [Parameter(ParameterSetName = 'Uri', ValueFromPipelineByPropertyName = $True)]
        [Parameter(ParameterSetName = 'VMId', Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Parameter(ParameterSetName = 'VMName', Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        ${Credential},

        [Parameter(ParameterSetName = 'ComputerName')]
        [ValidateRange(1, 65535)]
        [int]
        ${Port},

        [Parameter(ParameterSetName = 'ComputerName')]
        [switch]
        ${UseSSL},

        [Parameter(ParameterSetName = 'Uri', ValueFromPipelineByPropertyName = $True)]
        [Parameter(ParameterSetName = 'ComputerName', ValueFromPipelineByPropertyName = $True)]
        [Parameter(ParameterSetName = 'ContainerId', ValueFromPipelineByPropertyName = $True)]
        [Parameter(ParameterSetName = 'VMId', ValueFromPipelineByPropertyName = $True)]
        [Parameter(ParameterSetName = 'VMName', ValueFromPipelineByPropertyName = $True)]
        [string]
        ${ConfigurationName},

        [Parameter(ParameterSetName = 'ComputerName', ValueFromPipelineByPropertyName = $True)]
        [string]
        ${ApplicationName},

        [Parameter(ParameterSetName = 'Session')]
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'VMId')]
        [Parameter(ParameterSetName = 'VMName')]
        [Parameter(ParameterSetName = 'ContainerId')]
        [int]
        ${ThrottleLimit},

        [Parameter(ParameterSetName = 'Uri')]
        [Alias('URI','CU')]
        [ValidateNotNullOrEmpty()]
        [uri[]]
        ${ConnectionUri},

        [Parameter(ParameterSetName = 'Session')]
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'VMId')]
        [Parameter(ParameterSetName = 'VMName')]
        [Parameter(ParameterSetName = 'ContainerId')]
        [switch]
        ${AsJob},

        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [Alias('Disconnected')]
        [switch]
        ${InDisconnectedSession},

        [Parameter(ParameterSetName = 'ComputerName')]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${SessionName},

        [Parameter(ParameterSetName = 'VMId')]
        [Parameter(ParameterSetName = 'Session')]
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'VMName')]
        [Parameter(ParameterSetName = 'ContainerId')]
        [Alias('HCN')]
        [switch]
        ${HideComputerName},

        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'Session')]
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'ContainerId')]
        [string]
        ${JobName},
        
        [Parameter(ParameterSetName='InProcess')]
        [switch]
        ${NoNewScope},

        [Parameter(ParameterSetName = 'Uri')]
        [switch]
        ${AllowRedirection},

        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'Uri')]
        [System.Management.Automation.Remoting.PSSessionOption]
        ${SessionOption},

        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'Uri')]
        [System.Management.Automation.Runspaces.AuthenticationMechanism]
        ${Authentication},

        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'Uri')]
        [switch]
        ${EnableNetworkAccess},

        [Parameter(ParameterSetName = 'ContainerId')]
        [switch]
        ${RunAsAdministrator},

        [Parameter(ValueFromPipeline = $True)]
        [psobject]
        ${InputObject},

        [Parameter(ParameterSetName = 'VMId', Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('VMGuid')]
        [ValidateNotNullOrEmpty()]
        [guid[]]
        ${VMId},

        [Parameter(ParameterSetName = 'VMName', Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${VMName},

        [Parameter(ParameterSetName = 'ContainerId', Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${ContainerId},

        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'Uri')]
        [string]
        ${CertificateThumbprint}
    )

    Begin{
        $Scriptblock = {
            Param(
                [Parameter(Position = 0)]
                [string[]]$CommandLine,

                [Parameter(Position = 1)]
                [datetime]$StartTime,

                [Parameter(Position = 2)]
                [datetime]$EndTime,

                [Parameter(Position = 3)]
                [bool]$VerboseSwitch
            )

            $CommandLineRegEx = $CommandLine -join '|'

            Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';StartTime=$StartTime;EndTime=$EndTime} |
            Foreach-Object -Process {
                $EventData = [xml]$_.ToXML()
            
                $Data = $EventData.event.EventData.Data
            
                If($Data.Where({$_.Name -eq 'CommandLine'}).'#text' -notmatch $CommandLineRegEx)
                {
                    Return
                }

                $Properties = @{}
                
                Foreach($Node in $Data.Name)
                {
                    $Properties.$Node = $Data.Where({$_.Name -eq $Node}).'#text'
                }
        
                [pscustomobject]$Properties
            }
        }

        Try 
        {
            $outBuffer = $null
        
            if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer))
            {
                $PSBoundParameters['OutBuffer'] = 1
            }
        
            $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('Microsoft.PowerShell.Core\Invoke-Command', [System.Management.Automation.CommandTypes]::Cmdlet)
            
            Foreach($Parameter in $MyInvocation.MyCommand.Parameters.Keys.Where({$_ -notin $wrappedCmd.Parameters.Keys}))
            {
                [void]$PSBoundParameters.Remove($Parameter)
            }
            
            $VerboseSwitch = $VerbosePreference -eq [System.Management.Automation.ActionPreference]::Continue
        
            $scriptCmd = {
                & $wrappedCmd @PSBoundParameters -ScriptBlock $Scriptblock -ArgumentList $CommandLine,$StartTime,$EndTime,$VerboseSwitch
            }
            
            $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
            
            $steppablePipeline.Begin($PSCmdlet)
        }
        Catch 
        {
            Throw
        }
    }

    Process{
        Try 
        {
            $steppablePipeline.Process($_)
        }
        Catch 
        {
            Throw
        }
    }

    End{
        Try 
        {
            $steppablePipeline.End()
        }
        Catch 
        {
            Throw
        }
    }
}
function Search-SysmonNetworkConnection
{
    [CmdletBinding(DefaultParameterSetName='InProcess')]
    
    Param(
        [Parameter(Mandatory = $True)]
        [string[]]$Destination,

        [Parameter(Mandatory = $False)]
        [datetime]$StartTime = (Get-Date).AddMinutes(-10),

        [Parameter(Mandatory = $False)]
        [datetime]$EndTime = (Get-Date),

        [Parameter(ParameterSetName = 'Session')]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Runspaces.PSSession[]]
        ${Session},

        [Parameter(ParameterSetName = 'ComputerName')]
        [Alias('Cn')]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${ComputerName},

        [Parameter(ParameterSetName = 'ComputerName', ValueFromPipelineByPropertyName = $True)]
        [Parameter(ParameterSetName = 'Uri', ValueFromPipelineByPropertyName = $True)]
        [Parameter(ParameterSetName = 'VMId', Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Parameter(ParameterSetName = 'VMName', Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        ${Credential},

        [Parameter(ParameterSetName = 'ComputerName')]
        [ValidateRange(1, 65535)]
        [int]
        ${Port},

        [Parameter(ParameterSetName = 'ComputerName')]
        [switch]
        ${UseSSL},

        [Parameter(ParameterSetName = 'Uri', ValueFromPipelineByPropertyName = $True)]
        [Parameter(ParameterSetName = 'ComputerName', ValueFromPipelineByPropertyName = $True)]
        [Parameter(ParameterSetName = 'ContainerId', ValueFromPipelineByPropertyName = $True)]
        [Parameter(ParameterSetName = 'VMId', ValueFromPipelineByPropertyName = $True)]
        [Parameter(ParameterSetName = 'VMName', ValueFromPipelineByPropertyName = $True)]
        [string]
        ${ConfigurationName},

        [Parameter(ParameterSetName = 'ComputerName', ValueFromPipelineByPropertyName = $True)]
        [string]
        ${ApplicationName},

        [Parameter(ParameterSetName = 'Session')]
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'VMId')]
        [Parameter(ParameterSetName = 'VMName')]
        [Parameter(ParameterSetName = 'ContainerId')]
        [int]
        ${ThrottleLimit},

        [Parameter(ParameterSetName = 'Uri')]
        [Alias('URI','CU')]
        [ValidateNotNullOrEmpty()]
        [uri[]]
        ${ConnectionUri},

        [Parameter(ParameterSetName = 'Session')]
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'VMId')]
        [Parameter(ParameterSetName = 'VMName')]
        [Parameter(ParameterSetName = 'ContainerId')]
        [switch]
        ${AsJob},

        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [Alias('Disconnected')]
        [switch]
        ${InDisconnectedSession},

        [Parameter(ParameterSetName = 'ComputerName')]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${SessionName},

        [Parameter(ParameterSetName = 'VMId')]
        [Parameter(ParameterSetName = 'Session')]
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'VMName')]
        [Parameter(ParameterSetName = 'ContainerId')]
        [Alias('HCN')]
        [switch]
        ${HideComputerName},

        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'Session')]
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'ContainerId')]
        [string]
        ${JobName},
        
        [Parameter(ParameterSetName='InProcess')]
        [switch]
        ${NoNewScope},

        [Parameter(ParameterSetName = 'Uri')]
        [switch]
        ${AllowRedirection},

        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'Uri')]
        [System.Management.Automation.Remoting.PSSessionOption]
        ${SessionOption},

        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'Uri')]
        [System.Management.Automation.Runspaces.AuthenticationMechanism]
        ${Authentication},

        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'Uri')]
        [switch]
        ${EnableNetworkAccess},

        [Parameter(ParameterSetName = 'ContainerId')]
        [switch]
        ${RunAsAdministrator},

        [Parameter(ValueFromPipeline = $True)]
        [psobject]
        ${InputObject},

        [Parameter(ParameterSetName = 'VMId', Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('VMGuid')]
        [ValidateNotNullOrEmpty()]
        [guid[]]
        ${VMId},

        [Parameter(ParameterSetName = 'VMName', Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${VMName},

        [Parameter(ParameterSetName = 'ContainerId', Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${ContainerId},

        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'Uri')]
        [string]
        ${CertificateThumbprint}
    )

    Begin{
        $Scriptblock = {
            Param(
                [Parameter(Position = 0)]
                [string[]]$Destination,

                [Parameter(Position = 1)]
                [datetime]$StartTime,

                [Parameter(Position = 2)]
                [datetime]$EndTime,

                [Parameter(Position = 3)]
                [bool]$VerboseSwitch
            )

            $DestinationRegEx = $Destination -join '|'

            Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';StartTime=$StartTime;EndTime=$EndTime} |
            Foreach-Object -Process {
                $EventData = [xml]$_.ToXML()
            
                $Data = $EventData.event.EventData.Data
            
                If($Data.Where({$_.Name -eq 'DestinationHostname'}).'#text' -notmatch $DestinationRegEx -and $Data.Where({$_.Name -eq 'DestinationIp'}).'#text' -notmatch $DestinationRegEx)
                {
                    Return
                }

                $Properties = @{}
                
                Foreach($Node in $Data.Name)
                {
                    $Properties.$Node = $Data.Where({$_.Name -eq $Node}).'#text'
                }
        
                [pscustomobject]$Properties
            }
        }

        Try 
        {
            $outBuffer = $null
        
            if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer))
            {
                $PSBoundParameters['OutBuffer'] = 1
            }
        
            $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('Microsoft.PowerShell.Core\Invoke-Command', [System.Management.Automation.CommandTypes]::Cmdlet)
            
            Foreach($Parameter in $MyInvocation.MyCommand.Parameters.Keys.Where({$_ -notin $wrappedCmd.Parameters.Keys}))
            {
                [void]$PSBoundParameters.Remove($Parameter)
            }
            
            $VerboseSwitch = $VerbosePreference -eq [System.Management.Automation.ActionPreference]::Continue
        
            $scriptCmd = {
                & $wrappedCmd @PSBoundParameters -ScriptBlock $Scriptblock -ArgumentList $Destination,$StartTime,$EndTime,$VerboseSwitch
            }
            
            $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
            
            $steppablePipeline.Begin($PSCmdlet)
        }
        Catch 
        {
            Throw
        }
    }

    Process{
        Try 
        {
            $steppablePipeline.Process($_)
        }
        Catch 
        {
            Throw
        }
    }

    End{
        Try 
        {
            $steppablePipeline.End()
        }
        Catch 
        {
            Throw
        }
    }
}

function Search-SysmonFileCreation
{
    [CmdletBinding(DefaultParameterSetName='InProcess')]
    
    Param(
        [Parameter(Mandatory = $True)]
        [string[]]$FileHash,

        [Parameter(Mandatory = $False)]
        [datetime]$StartTime = (Get-Date).AddMinutes(-10),

        [Parameter(Mandatory = $False)]
        [datetime]$EndTime = (Get-Date),

        [Parameter(ParameterSetName = 'Session')]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Runspaces.PSSession[]]
        ${Session},

        [Parameter(ParameterSetName = 'ComputerName')]
        [Alias('Cn')]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${ComputerName},

        [Parameter(ParameterSetName = 'ComputerName', ValueFromPipelineByPropertyName = $True)]
        [Parameter(ParameterSetName = 'Uri', ValueFromPipelineByPropertyName = $True)]
        [Parameter(ParameterSetName = 'VMId', Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Parameter(ParameterSetName = 'VMName', Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [pscredential]
        [System.Management.Automation.CredentialAttribute()]
        ${Credential},

        [Parameter(ParameterSetName = 'ComputerName')]
        [ValidateRange(1, 65535)]
        [int]
        ${Port},

        [Parameter(ParameterSetName = 'ComputerName')]
        [switch]
        ${UseSSL},

        [Parameter(ParameterSetName = 'Uri', ValueFromPipelineByPropertyName = $True)]
        [Parameter(ParameterSetName = 'ComputerName', ValueFromPipelineByPropertyName = $True)]
        [Parameter(ParameterSetName = 'ContainerId', ValueFromPipelineByPropertyName = $True)]
        [Parameter(ParameterSetName = 'VMId', ValueFromPipelineByPropertyName = $True)]
        [Parameter(ParameterSetName = 'VMName', ValueFromPipelineByPropertyName = $True)]
        [string]
        ${ConfigurationName},

        [Parameter(ParameterSetName = 'ComputerName', ValueFromPipelineByPropertyName = $True)]
        [string]
        ${ApplicationName},

        [Parameter(ParameterSetName = 'Session')]
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'VMId')]
        [Parameter(ParameterSetName = 'VMName')]
        [Parameter(ParameterSetName = 'ContainerId')]
        [int]
        ${ThrottleLimit},

        [Parameter(ParameterSetName = 'Uri')]
        [Alias('URI','CU')]
        [ValidateNotNullOrEmpty()]
        [uri[]]
        ${ConnectionUri},

        [Parameter(ParameterSetName = 'Session')]
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'VMId')]
        [Parameter(ParameterSetName = 'VMName')]
        [Parameter(ParameterSetName = 'ContainerId')]
        [switch]
        ${AsJob},

        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [Alias('Disconnected')]
        [switch]
        ${InDisconnectedSession},

        [Parameter(ParameterSetName = 'ComputerName')]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${SessionName},

        [Parameter(ParameterSetName = 'VMId')]
        [Parameter(ParameterSetName = 'Session')]
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'VMName')]
        [Parameter(ParameterSetName = 'ContainerId')]
        [Alias('HCN')]
        [switch]
        ${HideComputerName},

        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'Session')]
        [Parameter(ParameterSetName = 'Uri')]
        [Parameter(ParameterSetName = 'ContainerId')]
        [string]
        ${JobName},
        
        [Parameter(ParameterSetName='InProcess')]
        [switch]
        ${NoNewScope},

        [Parameter(ParameterSetName = 'Uri')]
        [switch]
        ${AllowRedirection},

        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'Uri')]
        [System.Management.Automation.Remoting.PSSessionOption]
        ${SessionOption},

        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'Uri')]
        [System.Management.Automation.Runspaces.AuthenticationMechanism]
        ${Authentication},

        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'Uri')]
        [switch]
        ${EnableNetworkAccess},

        [Parameter(ParameterSetName = 'ContainerId')]
        [switch]
        ${RunAsAdministrator},

        [Parameter(ValueFromPipeline = $True)]
        [psobject]
        ${InputObject},

        [Parameter(ParameterSetName = 'VMId', Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('VMGuid')]
        [ValidateNotNullOrEmpty()]
        [guid[]]
        ${VMId},

        [Parameter(ParameterSetName = 'VMName', Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${VMName},

        [Parameter(ParameterSetName = 'ContainerId', Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        ${ContainerId},

        [Parameter(ParameterSetName = 'ComputerName')]
        [Parameter(ParameterSetName = 'Uri')]
        [string]
        ${CertificateThumbprint}
    )

    Begin{
        $Scriptblock = {
            Param(
                [Parameter(Position = 0)]
                [string[]]$FileHash,

                [Parameter(Position = 1)]
                [datetime]$StartTime,

                [Parameter(Position = 2)]
                [datetime]$EndTime,

                [Parameter(Position = 3)]
                [bool]$VerboseSwitch
            )

            $FileHashRegEx = $FileHash -join '|'

            Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';StartTime=$StartTime;EndTime=$EndTime;ID=15} |
            Foreach-Object -Process {
                $EventData = [xml]$_.ToXML()
            
                $Data = $EventData.event.EventData.Data
            
                If($Data.Where({$_.Name -eq 'Hash'}).'#text' -notmatch $FileHashRegEx)
                {
                    Return
                }

                $Properties = @{}
                
                Foreach($Node in $Data.Name)
                {
                    $Properties.$Node = $Data.Where({$_.Name -eq $Node}).'#text'
                }
        
                [pscustomobject]$Properties
            }
        }

        Try 
        {
            $outBuffer = $null
        
            if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer))
            {
                $PSBoundParameters['OutBuffer'] = 1
            }
        
            $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('Microsoft.PowerShell.Core\Invoke-Command', [System.Management.Automation.CommandTypes]::Cmdlet)
            
            Foreach($Parameter in $MyInvocation.MyCommand.Parameters.Keys.Where({$_ -notin $wrappedCmd.Parameters.Keys}))
            {
                [void]$PSBoundParameters.Remove($Parameter)
            }
            
            $VerboseSwitch = $VerbosePreference -eq [System.Management.Automation.ActionPreference]::Continue
        
            $scriptCmd = {
                & $wrappedCmd @PSBoundParameters -ScriptBlock $Scriptblock -ArgumentList $FileHash,$StartTime,$EndTime,$VerboseSwitch
            }
            
            $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
            
            $steppablePipeline.Begin($PSCmdlet)
        }
        Catch 
        {
            Throw
        }
    }

    Process{
        Try 
        {
            $steppablePipeline.Process($_)
        }
        Catch 
        {
            Throw
        }
    }

    End{
        Try 
        {
            $steppablePipeline.End()
        }
        Catch 
        {
            Throw
        }
    }
}
