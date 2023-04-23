using namespace System.Management.Automation

function Search-Sysmon
{
    [CmdletBinding(DefaultParameterSetName='InProcess')]
    
    Param(
        [Parameter(Mandatory = $False)]
        [switch]$CreateRemoteThread,

        [Parameter(Mandatory = $False)]
        [switch]$DriverLoad,

        [Parameter(Mandatory = $False)]
        [switch]$FileCreate,

        [Parameter(Mandatory = $False)]
        [switch]$FileCreateStreamHash,

        [Parameter(Mandatory = $False)]
        [switch]$FileCreateTime,

        [Parameter(Mandatory = $False)]
        [switch]$ImageLoad,

        [Parameter(Mandatory = $False)]
        [switch]$NetworkConnect,

        [Parameter(Mandatory = $False)]
        [switch]$PipeEvent,

        [Parameter(Mandatory = $False)]
        [switch]$ProcessAccess,

        [Parameter(Mandatory = $False)]
        [switch]$ProcessCreate,

        [Parameter(Mandatory = $False)]
        [switch]$ProcessTerminate,

        [Parameter(Mandatory = $False)]
        [switch]$RawAccessRead,

        [Parameter(Mandatory = $False)]
        [switch]$RegistryEvent,

        [Parameter(Mandatory = $False)]
        [switch]$SysmonStateChange,

        [Parameter(Mandatory = $False)]
        [switch]$WMIEvent,

        [Parameter(Mandatory = $False)]
        [switch]$AllEventTypes,

        [Parameter(Mandatory = $False)]
        [string]$Property,

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

    DynamicParam{
        function New-DynamicParameter
        {
            [CmdletBinding(SupportsShouldProcess = $True,ConfirmImpact = 'Low')]
            
            Param ( 
                [Parameter(Mandatory = $True)]
                [string]$Name,
                
                [Parameter(Mandatory = $False)]
                [string[]]$ValidateSetOptions,
                
                [Parameter(Mandatory = $False)]
                [System.Type]$TypeConstraint = [string],
                
                [Parameter(Mandatory = $False)]
                [switch]$Mandatory,
                
                [Parameter(Mandatory = $False)]
                [string]$ParameterSetName = $null,
                
                [Parameter(Mandatory = $False)]
                [switch]$ValueFromPipeline,
                
                [Parameter(Mandatory = $False)]
                [switch]$ValueFromPipelineByPropertyName,
                
                [Parameter(Mandatory = $False)]
                [RuntimeDefinedParameterDictionary]$ParameterDictionary = $null
            )
            
            Begin{}
            
            Process{
                If($PSCmdlet.ShouldProcess((Get-PSCallStack).FunctionName, 'Create Dynamic Parameter')){
                    $AttributeCollection = [System.Collections.ObjectModel.Collection[System.Attribute]]::new()
                
                    $ParamAttribute = [ParameterAttribute]::new()
                
                    $ParamAttribute.Mandatory = $Mandatory
                
                    If($null -ne $ParameterSetName)
                    {
                        $ParamAttribute.ParameterSetName = $ParameterSetName
                    }
                
                    $ParamAttribute.ValueFromPipeline = $ValueFromPipeline
                
                    $ParamAttribute.ValueFromPipelineByPropertyName = $ValueFromPipelineByPropertyName
                
                    $AttributeCollection.Add($ParamAttribute)
                
                    If($null -ne $ValidateSetOptions)
                    {
                        $ParameterOptions = [ValidateSetAttribute]::new($ValidateSetOptions)
                        $AttributeCollection.Add($ParameterOptions)
                    }
                
                    $RuntimeParameter = [RuntimeDefinedParameter]::new($Name, $TypeConstraint, $AttributeCollection)
                
                    If($null -ne $ParameterDictionary)
                    {
                        $ParameterDictionary.Add($Name,$RuntimeParameter)
                    }
                    Else
                    {
                        $ParameterDictionary = [RuntimeDefinedParameterDictionary]::new()
                        $ParameterDictionary.Add($Name,$RuntimeParameter)
                    }
                
                    $ParameterDictionary
                }
            }
            
            End{}
        }

        If($PSBoundParameters.ContainsKey('Property')){
            $ValidateSetOptions = @('eq','ne','gt','ge','lt','le','like','notlike','match','notmatch','contains','notcontains','in','notin')

            $ParamDictionary = New-DynamicParameter -Name ComparisonOperator -Mandatory -ValidateSetOptions $ValidateSetOptions

            New-DynamicParameter -Name Value -Mandatory -ParameterDictionary $ParamDictionary
        }
    }

    Begin{
        $EventIDs = [System.Collections.ArrayList]::New()
        
        If($CreateRemoteThread -or $AllEventTypes){[void]$EventIDs.Add(8)}
        If($DriverLoad -or $AllEventTypes){[void]$EventIDs.Add(6)}
        If($FileCreate -or $AllEventTypes){[void]$EventIDs.Add(11)}
        If($FileCreateStreamHash -or $AllEventTypes){[void]$EventIDs.Add(15)}
        If($FileCreateTime -or $AllEventTypes){[void]$EventIDs.Add(2)}
        If($ImageLoad -or $AllEventTypes){[void]$EventIDs.Add(7)}
        If($NetworkConnect -or $AllEventTypes){[void]$EventIDs.Add(3)}
        If($PipeEvent -or $AllEventTypes){17,18 | Foreach-Object -Process {[void]$EventIDs.Add($_)}}
        If($ProcessAccess -or $AllEventTypes){[void]$EventIDs.Add(10)}
        If($ProcessCreate -or $AllEventTypes){[void]$EventIDs.Add(1)}
        If($ProcessTerminate -or $AllEventTypes){[void]$EventIDs.Add(5)}
        If($RawAccessRead -or $AllEventTypes){[void]$EventIDs.Add(9)}
        If($RegistryEvent -or $AllEventTypes){12,13,14 | Foreach-Object -Process {[void]$EventIDs.Add($_)}}
        If($SysmonStateChange -or $AllEventTypes){[void]$EventIDs.Add(4)}
        If($WMIEvent -or $AllEventTypes){19,20,21 | Foreach-Object -Process {[void]$EventIDs.Add($_)}}

        If($PSBoundParameters.Property){
            $script:ComparisonOperator = $PSBoundParameters.ComparisonOperator
            $script:Value = [System.Management.Automation.Language.CodeGeneration]::EscapeSingleQuotedStringContent($PSBoundParameters.Value)
        }

        $script:Property = [System.Management.Automation.Language.CodeGeneration]::EscapeSingleQuotedStringContent($PSBoundParameters.Property)


        $Scriptblock = {
            Param(
                [Parameter(Position = 0)]
                [int[]]$EventIDs,

                [Parameter(Position = 1)]
                [string]$Property,

                [Parameter(Position = 2)]
                [string]$ComparisonOperator,

                [Parameter(Position = 3)]
                [string]$Value,

                [Parameter(Position = 4)]
                [datetime]$StartTime,

                [Parameter(Position = 5)]
                [datetime]$EndTime,

                [Parameter(Position = 6)]
                [bool]$VerboseSwitch
            )

            $EventIDLookup = @{
                1 = 'ProcessCreation'
                2 = 'FileCreationTime'
                3 = 'NetworkConnection'
                4 = 'SysmonStateChange'
                5 = 'ProcessTermination'
                6 = 'DriverLoaded'
                7 = 'ImageLoaded'
                8 = 'CreateRemoteThread'
                9 = 'RawAccessRead'
                10 = 'ProcessAccess'
                11 = 'FileCreate'
                12 = 'RegistryObjectCreatedDeleted'
                13 = 'RegistryValueSet'
                14 = 'RegistryKeyValueRenamed'
                15 = 'FileCreateStreamHash'
                17 = 'PipeCreated'
                18 = 'PipeConnected'
                19 = 'WmiEventFilter'
                20 = 'WmiEventConsumer'
                21 = 'WmiEventConsumerToFilter'
            }

            $HashtableParams = @{
                LogName='Microsoft-Windows-Sysmon/Operational'
                StartTime=$StartTime
                EndTime=$EndTime 
            }

            If($EventIDs){$HashtableParams.ID = $EventIDs}

            If($Property)
            {
                $IfFilter = [scriptblock]::Create("`$Data.Where({`$_.Name -eq '$Property'}).'#text' -$ComparisonOperator '$Value'")
            }
            Else{
                $IfFilter = [scriptblock]::Create("`$true")
            }

            Get-WinEvent -FilterHashtable $HashtableParams -ErrorAction SilentlyContinue |
            Foreach-Object -Process {
                $EventData = [xml]$_.ToXML()
            
                $Data = $EventData.event.EventData.Data
            
                If($IfFilter.Invoke())
                {
                    $Properties = @{}
                
                    Foreach($Node in $Data.Name)
                    {
                        If($Node -eq 'UtcTime')
                        {
                            $Properties.$Node = [datetime]::SpecifyKind($Data.Where({$_.Name -eq $Node}).'#text',[System.DateTimeKind]::Utc)
                            $Properties.LocalTime = [datetime]::SpecifyKind($Data.Where({$_.Name -eq $Node}).'#text',[System.DateTimeKind]::Utc).ToLocalTime()
                        }
                        Else
                        {
                            $Properties.$Node = $Data.Where({$_.Name -eq $Node}).'#text'
                        }
                    }

                    $Properties.PSTypeName = "ARTools.Sysmon.{0}" -f $EventIDLookup[[int]$EventData.Event.System.EventID]
            
                    [pscustomobject]$Properties
                }
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
                & $wrappedCmd @PSBoundParameters -ScriptBlock $Scriptblock -ArgumentList $EventIDs,$script:Property,
                    $script:ComparisonOperator,$script:Value,$StartTime,$EndTime,$VerboseSwitch
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
