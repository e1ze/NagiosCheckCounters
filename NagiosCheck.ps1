$DefaultsStruct = New-object PSObject -Property @{
    ComputerName = ([System.Net.Dns]::GetHostByName((hostname.exe)).HostName).tolower();
    Modes = ("cpu", "mem", "disk", "net", "sys");
    Filters = @();
    ExitCode = 3;
    WarningCount = 0;
    CriticalCount = 0;
#            ProcessorTime: limit over (%)
#            MemoryAvailable: limit under (B)
#            PagefileUsage: limit over (%)
#            DiskfreeSpace:
#            DiskfreePercentage:
#            InterfaceUsage:
#    AvgDiskReadQueueWarn = $DefaultInt;
#    AvgDiskReadQueueCrit = $DefaultInt;
#    AvgDiskWriteQueueWarn = $DefaultInt;
#    AvgDiskWriteQueueCrit = $DefaultInt;
#:warning    LimitMessages = @();
}

$Counters = @(

    '\Processor(*)\% Processor Time'
    '\Processor(*)\% User Time'
    '\Processor(*)\% Idle Time'
    '\Processor(*)\% Interrupt Time'
    '\Processor(*)\% Privileged Time'
    '\Processor(*)\Interrupts/sec'

    '\Memory\Available Bytes'
    '\Memory\Committed Bytes'
    '\Memory\System Code Total Bytes'
    '\Memory\Pool Nonpaged Bytes'
    '\Memory\Cache Bytes'
    '\Memory\Commit Limit'
    '\Memory\% Committed Bytes In Use'
    '\Memory\Pages/sec'
    '\Memory\Page Faults/sec'
    '\Memory\Page Reads/sec'
    '\Memory\Page Writes/sec'
    '\Paging File(*)\% Usage'

    '\LogicalDisk(*)\% Free Space'
    '\LogicalDisk(*)\Free Megabytes'
    '\PhysicalDisk(*)\Disk Transfers/sec'
    '\PhysicalDisk(*)\Disk Reads/sec'
    '\PhysicalDisk(*)\Disk Writes/sec'
    '\PhysicalDisk(*)\Disk Bytes/sec'
    '\PhysicalDisk(*)\Avg. Disk Bytes/Read'
    '\PhysicalDisk(*)\Disk Write Bytes/sec'
    '\PhysicalDisk(*)\Avg. Disk Bytes/Write'

    '\Network Interface(*)\Current Bandwidth'
    '\Network Interface(*)\Bytes Total/sec'
    '\Network Interface(*)\Bytes Received/sec'
    '\Network Interface(*)\Bytes Sent/sec'
    '\Network Interface(*)\Packets/sec'
    '\Network Interface(*)\Packets Received Unicast/sec'
    '\Network Interface(*)\Packets Received Non-Unicast/sec'
    '\Network Interface(*)\Packets Received Discarded'
    '\Network Interface(*)\Packets Received Errors'
    '\Network Interface(*)\Packets Received Unknown'
    '\Network Interface(*)\Packets Sent Unicast/sec'
    '\Network Interface(*)\Packets Sent Non-Unicast/sec'
    '\Network Interface(*)\Packets Outbound Discarded'
    '\Network Interface(*)\Packets Outbound Errors'

    '\System\Processes'
    '\System\Processor Queue Length'
    '\System\Threads'
    '\System\System Calls/sec'
    '\System\File Write Operations/sec'
    '\System\File Read Operations/sec'

)

Function Initialize-Args {
    Param (
        [Parameter(Mandatory=$True)]$Args
    )

    try {
        For ( $i = 0; $i -lt $Args.count; $i++ ) {
		    $CurrentArg = $Args[$i].ToString()
            if ($i -lt $Args.Count-1) {
				$Value = $Args[$i+1];
				If ($Value.Count -ge 2) {
					foreach ($Item in $Value) {
						Test-Strings $Item | Out-Null
					}
				}
				else {
	                $Value = $Args[$i+1];
					Test-Strings $Value | Out-Null
				}
            } else {
                $Value = ''
            };

            switch -regex -casesensitive ($CurrentArg) {
                "^(-m|--Modes)$" {
                    if ($value -match "^[a-zA-Z,]+$") {
                        $script:DefaultsStruct.Modes = $value -split ','
                    } else {
                        throw "Modes does not meet regex requirements (`"^[a-zA-Z,]+$`"). Value given is `"$value`"."
                    }
                    $i++
                }

                "^(-f|--Filters)$" {
                    # TODO validate input string ?
                    $script:DefaultsStruct.Filters = $value -split ','
                    $i++
                }

                "^(--CpuWarn)$" {
                    if (($value -match "^[\d]+$") -and ([int]$value -lt 999999)) {
                        $DefaultsStruct.LimitCpu = 1
                        $DefaultsStruct.LimitCpuWarn = $value
                    } else {
                        throw "Cpu warning does not meet regex requirements (`"^[\d]+$`"). Value given is `"$value`"."
                    }
                    $i++
                 }

                "^(--CpuCrit)$" {
                    if (($value -match "^[\d]+$") -and ([int]$value -lt 999999)) {
                        $DefaultsStruct.LimitCpu = 1
                        $DefaultsStruct.LimitCpuCrit = $value
                    } else {
                        throw "Cpu critical does not meet regex requirements (`"^[\d]+$`"). Value given is `"$value`"."
                    }
                    $i++
                 }

                "^(-h|--Help)$" {
                    Write-Help
                }

                default {

                    throw "Illegal arguments detected: $_"
                 
                 }
            }
        }
    }
    catch {

		Write-Host "Error: $_"
        Exit 3

	}

}

Function Test-Strings {

    Param ( [Parameter(Mandatory=$True)][string]$String )

    $BadChars=@("``", '|', ';', "`n")
    $BadChars | ForEach-Object {
        If ( $String.Contains("$_") ) {
            Write-Host "Error: String `"$String`" contains illegal characters."
            Exit $DefaultsStruct.ExitCode
        }
    }

    Return $true

}

Function Write-Help {

	Write-Host @"
NagiosCheckCounters.ps1:
This script is designed to monitor Microsoft Windows check counters.
Arguments:
    -m 	 | --Modes           Optional comma separated list of query modes. Default cpu,mem,disk,net,sys.
    -f   | --Filter          Optional comma separated list of exclusion filters (substrings),
                             applicable to LogicalDiskNames, PhysDiskNames and InterfaceNames.
                             For example: "C:","X:"
    -h   | --Help 			 Print this help.
"@

    Exit 0;

}

Function Process-Filter {

    Param ( [Parameter(Mandatory=$True)][string]$String )

    $Ignore = $true
    $DefaultsStruct.Filters | ForEach-Object {
        If ( $String.Contains("$_") ) {
            $Ignore = $false
        }
    }

    Return $Ignore

}

Function New-NagiosResult {

    <#
    .SYNOPSIS
        Creates Nagios results.
    .DESCRIPTION
        Takes specified values and creates the perfdata strings for each Label.
    .PARAMETER Label
        Name of the Label of the perfdata metric. This parameter is required and must be unique for the sensor.
    .PARAMETER Value
        The value as integer or float.
    .PARAMETER Unit
        The unit of the value. Maybe empty for count values.
    #>

    [CmdletBinding()]
    Param
    (

        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]$Label,
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        $Value,
        [String]$Unit = ""
    )

    Process {

        $Results += "'$Label'=$Value$Unit"

    }
    End {

        #$Results += ""
        $Results

    }

}

Function Publish-NagiosResults {

    <#
    .SYNOPSIS
        Writes Nagios results.
    .DESCRIPTION
        Takes specified results and creates the Nagios compatible output.
    .PARAMETER Publish
        Collection of NagiosResults.
    .PARAMETER Text
        (Optional) Text to include in output.
    .PARAMETER Warning
        Counter of WARNING states.
    .PARAMETER Critical
        Counter of CRITICAL states.
    #>

    [CmdletBinding()]
    Param
    (

        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]$Publish,
        [String]$Text = "Queried " + [string]$script:DefaultsStruct.ComputerName + " using modes [" + [string]$script:DefaultsStruct.Modes + "]",
        [Int]$Warning = 0,
        [Int]$Critical = 0

    )

    Begin {

        If ($script:DefaultsStruct.CriticalCount > 0){
            $PublishedResult = "CRITCAL: "
            $script:DefaultsStruct.ExitCode = 2
        }
        ElseIf ($script:DefaultsStruct.WarningCount > 0){
            $PublishedResult = "WARNING: "
            $script:DefaultsStruct.ExitCode = 1
        }
        Else {
            $PublishedResult = "OK: "
            $script:DefaultsStruct.ExitCode = 0
        }

        # TODO get messages for limits
        $PublishedResult += "$Text |`r`n"

    }

    Process {

        $PublishedResult += $Publish

    }
    End {

        #$PublishedResult += "..."
        $PublishedResult

    }
}

Function GetProcessorCounters {

    <#

    #>

    [CmdletBinding()]
    Param(

        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        $RawValues

    )

    Begin {

        $PublishedResults = @()

    }
    Process {

        $PublishedResults += ($RawValues).Where{ ($_.Path -like "*Processor(*)\*") } | Group-Object InstanceName | ForEach-Object {

            $Cpu = $_.Group
            $CpuName = (Get-Culture).TextInfo.ToTitleCase($_.Name)

            #Per CPU % Processor Time
            $CpuValue = $Cpu.Where{ ($_.Path -like "*\% processor time*") }.CookedValue
            # TODO limit if ($CpuName -eq "_total") {
            New-NagiosResult -Label "Processor($CpuName) % Processor Time" -Value $CpuValue -Unit "%"

            #Per CPU % User Time
            $CpuValue = $Cpu.Where{ ($_.Path -like "*\% user time*") }.CookedValue
            New-NagiosResult -Label "Processor($CpuName) % User Time" -Value $CpuValue -Unit "%"

            #Per CPU % Idle Time
            $CpuValue = $Cpu.Where{ ($_.Path -like "*\% idle time*") }.CookedValue
            New-NagiosResult -Label "Processor($CpuName) % Idle Time" -Value $CpuValue -Unit "%"

            #Per CPU % Interrupt Time
            $CpuValue = $Cpu.Where{ ($_.Path -like "*\% interrupt time*") }.CookedValue
            New-NagiosResult -Label "Processor($CpuName) % Interrupt Time" -Value $CpuValue -Unit "%"

            #Per CPU % Privileged Time
            $CpuValue = $Cpu.Where{ ($_.Path -like "*\% privileged time*") }.CookedValue
            New-NagiosResult -Label "Processor($CpuName) % Privileged Time" -Value $CpuValue -Unit "%"

            #Per CPU Interrupts/sec
            $CpuValue = $Cpu.Where{ ($_.Path -like "*\interrupts/sec*") }.CookedValue
            New-NagiosResult -Label "Processor($CpuName) Interrupts/sec" -Value $CpuValue

        }

    }
    End {

        $PublishedResults

    }
}

Function GetMemoryCounters {

    <#

    #>

    [CmdletBinding()]
    Param(

        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        $RawValues

    )

    Begin {

        $PublishedResults = @()

    }
    Process {

        #Memory Available Bytes
        $MemValue = ($RawValues).Where{ ($_.Path -like "*Memory\Available Bytes*") }.CookedValue
        # TODO limits
        $PublishedResults += New-NagiosResult -Label "Memory Available Bytes" -Value $MemValue -Unit "B"

        #Memory Committed Bytes
        $MemValue = ($RawValues).Where{ ($_.Path -like "*Memory\Committed Bytes*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "Memory Committed Bytes" -Value $MemValue -Unit "B"

        #Memory System Code Total Bytes
        $MemValue = ($RawValues).Where{ ($_.Path -like "*Memory\System Code Total Bytes*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "Memory System Code Total Bytes" -Value $MemValue -Unit "B"

        #Memory Pool Nonpaged Bytes
        $MemValue = ($RawValues).Where{ ($_.Path -like "*Memory\Pool Nonpaged Bytes*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "Memory Pool Nonpaged Bytes" -Value $MemValue -Unit "B"

        #Memory Cache Bytes
        $MemValue = ($RawValues).Where{ ($_.Path -like "*Memory\Cache Bytes*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "Memory Cache Bytes" -Value $MemValue -Unit "B"

        #Memory Commit Limit
        $MemValue = ($RawValues).Where{ ($_.Path -like "*Memory\Commit Limit*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "Memory Commit Limit" -Value $MemValue -Unit "B"

        #Memory % Committed Bytes In Use
        $MemValue = ($RawValues).Where{ ($_.Path -like "*Memory\% Committed Bytes In Use*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "Memory % Committed Bytes In Use" -Value $MemValue -Unit "B"

        #Memory Pages/sec
        $MemValue = ($RawValues).Where{ ($_.Path -like "*Memory\Pages/sec*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "Memory Pages/sec" -Value $MemValue

        #Memory Page Faults/sec
        $MemValue = ($RawValues).Where{ ($_.Path -like "*Memory\Page Faults/sec*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "Memory Page Faults/sec" -Value $MemValue

        #Memory Page Reads/sec
        $MemValue = ($RawValues).Where{ ($_.Path -like "*Memory\Page Reads/sec*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "Memory Page Reads/sec" -Value $MemValue

        #Memory Page Writes/sec
        $MemValue = ($RawValues).Where{ ($_.Path -like "*Memory\Page Writes/sec*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "Memory Page Writes/sec" -Value $MemValue

        #Total Paging File usage
        $TotalPageFileUsage = ($RawValues).Where{ ($_.Path -like "*Paging File(*)\% Usage*") -and ($_.InstanceName -eq "_total") }.CookedValue
        # TODO limits
        $PublishedResults += New-NagiosResult -Label "Total Page File usage" -Value $TotalPageFileUsage -Unit "%"

    }
    End {

        $PublishedResults

    }
}

Function GetDiskCounters {

    <#

    #>

    [CmdletBinding()]
    Param(

        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        $RawValues

    )

    Begin {

        $PublishedResults = @()

    }
    Process {

        #LogicalDisk usage
        $PublishedResults += ($RawValues).Where{ ($_.Path -like "*logicaldisk(*)\*") -and ($_.InstanceName -like "*:*") } | Group-Object InstanceName | ForEach-Object {

            $Disk = $_.Group
            $DiskName = (Get-Culture).TextInfo.ToTitleCase($_.Name)

            if (Process-Filter $DiskName) {
                $DiskSpacePercentage = $Disk.Where{ ($_.Path -like "*% Free Space*") }.CookedValue
                $DiskSpaceUsage = ($Disk.Where{ ($_.Path -like "*Free Megabytes*") }).CookedValue

                # TODO limits
                New-NagiosResult -Label "Drive $DiskName Free Percentage" -Value $DiskSpacePercentage -Unit "%"
                # TODO limits
                New-NagiosResult -Label "Drive $DiskName Free Space" -Value ($DiskSpaceUsage * 1024 * 1024 ) -Unit "B"
            }

        }

        #PhysicalDisk counters
        $PublishedResults += ($RawValues).Where{ ($_.Path -like "*physicaldisk(*)\*") } | Group-Object InstanceName | ForEach-Object {

            $PhysDisk = $_.Group
            $PhysDiskName = (Get-Culture).TextInfo.ToTitleCase($_.Name)

            if (Process-Filter $PhysDiskName) {
                #Per PhysicalDisk Disk Transfers/sec
                $PhysDiskValue = $PhysDisk.Where{ ($_.Path -like "*Disk Transfers/sec*") }.CookedValue
                New-NagiosResult -Label "PhysicalDisk($PhysDiskName) Disk Transfers/sec" -Value $PhysDiskValue

                #Per PhysicalDisk Disk Reads/sec
                $PhysDiskValue = $PhysDisk.Where{ ($_.Path -like "*Disk Reads/sec*") }.CookedValue
                New-NagiosResult -Label "PhysicalDisk($PhysDiskName) Disk Reads/sec" -Value $PhysDiskValue

                #Per PhysicalDisk Disk Writes/sec
                $PhysDiskValue = $PhysDisk.Where{ ($_.Path -like "*Disk Writes/sec*") }.CookedValue
                New-NagiosResult -Label "PhysicalDisk($PhysDiskName) Disk Writes/sec" -Value $PhysDiskValue

                #Per PhysicalDisk Disk Bytes/sec
                $PhysDiskValue = $PhysDisk.Where{ ($_.Path -like "*Disk Bytes/sec*") }.CookedValue
                New-NagiosResult -Label "PhysicalDisk($PhysDiskName) Disk Bytes/sec" -Value $PhysDiskValue -Unit "B"

                #Per PhysicalDisk Disk Write Bytes/sec
                $PhysDiskValue = $PhysDisk.Where{ ($_.Path -like "*Disk Write Bytes/sec*") }.CookedValue
                New-NagiosResult -Label "PhysicalDisk($PhysDiskName) Disk Write Bytes/sec" -Value $PhysDiskValue -Unit "B"

                #Per PhysicalDisk Avg. Disk Bytes/Read
                $PhysDiskValue = $PhysDisk.Where{ ($_.Path -like "*Avg. Disk Bytes/Read*") }.CookedValue
                New-NagiosResult -Label "PhysicalDisk($PhysDiskName) Avg. Disk Bytes/Read" -Value $PhysDiskValue -Unit "B"

                #Per PhysicalDisk Avg. Disk Bytes/Write
                $PhysDiskValue = $PhysDisk.Where{ ($_.Path -like "*Avg. Disk Bytes/Write*") }.CookedValue
                New-NagiosResult -Label "PhysicalDisk($PhysDiskName) Avg. Disk Bytes/Write" -Value $PhysDiskValue -Unit "B"
            }

        }

    }
    End {

        $PublishedResults

    }
}

Function GetNetworkCounters {

    <#

    #>

    [CmdletBinding()]
    Param(

        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        $RawValues

    )

    Begin {

        $PublishedResults = @()

    }
    Process {

        #Network Usage
        $PublishedResults += ($RawValues).Where{ ($_.Path -like "*Network Interface*") -and ($_.InstanceName -notlike "*isatap*") -and ($_.InstanceName -notlike "*local area connection`**") } | Group-Object InstanceName | ForEach-Object {
            $Interface = $_.Group
            $InterfaceName = (Get-Culture).TextInfo.ToTitleCase($_.Name)

            if (Process-Filter $InterfaceName) {
                $InterfaceTraffic = $Interface.Where{ ($_.Path -like "*\Network Interface(*)\Bytes Total/sec") }.CookedValue
                New-NagiosResult -Label "Network Adapter($InterfaceName) Bytes Total/sec" -Value $InterfaceTraffic -Unit "B"

                $InterfaceValue = $Interface.Where{ ($_.Path -like "*\Network Interface(*)\Bytes Received/sec") }.CookedValue
                New-NagiosResult -Label "Network Adapter($InterfaceName) Bytes Received/sec" -Value $InterfaceValue -Unit "B"

                $InterfaceValue = $Interface.Where{ ($_.Path -like "*\Network Interface(*)\Bytes Sent/sec") }.CookedValue
                New-NagiosResult -Label "Network Adapter($InterfaceName) Bytes Sent/sec" -Value $InterfaceValue -Unit "B"

                $InterfaceValue = $Interface.Where{ ($_.Path -like "*\Network Interface(*)\Packets/sec") }.CookedValue
                New-NagiosResult -Label "Network Adapter($InterfaceName) Packets/sec" -Value $InterfaceValue

                # TODO seems not set
                #$InterfaceValue = $Interface.Where{ ($_.Path -like "*\Network Interface(*)\Packets Received/sec") }.CookedValue
                #New-NagiosResult -Label "Network Adapter($InterfaceName) Packets Received/sec" -Value $InterfaceValue

                # TODO seems not set
                #$InterfaceValue = $Interface.Where{ ($_.Path -like "*\Network Interface(*)\Packets Sent/sec") }.CookedValue
                #New-NagiosResult -Label "Network Adapter($InterfaceName) Packets Sent/sec" -Value $InterfaceValue

                $InterfaceValue = $Interface.Where{ ($_.Path -like "*\Network Interface(*)\Packets Received Non-Unicast/sec") }.CookedValue
                New-NagiosResult -Label "Network Adapter($InterfaceName) Packets Received Non-Unicast/sec" -Value $InterfaceValue

                $InterfaceValue = $Interface.Where{ ($_.Path -like "*\Network Interface(*)\Packets Received Unicast/sec") }.CookedValue
                New-NagiosResult -Label "Network Adapter($InterfaceName) Packets Received Unicast/sec" -Value $InterfaceValue

                $InterfaceBandwith = $Interface.Where{ ($_.Path -like "*\Network Interface(*)\Current Bandwidth") }.CookedValue /8
                #$InterfaceBandwith = $Interface.Where{ ($_.Path -like "*\Network Interface(*)\Current Bandwidth") }.CookedValue
                New-NagiosResult -Label "Network Adapter($InterfaceName) Current Bandwidth" -Value $InterfaceBandwith -Unit "B"

                $InterfacePercentage = $InterfaceTraffic / $InterfaceBandwith * 100
                # TODO limits
                New-NagiosResult -Label "Network Adapter($InterfaceName) % Usage" -Value $InterfacePercentage -Unit "%"
            }

        }

    }
    End {

        $PublishedResults

    }
}

Function GetSystemCounters {

    <#

    #>

    [CmdletBinding()]
    Param(

        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        $RawValues

    )

    Begin {

        $PublishedResults = @()

    }
    Process {

        # System Processes
        $SysValue = ($RawValues).Where{ ($_.Path -like "*System\Processes*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "System Processes" -Value $SysValue

        # System Processor Queue Length
        $SysValue = ($RawValues).Where{ ($_.Path -like "*System\Processor Queue Length*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "System Processor Queue Length" -Value $SysValue

        # System Threads
        $SysValue = ($RawValues).Where{ ($_.Path -like "*System\Threads*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "System Threads" -Value $SysValue

        # System System Calls/sec
        $SysValue = ($RawValues).Where{ ($_.Path -like "*System\System Calls/sec*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "System System Calls/sec" -Value $SysValue

        # System File Read Operations/sec
        $SysValue = ($RawValues).Where{ ($_.Path -like "*System\File Read Operations/sec*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "System File Read Operations/sec" -Value $SysValue

        # System File Write Operations/sec
        $SysValue = ($RawValues).Where{ ($_.Path -like "*System\File Write Operations/sec*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "System File Write Operations/sec" -Value $SysValue

    }
    End {

        $PublishedResults

    }
}



# Main function

if ($Args) {
    if($Args[0].ToString() -ne "$ARG1$"){
	    if($Args.count -ge 1){Initialize-Args $Args}
    }
}

<#

    .DESCRIPTION
        TODO
            Limits
            Test
                PNP/Perfdata correctness
                2008 2012

#>

Remove-Module *

# DEBUG
#(Get-Counter -ComputerName $DefaultsStruct.ComputerName -Counter $Counters).CounterSamples | Format-Table -AutoSize

# get defined counters
$RawValues = (Get-Counter -ComputerName $DefaultsStruct.ComputerName -Counter $Counters).CounterSamples

$PublishedResults = @()

if ($DefaultsStruct.Modes -contains 'cpu') {
    $PublishedResults += GetProcessorCounters -RawValues $RawValues
}
if ($DefaultsStruct.Modes -contains 'mem') {
    $PublishedResults += GetMemoryCounters -RawValues $RawValues
}
if ($DefaultsStruct.Modes -contains 'disk') {
    $PublishedResults += GetDiskCounters -RawValues $RawValues
}
if ($DefaultsStruct.Modes -contains 'net') {
    $PublishedResults += GetNetworkCounters -RawValues $RawValues
}
if ($DefaultsStruct.Modes -contains 'sys') {
    $PublishedResults += GetSystemCounters -RawValues $RawValues
}

Publish-NagiosResults -Publish $PublishedResults
Exit $DefaultsStruct.ExitCode
