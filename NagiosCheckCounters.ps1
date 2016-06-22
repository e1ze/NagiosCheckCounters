# Script name:   	NagiosCheckCounters.ps1
# Version:			2016.06.08.01
# Author:        	Michael Kraus
# Purpose:       	Check a bunch of preselcted perfcounters using Powershell
# On Github:		https://github.com/m-kraus/NagiosCheckCounters
# Recent History:
#	2016.06.08.01 => Initial version
# Copyright:
#	This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published
#	by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. This program is distributed
#	in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
#	PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU General Public
#	License along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Requires Powershell Version 2.0 or greater

#TODO
# Introduce limits
# Introduce a check for system language
# Timeout handling

#######################################################################################################################
#
# Initialize variables
#
#######################################################################################################################

$DefaultsStruct = New-object PSObject -Property @{
    ComputerName = ([System.Net.Dns]::GetHostByName((hostname.exe)).HostName).tolower();
    Modes = ("cpu", "mem", "disk", "net", "sys");
    Exclude = @();
    Include = @();
    ExitCode = 3;
    WarningCount = 0;
    CriticalCount = 0;
# TODO
#    ProcessorTime: limit over (%)
#    MemoryAvailable: limit under (B)
#    PagefileUsage: limit over (%)
#    DiskfreeSpace:
#    DiskfreePercentage:
#    InterfaceUsage:
#    AvgDiskReadQueue: limit over (int)
#    AvgDiskWriteQueue: limit over (int)
#    LimitMessages = @();
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



#######################################################################################################################
#
# Functions
#
#######################################################################################################################

Function Initialize-Args {

    Param ( [Parameter(Mandatory=$True)]$Args )

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

                "^(-x|--Exclude)$" {
                    # TODO validate input string ?
                    $script:DefaultsStruct.Exclude = $value -split ','
                    $i++
                }

                "^(-i|--Include)$" {
                    # TODO validate input string ?
                    $script:DefaultsStruct.Include = $value -split ','
                    $i++
                }

#                "^(--CpuWarn)$" {
#                    if (($value -match "^[\d]+$") -and ([int]$value -lt 999999)) {
#                        $DefaultsStruct.LimitCpu = 1
#                        $DefaultsStruct.LimitCpuWarn = $value
#                    } else {
#                        throw "Cpu warning does not meet regex requirements (`"^[\d]+$`"). Value given is `"$value`"."
#                    }
#                    $i++
#                 }

#                "^(--CpuCrit)$" {
#                    if (($value -match "^[\d]+$") -and ([int]$value -lt 999999)) {
#                        $DefaultsStruct.LimitCpu = 1
#                        $DefaultsStruct.LimitCpuCrit = $value
#                    } else {
#                        throw "Cpu critical does not meet regex requirements (`"^[\d]+$`"). Value given is `"$value`"."
#                    }
#                    $i++
#                 }

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
This script is designed to monitor preselected Microsoft Windows performance counters.
Arguments:
    -m 	 | --Modes           Optional comma separated list of query modes. Default cpu,mem,disk,net,sys.

    -i   | --Include         Optional comma separated list of inclusion filters (whitelist),
                             applicable to CpuNames, LogicalDiskNames, PhysDiskNames and InterfaceNames.
                             For example: "C:","X:"
    -x   | --Exclude         Optional comma separated list of exclusion filters (blacklist),
                             applicable to CpuNames, LogicalDiskNames, PhysDiskNames and InterfaceNames.
                             For example: "C:","X:"

                             Note: The blacklist is applied after the whitelist

    -h   | --Help 			 Print this help.
"@

    Exit 0;

}

Function Process-Filter {

    Param ( [Parameter(Mandatory=$True)][string]$String )

    # Sanitize instance names
    #-#$pattern = '[^a-zA-Z0-9]'
    #-#$String -replace $pattern, ''

    # set default
    $DoCheck = $false
    # first determine whitelist
    if ( $script:DefaultsStruct.Include.Count -gt 0 ) {
        $script:DefaultsStruct.Include | ForEach-Object {
            If ( $String.Contains("$_") ) {
                $DoCheck = $true
            }
        }
    } Else {
        $DoCheck = $true
    }
    # then apply blacklist
    if ( $script:DefaultsStruct.Exclude.Count -gt 0 ) {
        $script:DefaultsStruct.Exclude | ForEach-Object {
            If ( $String.Contains("$_") ) {
                $DoCheck = $false
            }
        }
    }

    Return $DoCheck

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

        $Value = [Math]::Round($Value, 2)
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
        [String]$Text = "Queried " + [string]$script:DefaultsStruct.ComputerName + " using modes [" + [string]$script:DefaultsStruct.Modes + "]"

    )

    Begin {

        If ($script:DefaultsStruct.CriticalCount -gt 0){
            $PublishedResult = "CRITCAL: "
            $script:DefaultsStruct.ExitCode = 2
        }
        ElseIf ($script:DefaultsStruct.WarningCount -gt 0){
            $PublishedResult = "WARNING: "
            $script:DefaultsStruct.ExitCode = 1
        }
        Else {
            $PublishedResult = "OK: "
            $script:DefaultsStruct.ExitCode = 0
        }

        # TODO get messages for limits
        $PublishedResult += "$Text |"

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
    .PARAMETER RawValues
        Object containing queried counters
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

        $SelectedObj = $RawValues | ? { ($_.Path -like "*Processor(*)\*") }
        $PublishedResults += $SelectedObj | Group-Object InstanceName | ForEach-Object {

            $Cpu = $_.Group
            $CpuName = (Get-Culture).TextInfo.ToTitleCase($_.Name)
            $CpuName = $CpuName -replace $script:CleanPattern, ''

            if (Process-Filter $CpuName)  {

                #Per CPU % Processor Time
                $CpuValue = $Cpu | ? { ($_.Path -like "*\% processor time*") }
                # TODO limits/thresholds if ($CpuName -eq "_total") {
                New-NagiosResult -Label "Cpu $CpuName PctProcTime" -Value $CpuValue.CookedValue -Unit "%"

                #Per CPU % User Time
                $CpuValue = $Cpu | ? { ($_.Path -like "*\% user time*") }
                New-NagiosResult -Label "Cpu $CpuName PctUserTime" -Value $CpuValue.CookedValue -Unit "%"

                #Per CPU % Idle Time
                $CpuValue = $Cpu | ? { ($_.Path -like "*\% idle time*") }
                New-NagiosResult -Label "Cpu $CpuName PctIdleTime" -Value $CpuValue.CookedValue -Unit "%"

                #Per CPU % Interrupt Time
                $CpuValue = $Cpu | ? { ($_.Path -like "*\% interrupt time*") }
                New-NagiosResult -Label "Cpu $CpuName PctIntrptTime" -Value $CpuValue.CookedValue -Unit "%"

                #Per CPU % Privileged Time
                $CpuValue = $Cpu | ? { ($_.Path -like "*\% privileged time*") }
                New-NagiosResult -Label "Cpu $CpuName PctPrivTime" -Value $CpuValue.CookedValue -Unit "%"

                #Per CPU Interrupts/sec
                $CpuValue = $Cpu | ? { ($_.Path -like "*\interrupts/sec*") }
                New-NagiosResult -Label "Cpu $CpuName IntrptsSec" -Value $CpuValue.CookedValue

            }

        }

    }
    End {

        $PublishedResults

    }
}

Function GetMemoryCounters {

    <#
    .PARAMETER RawValues
        Object containing queried counters
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
        $MemValue = $RawValues | ? { ($_.Path -like "*Memory\Available Bytes*") }
        # TODO limits
        $PublishedResults += New-NagiosResult -Label "MemAvailBytes" -Value $MemValue.CookedValue -Unit "B"

        #Memory Committed Bytes
        $MemValue = $RawValues | ? { ($_.Path -like "*Memory\Committed Bytes*") }
        $PublishedResults += New-NagiosResult -Label "MemCommtdBytes" -Value $MemValue.CookedValue -Unit "B"

        #Memory System Code Total Bytes
        $MemValue = $RawValues | ? { ($_.Path -like "*Memory\System Code Total Bytes*") }
        $PublishedResults += New-NagiosResult -Label "MemSysCodeTtlBytes" -Value $MemValue.CookedValue -Unit "B"

        #Memory Pool Nonpaged Bytes
        $MemValue = $RawValues | ? { ($_.Path -like "*Memory\Pool Nonpaged Bytes*") }
        $PublishedResults += New-NagiosResult -Label "MemPoolNonpgdBytes" -Value $MemValue.CookedValue -Unit "B"

        #Memory Cache Bytes
        $MemValue = $RawValues | ? { ($_.Path -like "*Memory\Cache Bytes*") }
        $PublishedResults += New-NagiosResult -Label "MemCacheBytes" -Value $MemValue.CookedValue -Unit "B"

        #Memory Commit Limit
        $MemValue = $RawValues | ? { ($_.Path -like "*Memory\Commit Limit*") }
        $PublishedResults += New-NagiosResult -Label "MemCommitLimit" -Value $MemValue.CookedValue -Unit "B"

        #Memory % Committed Bytes In Use
        $MemValue = $RawValues | ? { ($_.Path -like "*Memory\% Committed Bytes In Use*") }
        $PublishedResults += New-NagiosResult -Label "MemPctCommtdBytesInUse" -Value $MemValue.CookedValue -Unit "%"

        #Memory Pages/sec
        $MemValue = $RawValues | ? { ($_.Path -like "*Memory\Pages/sec*") }
        $PublishedResults += New-NagiosResult -Label "MemPagesSec" -Value $MemValue.CookedValue

        #Memory Page Faults/sec
        $MemValue = $RawValues | ? { ($_.Path -like "*Memory\Page Faults/sec*") }
        $PublishedResults += New-NagiosResult -Label "MemPageFaultsSec" -Value $MemValue.CookedValue

        #Memory Page Reads/sec
        $MemValue = $RawValues | ? { ($_.Path -like "*Memory\Page Reads/sec*") }
        $PublishedResults += New-NagiosResult -Label "MemPageReadsSec" -Value $MemValue.CookedValue

        #Memory Page Writes/sec
        $MemValue = $RawValues | ? { ($_.Path -like "*Memory\Page Writes/sec*") }
        $PublishedResults += New-NagiosResult -Label "MemPageWritesSec" -Value $MemValue.CookedValue

        #Total Paging File usage
        $TotalPageFileUsage = $RawValues | ? { ($_.Path -like "*Paging File(*)\% Usage*") -and ($_.InstanceName -eq "_total") }
        # TODO limits
        $PublishedResults += New-NagiosResult -Label "TtlPageFileUsage" -Value $TotalPageFileUsage.CookedValue -Unit "%"

    }
    End {

        $PublishedResults

    }
}

Function GetDiskCounters {

    <#
    .PARAMETER RawValues
        Object containing queried counters
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
        $SelectedObj = $RawValues | ? { ($_.Path -like "*logicaldisk(*)\*") -and ($_.InstanceName -like "*:*") }
        $PublishedResults += $SelectedObj | Group-Object InstanceName | ForEach-Object {

            $Disk = $_.Group
            $DiskName = (Get-Culture).TextInfo.ToTitleCase($_.Name)
            $DiskName = $DiskName -replace $script:CleanPattern, ''

            if (Process-Filter $DiskName)  {
                $DiskSpacePercentage = $Disk | ? { ($_.Path -like "*% Free Space*") }
                $DiskSpaceUsage = $Disk | ? { ($_.Path -like "*Free Megabytes*") }

                # TODO limits
                New-NagiosResult -Label "LogDsk $DiskName PctFreeSpace" -Value $DiskSpacePercentage.CookedValue -Unit "%"
                # TODO limits
                New-NagiosResult -Label "LogDsk $DiskName FreeBytes" -Value ($DiskSpaceUsage.CookedValue * 1024 * 1024) -Unit "B"
            }

        }

        #PhysicalDisk counters
        $SelectedObj = $RawValues | ? { ($_.Path -like "*physicaldisk(*)\*") }
        $PublishedResults += $SelectedObj | Group-Object InstanceName | ForEach-Object {

            $PhysDisk = $_.Group
            $PhysDiskName = (Get-Culture).TextInfo.ToTitleCase($_.Name)
            $PhysDiskName = $PhysDiskName -replace $script:CleanPattern, ''

            if (Process-Filter $PhysDiskName) {
                #Per PhysicalDisk Disk Transfers/sec
                $PhysDiskValue = $PhysDisk | ? { ($_.Path -like "*Disk Transfers/sec*") }
                New-NagiosResult -Label "PhyDsk $PhysDiskName DskTransfrSec" -Value $PhysDiskValue.CookedValue

                #Per PhysicalDisk Disk Reads/sec
                $PhysDiskValue = $PhysDisk | ? { ($_.Path -like "*Disk Reads/sec*") }
                New-NagiosResult -Label "PhyDsk $PhysDiskName DskReadsSec" -Value $PhysDiskValue.CookedValue

                #Per PhysicalDisk Disk Writes/sec
                $PhysDiskValue = $PhysDisk | ? { ($_.Path -like "*Disk Writes/sec*") }
                New-NagiosResult -Label "PhyDsk $PhysDiskName DskWritesSec" -Value $PhysDiskValue.CookedValue

                #Per PhysicalDisk Disk Bytes/sec
                $PhysDiskValue = $PhysDisk | ? { ($_.Path -like "*Disk Bytes/sec*") }
                New-NagiosResult -Label "PhyDsk $PhysDiskName DskBytesSec" -Value $PhysDiskValue.CookedValue -Unit "B"

                #Per PhysicalDisk Disk Write Bytes/sec
                $PhysDiskValue = $PhysDisk | ? { ($_.Path -like "*Disk Write Bytes/sec*") }
                New-NagiosResult -Label "PhyDsk $PhysDiskName DskWriteBytesSec" -Value $PhysDiskValue.CookedValue -Unit "B"

                #Per PhysicalDisk Avg. Disk Bytes/Read
                $PhysDiskValue = $PhysDisk | ? { ($_.Path -like "*Avg. Disk Bytes/Read*") }
                New-NagiosResult -Label "PhyDsk $PhysDiskName AvgDskBytesRead" -Value $PhysDiskValue.CookedValue -Unit "B"

                #Per PhysicalDisk Avg. Disk Bytes/Write
                $PhysDiskValue = $PhysDisk | ? { ($_.Path -like "*Avg. Disk Bytes/Write*") }
                New-NagiosResult -Label "PhyDsk $PhysDiskName AvgDskBytesWrite" -Value $PhysDiskValue.CookedValue -Unit "B"
            }

        }

    }
    End {

        $PublishedResults

    }
}

Function GetNetworkCounters {

    <#
    .PARAMETER RawValues
        Object containing queried counters
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
        $SelectedObj = $RawValues | ? { ($_.Path -like "*Network Interface*") -and ($_.InstanceName -notlike "*isatap*") -and ($_.InstanceName -notlike "*local area connection`**") }
        $PublishedResults += $SelectedObj | Group-Object InstanceName | ForEach-Object {
            $Interface = $_.Group
            $InterfaceName = (Get-Culture).TextInfo.ToTitleCase($_.Name)
            $InterfaceName = $InterfaceName -replace $script:CleanPattern, ''

            if (Process-Filter $InterfaceName) {
                $InterfaceTraffic = $Interface | ? { ($_.Path -like "*\Network Interface(*)\Bytes Total/sec") }
                New-NagiosResult -Label "NetInt $InterfaceName BytesTtlSec" -Value $InterfaceTraffic.CookedValue -Unit "B"

                $InterfaceValue = $Interface | ? { ($_.Path -like "*\Network Interface(*)\Bytes Received/sec") }
                New-NagiosResult -Label "NetInt $InterfaceName BytesRcvdSec" -Value $InterfaceValue.CookedValue -Unit "B"

                $InterfaceValue = $Interface | ? { ($_.Path -like "*\Network Interface(*)\Bytes Sent/sec") }
                New-NagiosResult -Label "NetInt $InterfaceName BytesSentSec" -Value $InterfaceValue.CookedValue -Unit "B"

                $InterfaceValue = $Interface | ? { ($_.Path -like "*\Network Interface(*)\Packets/sec") }
                New-NagiosResult -Label "NetInt $InterfaceName PacketsSec" -Value $InterfaceValue.CookedValue

                # FIXME seems not set
                #$InterfaceValue = $Interface | ? { ($_.Path -like "*\Network Interface(*)\Packets Received/sec") }
                #New-NagiosResult -Label "NetInt $InterfaceName Packets Received/sec" -Value $InterfaceValue.CookedValue

                # FIXME seems not set
                #$InterfaceValue = $Interface | ? { ($_.Path -like "*\Network Interface(*)\Packets Sent/sec") }
                #New-NagiosResult -Label "NetInt $InterfaceName Packets Sent/sec" -Value $InterfaceValue.CookedValue

                $InterfaceValue = $Interface | ? { ($_.Path -like "*\Network Interface(*)\Packets Received Non-Unicast/sec") }
                New-NagiosResult -Label "NetInt $InterfaceName PacketsRcvdNonUnicastSec" -Value $InterfaceValue.CookedValue

                $InterfaceValue = $Interface | ? { ($_.Path -like "*\Network Interface(*)\Packets Received Unicast/sec") }
                New-NagiosResult -Label "NetInt $InterfaceName PacketsRcvdUnicastSec" -Value $InterfaceValue.CookedValue

                $InterfaceBandwith = $Interface | ? { ($_.Path -like "*\Network Interface(*)\Current Bandwidth") }
                #$InterfaceBandwith = $Interface.Where{ ($_.Path -like "*\Network Interface(*)\Current Bandwidth") }.CookedValue
                New-NagiosResult -Label "NetInt $InterfaceName CurrBandwidth" -Value ($InterfaceBandwith.CookedValue / 8) -Unit "B"

                # avoid division by zero
                if ( $InterfaceBandwith.CookedValue -gt 0 ) {
                    $InterfacePercentage = $InterfaceTraffic.CookedValue / ($InterfaceBandwith.CookedValue / 8 ) * 100
                }
                Else {
                    $InterfacePercentage = 0
                }

                # TODO limits
                New-NagiosResult -Label "NetInt $InterfaceName PctUsage" -Value $InterfacePercentage -Unit "%"
            }

        }

    }
    End {

        $PublishedResults

    }
}

Function GetSystemCounters {

    <#
    .PARAMETER RawValues
        Object containing queried counters
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
        $SysValue = $RawValues | ? { ($_.Path -like "*System\Processes*") }
        $PublishedResults += New-NagiosResult -Label "SysProcesses" -Value $SysValue.CookedValue

        # System Processor Queue Length
        $SysValue = $RawValues | ? { ($_.Path -like "*System\Processor Queue Length*") }
        $PublishedResults += New-NagiosResult -Label "SysProcQueueLen" -Value $SysValue.CookedValue

        # System Threads
        $SysValue = $RawValues | ? { ($_.Path -like "*System\Threads*") }
        $PublishedResults += New-NagiosResult -Label "SysThreads" -Value $SysValue.CookedValue

        # System System Calls/sec
        $SysValue = $RawValues | ? { ($_.Path -like "*System\System Calls/sec*") }
        $PublishedResults += New-NagiosResult -Label "SysSystemCallsSec" -Value $SysValue.CookedValue

        # System File Read Operations/sec
        $SysValue = $RawValues | ? { ($_.Path -like "*System\File Read Operations/sec*") }
        $PublishedResults += New-NagiosResult -Label "SysFileReadOperSec" -Value $SysValue.CookedValue

        # System File Write Operations/sec
        $SysValue = $RawValues | ? { ($_.Path -like "*System\File Write Operations/sec*") }
        $PublishedResults += New-NagiosResult -Label "SysFileWriteOperSec" -Value $SysValue.CookedValue

    }
    End {

        $PublishedResults

    }
}

#######################################################################################################################
#
# Main function
#
#######################################################################################################################

if ($Args) {
    if($Args[0].ToString() -ne "$ARG1$"){
	    if($Args.count -ge 1){Initialize-Args $Args}
    }
}

Remove-Module *

# DEBUG
#(Get-Counter -ComputerName $DefaultsStruct.ComputerName -Counter $Counters).CounterSamples | Format-Table -AutoSize

$CleanPattern = '[^a-zA-Z0-9]'

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
