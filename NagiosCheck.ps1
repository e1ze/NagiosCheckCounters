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

#        $Results += ""
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
        [String]$Text = "Plugin Output",
        [Int]$Warning = 0,
        [Int]$Critical = 0

    )

    Begin {

        If ($Critical){
            $PublishedResult = "CRITCAL: "   
        }
        ElseIf ($Warning){
            $PublishedResult = "WARNING: "   
        }
        Else {
            $PublishedResult = "OK: "   
        }

        $PublishedResult += "$Text |"

    }

    Process { 
     
        $PublishedResult += $Publish
    
    }
    End {
    
#        $PublishedResult += "..."
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

        # TODO make this value limitable
        #$TotalCpuUsage = ($RawValues).Where{ ($_.Path -like "*\% processor time*") -and ($_.InstanceName -eq "_total") }.CookedValue

        #Per CPU % Processor Time
        $PublishedResults += ($RawValues).Where{ ($_.Path -like "*\% processor time*") } | ForEach-Object {

            $Cpu = $_
            $CpuValue = $Cpu.CookedValue
            $CpuName = [string]$Cpu.InstanceName

            New-NagiosResult -Label "Processor($CpuName) % Processor Time" -Value $CpuValue -Unit "%"

        }

        #Per CPU % User Time
        $PublishedResults += ($RawValues).Where{ ($_.Path -like "*\% user time*") } | ForEach-Object {

            $Cpu = $_
            $CpuValue = $Cpu.CookedValue
            $CpuName = [string]$Cpu.InstanceName

            New-NagiosResult -Label "Processor($CpuName) % User Time" -Value $CpuValue -Unit "%"

        }

        #Per CPU % Idle Time
        $PublishedResults += ($RawValues).Where{ ($_.Path -like "*\% idle time*") } | ForEach-Object {

            $Cpu = $_
            $CpuValue = $Cpu.CookedValue
            $CpuName = [string]$Cpu.InstanceName

            New-NagiosResult -Label "Processor($CpuName) % Idle Time" -Value $CpuValue -Unit "%"

        }

        #Per CPU % Interrupt Time
        $PublishedResults += ($RawValues).Where{ ($_.Path -like "*\% interrupt time*") } | ForEach-Object {

            $Cpu = $_
            $CpuValue = $Cpu.CookedValue
            $CpuName = [string]$Cpu.InstanceName

            New-NagiosResult -Label "Processor($CpuName) % Interrupt Time" -Value $CpuValue -Unit "%"

        }

        #Per CPU % Privileged Time
        $PublishedResults += ($RawValues).Where{ ($_.Path -like "*\% privileged time*") } | ForEach-Object {

            $Cpu = $_
            $CpuValue = $Cpu.CookedValue
            $CpuName = [string]$Cpu.InstanceName

            New-NagiosResult -Label "Processor($CpuName) % Privileged Time" -Value $CpuValue -Unit "%"

        }

        #Per CPU Interrupts/sec
        $PublishedResults += ($RawValues).Where{ ($_.Path -like "*\interrupts/sec*") } | ForEach-Object {

            $Cpu = $_
            $CpuValue = $Cpu.CookedValue
            $CpuName = [string]$Cpu.InstanceName

            New-NagiosResult -Label "Processor($CpuName) Interrupts/sec" -Value $CpuValue

        }

    }
    End {

        Publish-NagiosResults -Publish $PublishedResults

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
        $MemValue = ($RawValues).Where{ ($_.Path -like "*\available bytes*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "Memory Available Bytes" -Value $MemValue -Unit "B"

        #Memory Committed Bytes
        $MemValue = ($RawValues).Where{ ($_.Path -like "*\committed bytes*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "Memory Committed Bytes" -Value $MemValue -Unit "B"

        #Memory System Code Total Bytes
        $MemValue = ($RawValues).Where{ ($_.Path -like "*\system code total bytes*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "Memory System Code Total Bytes" -Value $MemValue -Unit "B"

        #Memory Pool Nonpaged Bytes
        $MemValue = ($RawValues).Where{ ($_.Path -like "*\pool nonpaged bytes*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "Memory Pool Nonpaged Bytes" -Value $MemValue -Unit "B"

        #Memory Cache Bytes
        $MemValue = ($RawValues).Where{ ($_.Path -like "*\cache bytes*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "Memory Cache Bytes" -Value $MemValue -Unit "B"

        #Memory Commit Limit
        $MemValue = ($RawValues).Where{ ($_.Path -like "*\commit limit*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "Memory Commit Limit" -Value $MemValue -Unit "B"

        #Memory % Committed Bytes In Use
        $MemValue = ($RawValues).Where{ ($_.Path -like "*\% committed bytes in use*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "Memory % Committed Bytes In Use" -Value $MemValue -Unit "B"

        #Memory Pages/sec
        $MemValue = ($RawValues).Where{ ($_.Path -like "*\pages/sec*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "Memory Pages/sec" -Value $MemValue

        #Memory Page Faults/sec
        $MemValue = ($RawValues).Where{ ($_.Path -like "*\page faults/sec*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "Memory Page Faults/sec" -Value $MemValue
        
        #Memory Page Reads/sec
        $MemValue = ($RawValues).Where{ ($_.Path -like "*\page reads/sec*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "Memory Page Reads/sec" -Value $MemValue
        
        #Memory Page Writes/sec
        $MemValue = ($RawValues).Where{ ($_.Path -like "*\page writes/sec*") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "Memory Page Writes/sec" -Value $MemValue

        #Total Paging File usage
        $TotalPageFileUsage = ($RawValues).Where{ ($_.Path -like "*paging file*") -and ($_.InstanceName -eq "_total") }.CookedValue
        $PublishedResults += New-NagiosResult -Label "Total Page File usage" -Value $TotalPageFileUsage -Unit "%"

    }
    End {

        Publish-NagiosResults -Publish $PublishedResults

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

        #Disk usage
        $PublishedResults += ($RawValues).Where{ ($_.Path -like "*logicaldisk*") -and ($_.InstanceName -like "*:*") } | Group-Object InstanceName | ForEach-Object {
            
            $Disk = $_.Group
            $DiskName = (Get-Culture).TextInfo.ToTitleCase($_.Name)
            $DiskSpacePercentage = $Disk.Where{ ($_.Path -like "*% Free Space*") }.CookedValue
            $DiskSpaceUsage = ($Disk.Where{ ($_.Path -like "*Free Megabytes*") }).CookedValue 
            
            New-NagiosResult -Label "Drive $DiskName Free Percentage" -Value $DiskSpacePercentage -Unit "%"
            New-NagiosResult -Label "Drive $DiskName Free Space" -Value ($DiskSpaceUsage * 1024 * 1024 ) -Unit "B"
        
        }

        #Per PhysicalDisk Disk Transfers/sec
        $PublishedResults += ($RawValues).Where{ ($_.Path -like "*\Disk Transfers/sec*") } | ForEach-Object {
            
            $PhysDisk = $_
            $PhysDiskValue = $PhysDisk.CookedValue
            $PhysDiskName = [string]$PhysDisk.InstanceName
            
            New-NagiosResult -Label "PhysicalDisk($PhysDiskName) Disk Transfers/sec" -Value $PhysDiskValue
        
        }

    }
    End {

        Publish-NagiosResults -Publish $PublishedResults

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
            New-NagiosResult -Label "Network Adapter($InterfaceName) % Usage" -Value $InterfacePercentage -Unit "%"
        
        }

    }
    End {

        Publish-NagiosResults -Publish $PublishedResults

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

        Publish-NagiosResults -Publish $PublishedResults

    }
}



[string]$ComputerName = 'localhost'

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

# DEBUG
#(Get-Counter -ComputerName $ComputerName -Counter $Counters).CounterSamples | Format-Table -AutoSize  

$RawValues = (Get-Counter -ComputerName $ComputerName -Counter $Counters).CounterSamples

GetProcessorCounters -RawValues $RawValues
GetMemoryCounters -RawValues $RawValues
GetDiskCounters -RawValues $RawValues
GetNetworkCounters -RawValues $RawValues
GetSystemCounters -RawValues $RawValues

# Exit $DiskStruct.ExitCode