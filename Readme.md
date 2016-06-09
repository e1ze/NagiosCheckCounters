# About NagiosCheckCounter.ps1

NagiosCheckCounter.ps1 is a plugin for Nagios and compatible systems like Icinga. Its primary goal is to collect the most important Windows Performance Counter metrics.

In its first published version it is only compatible with english language systems. It is tested with Windows Server 2008 R2 and Windows Server 2012 R2, other Windows versions may work.

**Note: Currently checking counter values against thersholds is not implemented. This is planned for a future release.**

**Note: This plugins creates a lot of performance data. Therefore it will almost certainly not be usable with NRPE and its default transport limit of 1024kB**

## Collected performance counters

NagiosCheckCounter.ps1 collects the performance data for all insatnces of the counters below:

Mode `cpu`:

    \Processor(*)\% Processor Time
    \Processor(*)\% User Time
    \Processor(*)\% Idle Time
    \Processor(*)\% Interrupt Time
    \Processor(*)\% Privileged Time
    \Processor(*)\Interrupts/sec
    
Mode `mem`:

    \Memory\Available Bytes
    \Memory\Committed Bytes
    \Memory\System Code Total Bytes
    \Memory\Pool Nonpaged Bytes
    \Memory\Cache Bytes
    \Memory\Commit Limit
    \Memory\% Committed Bytes In Use
    \Memory\Pages/sec
    \Memory\Page Faults/sec
    \Memory\Page Reads/sec
    \Memory\Page Writes/sec
    \Paging File(*)\% Usage
    
Mode `disk`:

    (1)   \LogicalDisk(*)\% Free Space
    (1,2) \LogicalDisk(*)\Free Megabytes
    \PhysicalDisk(*)\Disk Transfers/sec
    \PhysicalDisk(*)\Disk Reads/sec
    \PhysicalDisk(*)\Disk Writes/sec
    \PhysicalDisk(*)\Disk Bytes/sec
    \PhysicalDisk(*)\Avg. Disk Bytes/Read
    \PhysicalDisk(*)\Disk Write Bytes/sec
    \PhysicalDisk(*)\Avg. Disk Bytes/Write

Mode `net`:

    (3) \Network Interface(*)\Current Bandwidth
    (3) \Network Interface(*)\Bytes Total/sec
    (3) \Network Interface(*)\Bytes Received/sec
    (3) \Network Interface(*)\Bytes Sent/sec
    (3) \Network Interface(*)\Packets/sec
    (3) \Network Interface(*)\Packets Received Unicast/sec
    (3) \Network Interface(*)\Packets Received Non-Unicast/sec
    (3) \Network Interface(*)\Packets Received Discarded
    (3) \Network Interface(*)\Packets Received Errors
    (3) \Network Interface(*)\Packets Received Unknown
    (3) \Network Interface(*)\Packets Sent Unicast/sec
    (3) \Network Interface(*)\Packets Sent Non-Unicast/sec
    (3) \Network Interface(*)\Packets Outbound Discarded
    (3) \Network Interface(*)\Packets Outbound Errors

Mode `sys`:

    \System\Processes
    \System\Processor Queue Length
    \System\Threads
    \System\System Calls/sec
    \System\File Write Operations/sec
    \System\File Read Operations/sec

If not specified otherwise (see "Command reference" below), all modes are queried at once. 

### Annotations:

**(1)** Only LogicalDisks instances containing `:` are queried.

**(2)** The values of this counter are converted to Bytes by the plugin.

**(3)** NetworkInterface instances containing `isatap` or `local area connection` are ignored.

## Command reference

	X:\> .\NagiosCheckCounters.ps1 -h
	
	NagiosCheckCounters.ps1:
	This script is designed to monitor preselected Microsoft Windows performance counters.
	Arguments:
	    -m   | --Modes       Optional comma separated list of query modes. Default cpu,mem,disk,net,sys.
	
 	    -i   | --Include     Optional comma separated list of inclusion filters (whitelist),
                             applicable to CpuNames, LogicalDiskNames, PhysDiskNames and InterfaceNames.
 	                         For example: "C:","X:"
 	    -x   | --Exclude     Optional comma separated list of exclusion filters (blacklist),
                             applicable to CpuNames, LogicalDiskNames, PhysDiskNames and InterfaceNames.
                             For example: "C:","X:"

                             Note: The blacklist is applied after the whitelist

       -h   | --Help         Print this help.

### Modes

Using modes you can limit the output of the plugin to one or more of the counter groups (see "Collected performance counters" above):

	-m cpu

	-m cpu,mem,sys

### Whitelist / Blacklist

Whitelisting example only showing items containing `_Total` in mode `cpu`:

	X:\> .\NagiosCheckCounters.ps1 -m cpu -i _Total

	OK: Queried vagrant-2012-r2 using modes [cpu] |'Processor(_Total) % Processor Time'=0.0069695142248638% 'Processor(_Total) % User Time'=0% 'Processor(_Total) % Idle Time'=99.1218012104556% 'Processor(_Total) % Interrupt Time'=0% 'Processor(_Total) % Privileged Time'=0% 'Processor(_Total) Interrupts/sec'=213.232710981228
	
Blacklisting example ignoring all disk instance names containing `C:` in mode `disk`:

	X:\> .\NagiosCheckCounters.ps1 -m disk -x C:

	OK: Queried vagrant-2012-r2 using modes [disk] |'PhysicalDisk(_Total) Disk Transfers/sec'=0 'PhysicalDisk(_Total) Disk Reads/sec'=0 'PhysicalDisk(_Total) Disk Writes/sec'=0 'PhysicalDisk(_Total) Disk Bytes/sec'=0B 'PhysicalDisk(_Total) Disk Write Bytes/sec'=0B 'PhysicalDisk(_Total) Avg. Disk Bytes/Read'=0B 'PhysicalDisk(_Total) Avg. Disk Bytes/Write'=0B
	
You can combine White- and Blackist. Whitelist items are applied **before** blacklist items.

### Sample output:

	X:\> .\NagiosCheckCounters.ps1

	OK: Queried vagrant-2012-r2 using modes [cpu mem disk net sys] |'Processor(0) % Processor Time'=1.60981107607874% 'Processor(0) % User Time'=0% 'Processor(0) % Idle Time'=98.6103763277141% 'Processor(0) % Interrupt Time'=0% 'Processor(0) % Privileged Time'=1.53734670193627% 'Processor(0) Interrupts/sec'=128.321950373717 'Processor(1) % Processor Time'=1.60981107607874% 'Processor(1) % User Time'=0% 'Processor(1) % Idle Time'=99.0074397741355% 'Processor(1) % Interrupt Time'=0% 'Processor(1) % Privileged Time'=1.53734670193627% 'Processor(1) Interrupts/sec'=100.68337644707 'Processor(_Total) % Processor Time'=1.60981107607874% 'Processor(_Total) % User Time'=0% 'Processor(_Total) % Idle Time'=98.8089080509248% 'Processor(_Total) % Interrupt Time'=0% 'Processor(_Total) % Privileged Time'=1.53734670193627% Processor(_Total) Interrupts/sec'=229.005326820788 'Memory Available Bytes'=513220608B 'Memory Committed Bytes'=952446976B 'Memory System Code Total Bytes'=3608576B 'Memory Pool Nonpaged Bytes'=37064704B 'Memory Cache Bytes'=7860224B 'Memory Commit Limit'=2674069504B 'Memory % Committed Bytes In Use'=35.6178840742653% 'Memory Pages/sec'=0 'Memory Page Faults/sec'=0.987091925951671 'Memory Page Reads/sec'=0 'Memory Page Writes/sec'=0 'Total Page File usage'=7.48835781178036% 'LogicalDisk(C:) % Free Space'=84.8052777186635% 'LogicalDisk(C:) Free Bytes'=54321479680B 'PhysicalDisk(0 C:) Disk Transfers/sec'=20.7289304449851 'PhysicalDisk(0 C:) Disk Reads/sec'=0 'PhysicalDisk(0 C:) Disk Writes/sec'=20.7289304449851 'PhysicalDisk(0 C:) Disk Bytes/sec'=271900.393554943B 'PhysicalDisk(0 C:) Disk Write Bytes/sec'=271900.393554943B 'PhysicalDisk(0 C:) Avg. Disk Bytes/Read'=0B 'PhysicalDisk(0 C:) Avg. Disk Bytes/Write'=13116.9523809524B 'PhysicalDisk(_Total) Disk Transfers/sec'=20.7289304449851 'PhysicalDisk(_Total) Disk Reads/sec'=0 'PhysicalDisk(_Total) Disk Writes/sec'=20.7289304449851 'PhysicalDisk(_Total) Disk Bytes/sec'=271900.393554943B 'PhysicalDisk(_Total) Disk Write Bytes/sec'=271900.393554943B 'PhysicalDisk(_Total) Avg. Disk Bytes/Read'=0B 'PhysicalDisk(_Total) Avg. Disk Bytes/Write'=13116.9523809524B 'Network Adapter(Intel[R] Pro_1000 Mt Desktop Adapter) Bytes Total/sec'=0B 'Network Adapter(Intel[R] Pro_1000 Mt Desktop Adapter) Bytes Received/sec'=0B 'Network Adapter(Intel[R] Pro_1000 Mt Desktop Adapter) Bytes Sent/sec'=0B 'Network Adapter(Intel[R] Pro_1000 Mt Desktop Adapter) Packets/sec'=0 'Network Adapter(Intel[R] Pro_1000 Mt Desktop Adapter) Packets Received Non-Unicast/sec'=0 'Network Adapter(Intel[R] Pro_1000 Mt Desktop Adapter) Packets Received Unicast/sec'=0 'Network Adapter(Intel[R] Pro_1000 Mt Desktop Adapter) Current Bandwidth'=0B 'Network Adapter(Intel[R] Pro_1000 Mt Desktop Adapter) % Usage'=0% 'Network Adapter(Intel[R] Pro_1000 Mt Desktop Adapter _2) Bytes Total/sec'=0B 'Network Adapter(Intel[R] Pro_1000 Mt Desktop Adapter _2) Bytes Received/sec'=0B 'Network Adapter(Intel[R] Pro_1000 Mt Desktop Adapter _2) Bytes Sent/sec'=0B 'Network Adapter(Intel[R] Pro_1000 Mt Desktop Adapter _2) Packets/sec'=0 'Network Adapter(Intel[R] Pro_1000 Mt Desktop Adapter _2) Packets Received Non-Unicast/sec'=0 'Network Adapter(Intel[R] Pro_1000 Mt Desktop Adapter _2) Packets Received Unicast/sec'=0 'Network Adapter(Intel[R] Pro_1000 Mt Desktop Adapter _2) Current Bandwidth'=125000000B 'Network Adapter(Intel[R] Pro_1000 Mt Desktop Adapter _2) % Usage'=0% 'System Processes'=35 'System Processor Queue Length'=0 'System Threads'=461 'System System Calls/sec'=645.558119572393 'System File Read Operations/sec'=8.88382733356504 'System File Write Operations/sec'=8.88382733356504

## Nagios configuration and transports

### Usage with NRPE and NSClient++

To use NagiosCheckCounter.ps1 with NSClient++, place it in the `scripts\` directory of the NSClient++ installation path.

Add the following items to your `nsclient.ini` configuration:

	[/settings/NRPE/server]
	...
	allow arguments = true
	allow nasty characters = true

	[/settings/external scripts]
	allow arguments = true
	allow nasty characters = true

	[/settings/external scripts/scripts/default]
	ignore perfdata = false

	[/settings/external scripts/scripts]
	...
	ncc = cmd /c echo scripts\NagiosCheckCounters.ps1 $ARG1$; exit($lastexitcode) | powershell.exe -command -

In Nagios you can then use a configuration similar to the following:

	define command{
        command_name    nrpe
        command_line    $USER1$/check_nrpe -H $HOSTADDRESS$ -p 5666 -c $ARG1$  -a $ARG2$
	}
	...
	define service {
  		use                   generic-service,srv-pnp
  		host_name             MYHOST
  		service_description   NagiosCheckCounters mode cpu
  		check_command         nrpe!ncc!"-m cpu"
	}
	...

### Usage with SSH

If you are lucky and have an SSH server at hand on your Windows server, you can use a configuration similar to the following. With this transport mechanism you don't have to mind about transport limitations.

Of course you have to setup passwordless SSH connections using public keys to your Windows hosts. In the following example the user `vagrant` is used for SSH access:

	define command{
        command_name    byssh
        command_line    $USER1$/check_by_ssh -H $HOSTADDRESS$ -p 22 -l vagrant  -C '$ARG1$'
	}
	...
	define service {
	  use                   generic-service,srv-pnp
	  host_name             MYHOST
	  service_description   NagiosCheckCounters
	  check_command         byssh!powershell "& ""%ProgramFiles%\\NSClient++\\scripts\\NagiosCheckCounters.ps1"""
	}
	
NagiosCheckCounters.ps1 is located in `%ProgramFiles%\NSClient++\scripts\NagiosCheckCounters.ps1` in this example.




