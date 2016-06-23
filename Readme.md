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
 	                         For example: "C","X"
 	    -x   | --Exclude     Optional comma separated list of exclusion filters (blacklist),
                             applicable to CpuNames, LogicalDiskNames, PhysDiskNames and InterfaceNames.
                             For example: "C","X"

                             Note: The blacklist is applied after the whitelist

       -h   | --Help         Print this help.

### Modes

Using modes you can limit the output of the plugin to one or more of the counter groups (see "Collected performance counters" above):

	-m cpu

	-m cpu,mem,sys
	
### Shortening of Values and Instances

Values are rounded to two decimal places.

Instance Names are stripped from any other characters other than `a-z` `A-Z` `0-9` and `:`.

### Whitelist / Blacklist

Whitelisting example only showing items containing `Total` in mode `cpu`:

	X:\> .\NagiosCheckCounters.ps1 -m cpu -i Total

	OK: Queried vagrant-2012-r2 using modes [cpu] |'Cpu Total PctProcTime'=0% 'Cpu Total PctUserTime'=0% 'Cpu Total PctIdle
	Time'=98.79% 'Cpu Total PctIntrptTime'=0% 'Cpu Total PctPrivTime'=0% 'Cpu Total IntrptsSec'=199.03
	
Blacklisting example ignoring all disk instance names containing `C:` in mode `disk`:

	X:\> .\NagiosCheckCounters.ps1 -m disk -x C:

	OK: Queried vagrant-2012-r2 using modes [disk] |'PhyDsk Total DskTransfrSec'=2 'PhyDsk Total DskReadsSec'=2 'PhyDsk Tot
	al DskWritesSec'=0 'PhyDsk Total DskBytesSec'=77876.14B 'PhyDsk Total DskWriteBytesSec'=0B 'PhyDsk Total AvgDskBytesRea
	d'=38912B 'PhyDsk Total AvgDskBytesWrite'=0B
	
You can combine White- and Blackist. Whitelist items are applied **before** blacklist items.

### Sample output:

	X:\> .\NagiosCheckCounters.ps1

	OK: Queried vagrant-2012-r2 using modes [cpu mem disk net sys] |'Cpu 0 PctProcTime'=0% 'Cpu 0 PctUserTime'=0% 'Cpu 0 Pc
	tIdleTime'=97.51% 'Cpu 0 PctIntrptTime'=0% 'Cpu 0 PctPrivTime'=0% 'Cpu 0 IntrptsSec'=99.85 'Cpu 1 PctProcTime'=1.54% 'C
	pu 1 PctUserTime'=0% 'Cpu 1 PctIdleTime'=97.99% 'Cpu 1 PctIntrptTime'=0% 'Cpu 1 PctPrivTime'=1.54% 'Cpu 1 IntrptsSec'=1
	13.83 'Cpu Total PctProcTime'=0.77% 'Cpu Total PctUserTime'=0% 'Cpu Total PctIdleTime'=97.75% 'Cpu Total PctIntrptTime'
	=0% 'Cpu Total PctPrivTime'=0.77% 'Cpu Total IntrptsSec'=213.67 'MemAvailBytes'=411959296B 'MemCommtdBytes'=934420480B
	'MemSysCodeTtlBytes'=3608576B 'MemPoolNonpgdBytes'=33501184B 'MemCacheBytes'=24707072B 'MemCommitLimit'=2147012608B 'Me
	mPctCommtdBytesInUse'=43.52% 'MemPagesSec'=0 'MemPageFaultsSec'=16.97 'MemPageReadsSec'=0 'MemPageWritesSec'=0 'TtlPage
	FileUsage'=0% 'LogDsk C PctFreeSpace'=86.04% 'LogDsk C FreeBytes'=55110008832B 'PhyDsk 0C DskTransfrSec'=0 'PhyDsk 0C D
	skReadsSec'=0 'PhyDsk 0C DskWritesSec'=0 'PhyDsk 0C DskBytesSec'=0B 'PhyDsk 0C DskWriteBytesSec'=0B 'PhyDsk 0C AvgDskBy
	tesRead'=0B 'PhyDsk 0C AvgDskBytesWrite'=0B 'PhyDsk Total DskTransfrSec'=0 'PhyDsk Total DskReadsSec'=0 'PhyDsk Total D
	skWritesSec'=0 'PhyDsk Total DskBytesSec'=0B 'PhyDsk Total DskWriteBytesSec'=0B 'PhyDsk Total AvgDskBytesRead'=0B 'PhyD
	sk Total AvgDskBytesWrite'=0B 'NetInt IntelRPro1000MtDesktopAdapter BytesTtlSec'=0B 'NetInt IntelRPro1000MtDesktopAdapt
	er BytesRcvdSec'=0B 'NetInt IntelRPro1000MtDesktopAdapter BytesSentSec'=0B 'NetInt IntelRPro1000MtDesktopAdapter Packet
	sSec'=0 'NetInt IntelRPro1000MtDesktopAdapter PacketsRcvdNonUnicastSec'=0 'NetInt IntelRPro1000MtDesktopAdapter Packets
	RcvdUnicastSec'=0 'NetInt IntelRPro1000MtDesktopAdapter CurrBandwidth'=125000000B 'NetInt IntelRPro1000MtDesktopAdapter
	 PctUsage'=0% 'NetInt IntelRPro1000MtDesktopAdapter2 BytesTtlSec'=0B 'NetInt IntelRPro1000MtDesktopAdapter2 BytesRcvdSe
	c'=0B 'NetInt IntelRPro1000MtDesktopAdapter2 BytesSentSec'=0B 'NetInt IntelRPro1000MtDesktopAdapter2 PacketsSec'=0 'Net
	Int IntelRPro1000MtDesktopAdapter2 PacketsRcvdNonUnicastSec'=0 'NetInt IntelRPro1000MtDesktopAdapter2 PacketsRcvdUnicas
	tSec'=0 'NetInt IntelRPro1000MtDesktopAdapter2 CurrBandwidth'=125000000B 'NetInt IntelRPro1000MtDesktopAdapter2 PctUsag
	e'=0% 'SysProcesses'=37 'SysProcQueueLen'=0 'SysThreads'=491 'SysSystemCallsSec'=799.78 'SysFileReadOperSec'=9.98 'SysF
	ileWriteOperSec'=9.98

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




