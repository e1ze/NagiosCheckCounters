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