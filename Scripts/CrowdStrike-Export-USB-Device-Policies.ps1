#Requires -Version 5.1
#Requires -Modules PSFalcon


<#
.SYNOPSIS
  This script will export all USB Device Policies and their respective settings from the CrowdStrike console

.DESCRIPTION
  Script that leverages the PSFalcon PowerShell module
  https://github.com/CrowdStrike/psfalcon

.INPUTS
  Users are prompted to select the appropriate CrowdStrike Cloud  
  Users must supply their clientID and secret API keys

.OUTPUTS
  Verbose logging to C:\Temp\PSFalcon\PSFalcon-Export-Configuration.log
  Exported results to C:\Temp\PSFAlcon\FalconConfig_<yyyMMdd>.zip

.NOTES
  Version:        1.2
  Script Name:    CrowdStrike-Export-USB-Device-Policies.ps1
  Author:         Kevin Elwell - Booz Allen Hamilton
  Creation Date:  4/6/2022
  Purpose/Change: Initial script development
  Credits: Luca Sturlese for the logging functions - https://github.com/9to5IT/PSLogging
           Brendan Kremian @CrowdStrike for PSFalcon and the Get-USBDevicePolicies function - https://github.com/CrowdStrike/psfalcon/wiki/Basic-Scripts#create-csvs-containing-device-control-policy-details-and-exceptions 

#>


# Import the psfalcon module - REQUIRES the PSFalcon PowerShell Module be placed in one of the PowerShell Modules directories
Import-Module -Name PSFalcon -Force -PassThru


#region Variables

# Initialize some Variables
$sLogPath = "C:\Temp\PSFalcon"
$sLogName = "PSFalcon-Export-USB-Device-Policies.log"
$sLogFile = Join-Path -Path $sLogPath -ChildPath $sLogName

#Script Version
$ScriptVersion = "1.2"

#endregion Variables



#region functions

Function Log-Start{
  <#
  .SYNOPSIS
    Creates log file

  .DESCRIPTION
    Creates log file with path and name that is passed. Checks if log file exists, and if it does deletes it and creates a new one.
    Once created, writes initial logging data

  .PARAMETER LogPath
    Mandatory. Path of where log is to be created. Example: C:\Windows\Temp

  .PARAMETER LogName
    Mandatory. Name of log file to be created. Example: Test_Script.log
      
  .PARAMETER ScriptVersion
    Mandatory. Version of the running script which will be written in the log. Example: 1.5

  .INPUTS
    Parameters above

  .OUTPUTS
    Log file created

  .NOTES
    Version:        1.0
    Author:         Luca Sturlese
    Creation Date:  10/05/12
    Purpose/Change: Initial function development

    Version:        1.1
    Author:         Luca Sturlese
    Creation Date:  19/05/12
    Purpose/Change: Added debug mode support

  .EXAMPLE
    Log-Start -LogPath "C:\Windows\Temp" -LogName "Test_Script.log" -ScriptVersion "1.5"
  #>
    
  [CmdletBinding()]
  
  Param ([Parameter(Mandatory=$true)][string]$LogPath, [Parameter(Mandatory=$true)][string]$LogName, [Parameter(Mandatory=$true)][string]$ScriptVersion)
  
  Process{
    $sFullPath = $LogPath + "\" + $LogName
      
    #Create file and start logging
    New-Item -Path $LogPath -Value $LogName -ItemType File -Force -ErrorAction SilentlyContinue
    
    Add-Content -Path $sFullPath -Value "***************************************************************************************************"
    Add-Content -Path $sFullPath -Value "Started processing at [$([DateTime]::Now)]."
    Add-Content -Path $sFullPath -Value "Running script version [$ScriptVersion]."
    Add-Content -Path $sFullPath -Value "***************************************************************************************************"
    Add-Content -Path $sFullPath -Value ""
  
    #Write to screen for debug mode
    Write-Debug "***************************************************************************************************"
    Write-Debug "Started processing at [$([DateTime]::Now)]."
    Write-Debug "***************************************************************************************************"
    Write-Debug ""
    Write-Debug "Running script version [$ScriptVersion]."
    Write-Debug ""
    Write-Debug "***************************************************************************************************"
    Write-Debug ""
  }
}

Function Log-Write{
  <#
  .SYNOPSIS
    Writes to a log file

  .DESCRIPTION
    Appends a new line to the end of the specified log file
  
  .PARAMETER LogPath
    Mandatory. Full path of the log file you want to write to. Example: C:\Windows\Temp\Test_Script.log
  
  .PARAMETER LineValue
    Mandatory. The string that you want to write to the log
      
  .INPUTS
    Parameters above

  .OUTPUTS
    None

  .NOTES
    Version:        1.0
    Author:         Luca Sturlese
    Creation Date:  10/05/12
    Purpose/Change: Initial function development
  
    Version:        1.1
    Author:         Luca Sturlese
    Creation Date:  19/05/12
    Purpose/Change: Added debug mode support

  .EXAMPLE
    Log-Write -LogPath "C:\Windows\Temp\Test_Script.log" -LineValue "This is a new line which I am appending to the end of the log file."
  #>
  
  [CmdletBinding()]
  
  Param ([Parameter(Mandatory=$true)][string]$LogPath, [Parameter(Mandatory=$true)][string]$LineValue)
  
  Process{
    Add-Content -Path $LogPath -Value $LineValue
  
    #Write to screen for debug mode
    Write-Debug $LineValue
  }
}

Function Log-Error{
  <#
  .SYNOPSIS
    Writes an error to a log file

  .DESCRIPTION
    Writes the passed error to a new line at the end of the specified log file
  
  .PARAMETER LogPath
    Mandatory. Full path of the log file you want to write to. Example: C:\Windows\Temp\Test_Script.log
  
  .PARAMETER ErrorDesc
    Mandatory. The description of the error you want to pass (use $_.Exception)
  
  .PARAMETER ExitGracefully
    Mandatory. Boolean. If set to True, runs Log-Finish and then exits script

  .INPUTS
    Parameters above

  .OUTPUTS
    None

  .NOTES
    Version:        1.0
    Author:         Luca Sturlese
    Creation Date:  10/05/12
    Purpose/Change: Initial function development
    
    Version:        1.1
    Author:         Luca Sturlese
    Creation Date:  19/05/12
    Purpose/Change: Added debug mode support. Added -ExitGracefully parameter functionality

  .EXAMPLE
    Log-Error -LogPath "C:\Windows\Temp\Test_Script.log" -ErrorDesc $_.Exception -ExitGracefully $True
  #>
  
  [CmdletBinding()]
  
  Param ([Parameter(Mandatory=$true)][string]$LogPath, [Parameter(Mandatory=$true)][string]$ErrorDesc, [Parameter(Mandatory=$true)][boolean]$ExitGracefully)
  
  Process{
    Add-Content -Path $LogPath -Value "Error: An error has occurred [$ErrorDesc]."
  
    #Write to screen for debug mode
    Write-Debug "Error: An error has occurred [$ErrorDesc]."
    
    #If $ExitGracefully = True then run Log-Finish and exit script
    If ($ExitGracefully -eq $True){
      Log-Finish -LogPath $LogPath
      Break
    }
  }
}

Function Log-Finish{
  <#
  .SYNOPSIS
    Write closing logging data & exit

  .DESCRIPTION
    Writes finishing logging data to specified log and then exits the calling script
  
  .PARAMETER LogPath
    Mandatory. Full path of the log file you want to write finishing data to. Example: C:\Windows\Temp\Test_Script.log

  .PARAMETER NoExit
    Optional. If this is set to True, then the function will not exit the calling script, so that further execution can occur
  
  .INPUTS
    Parameters above

  .OUTPUTS
    None

  .NOTES
    Version:        1.0
    Author:         Luca Sturlese
    Creation Date:  10/05/12
    Purpose/Change: Initial function development
    
    Version:        1.1
    Author:         Luca Sturlese
    Creation Date:  19/05/12
    Purpose/Change: Added debug mode support
  
    Version:        1.2
    Author:         Luca Sturlese
    Creation Date:  01/08/12
    Purpose/Change: Added option to not exit calling script if required (via optional parameter)

  .EXAMPLE
    Log-Finish -LogPath "C:\Windows\Temp\Test_Script.log"

.EXAMPLE
    Log-Finish -LogPath "C:\Windows\Temp\Test_Script.log" -NoExit $True
  #>
  
  [CmdletBinding()]
  
  Param ([Parameter(Mandatory=$true)][string]$LogPath, [Parameter(Mandatory=$false)][string]$NoExit)
  
  Process{
    Add-Content -Path $LogPath -Value ""
    Add-Content -Path $LogPath -Value "***************************************************************************************************"
    Add-Content -Path $LogPath -Value "Finished processing at [$([DateTime]::Now)]."
    Add-Content -Path $LogPath -Value "***************************************************************************************************`n"
  
    #Write to screen for debug mode
    Write-Debug ""
    Write-Debug "***************************************************************************************************"
    Write-Debug "Finished processing at [$([DateTime]::Now)]."
    Write-Debug "***************************************************************************************************"
  
    #Exit calling script if NoExit has not been specified or is set to False
    If(!($NoExit) -or ($NoExit -eq $False)){
      Exit
    }    
  }
}

Function CreateLogDir {

    If(!(Test-Path -Path $sLogPath)) {
            
        # Create C:\Temp directory
        New-Item -Path $sLogPath -ItemType Directory

        # Start logging
        Log-Start -LogPath $sLogPath -LogName $sLogName -ScriptVersion $ScriptVersion

        # Log that we are created the C:\Temp directory
        Log-Write -LogPath $sLogFile -LineValue "Created C:\Temp directory"

    }else{

        # Start logging
        Log-Start -LogPath $sLogPath -LogName $sLogName -ScriptVersion $ScriptVersion

    }

}

Function CS-Cloud {
Clear-Host

    do {
    Write-Host "`n============= SELECT THE APPROPRIATE CROWDSTRIKE CLOUD =============="
    Write-Host "`'1' for US-1 Cloud"
    Write-Host "`'2' for US-2 Cloud"
    Write-Host "`'3' for EU Cloud"
    Write-Host "`'4' for GOV Cloud"
    Write-Host "`'Q' to Quit"
    Write-Host "======================================================================="

    # Prompt user to select one of the CrowdStrike Cloud environments
    $choice = Read-Host "`nEnter Choice"

        } until (($choice -eq '1') -or ($choice -eq '2') -or ($choice -eq '3') -or ($choice -eq '4') -or ($choice -eq 'Q') )

            switch ($choice) {
                '1'{
                    Write-Host "`nYou have selected the US-1 Cloud" -ForegroundColor Green
                    $cloud = "us-1"
            }
                '2'{
                    Write-Host "`nYou have selected the US-2 Cloud" -ForegroundColor Green
                    $cloud = "us-2"
            }
                '3'{
                    Write-Host "`nYou have selected the EU Cloud" -ForegroundColor Yellow
                    $cloud = "eu-1"
            }
                '4'{
                    Write-Host "`nYou have selected the GOV Cloud" -ForegroundColor Cyan
                    $cloud = "us-gov-1"
            }
                'Q'{
                    Write-Host "`nExiting menu. Please note you MUST select one of the CrowdStrike Cloud environments." -ForegroundColor Red
                    $cloud = "quit"
                    
            }
    }

    If($cloud -ne "quit") {
        # Log that the CrowdStrike Cloud the user choose
        Log-Write -LogPath $sLogFile -LineValue "User choose the CrowdStrike $cloud Cloud."
        Return $cloud
    
    }

    If($cloud -eq "quit") {
        # Log that the user choose to quit
        Log-Write -LogPath $sLogFile -LineValue "User choose to quit the menu. Execution halting."
        Log-Finish -LogPath $sLogFile
        Break
    }

}

Function Get-USBDevicePolicies {

# Credit to Brendan Kremian @CrowdStrike
# https://github.com/CrowdStrike/psfalcon/wiki/Basic-Scripts#create-csvs-containing-device-control-policy-details-and-exceptions

[CmdletBinding(DefaultParameterSetName = 'Id')]
param(
    [Parameter(ParameterSetName = 'Id', Mandatory = $true, Position = 1)]
    [Parameter(ParameterSetName = 'Name', Mandatory = $true, Position = 1)]
    [ValidatePattern('^\w{32}$')]
    [string] $ClientId,

    [Parameter(ParameterSetName = 'Id', Mandatory = $true, Position = 2)]
    [Parameter(ParameterSetName = 'Name', Mandatory = $true, Position = 2)]
    [ValidatePattern('^\w{40}$')]
    [string] $ClientSecret,

    [Parameter(ParameterSetName = 'Id', Position = 3)]
    [Parameter(ParameterSetName = 'Name', Position = 3)]
    [ValidateSet('eu-1', 'us-gov-1', 'us-1', 'us-2')]
    [string] $Cloud,

    [Parameter(ParameterSetName = 'Id', Mandatory = $true, Position = 4)]
    [ValidatePattern('^\w{32}$')]
    [string] $Id,

    [Parameter(ParameterSetName = 'Name', Mandatory = $true, Position = 5)]
    [string] $Name,

    [Parameter(ParameterSetName = 'Id', Position = 6)]
    [Parameter(ParameterSetName = 'Name', Position = 6)]
    [ValidateScript({
        if ((Test-Path $_) -eq $false) {
            throw "Cannot find path '$_' because it does not exist."
        } elseif ((Test-Path $_ -PathType Container) -eq $false) {
            throw "'Path' must specify a folder."
        } else {
            $true
        }
    })]
    [string] $Path

)
begin {
    function Write-Output ([object] $Content, [string] $Type) {
        if ($Content) {
            $Param = @{
                Path              = Join-Path -Path $OutputFolder -ChildPath "$(Get-Date -Format FileDate)_$(
                    $Id)_$($Type).csv"
                NoTypeInformation = $true
                Append            = $true
                Force             = $true
            }
            $Content | Export-Csv @Param
        }
    }
    $OutputFolder = if (!$Path) {
        (Get-Location).Path
    } else {
        $Path
    }
    $Param = @{
        ClientId     = $ClientId
        ClientSecret = $ClientSecret
    }
    if ($Cloud) {
        $Param['Cloud'] = $Cloud
    }
    Request-FalconToken @Param
    #$VerbosePreference = 'Continue'
}
process {
    $PolicyId = if ((Test-FalconToken).Token -eq $true) {
        if ($Name) {
            try {
                Get-FalconDeviceControlPolicy -Filter "name:'$($Name.ToLower())'" -Detailed
            } catch {
                throw "No Device Control policy found matching '$($Name.ToLower())'."
            }
        } else {
            $Id
        }
    }
    if ($PolicyId) {
        foreach ($Item in (Get-FalconDeviceControlPolicy -Ids $PolicyId)) {
            $Item.settings.PSObject.Members.Where({ $_.MemberType -eq 'NoteProperty' }).foreach{
                if ($_.Name -eq 'classes') {
                    Write-Output ($_.Value | Select-Object id, action) 'classes'
                    foreach ($Exception in ($_.Value).Where({ $_.exceptions }).exceptions) {
                        Write-Output $Exception 'exceptions'
                    }
                } else {
                    $Item.PSObject.Properties.Add((New-Object PSNoteProperty($_.Name, $_.Value)))
                }
            }
            foreach ($Property in @('groups', 'settings')) {
                if ($Item.$Property -and $Property -eq 'groups') {
                    Write-Output ($Item.$Property | Select-Object id, name) $Property
                }
                $Item.PSObject.Properties.Remove($Property)
            }
            Write-Output $Item 'settings'
            Write-Output (Get-FalconDeviceControlPolicyMember -Id $PolicyId -Detailed -All |
                Select-Object device_id, hostname) 'members'
        }
    }
}

}

Function USBDevPolDetails {

    Try {

        Write-Host "Exporting detailed lists of each CrowdStrike USB Device Policy settings to $sLogPath\yyyyMMdd_<USB Device Policy ID>_Item.csv." -ForegroundColor Green
        # Log that We are exporting all of the USB Device Policies
        Log-Write -LogPath $sLogFile -LineValue "Exporting detailed lists of each CrowdStrike USB Device Policy settings to $sLogPath\yyyyMMdd_<USB Device Policy ID>_Item.csv."

            # Exporting detailed lists of each CrowdStrike USB Device Policy settings to a .CSV
            USBDevPolList -csvOutDir $sLogPath

            # Get all Falcon USB device policies
            $fusbdevpols = Get-FalconDeviceControlPolicy -Detailed

                # Get user USB device policy metadata
                $ids = $fusbdevpols.id
                    ForEach($id in $ids) {
    
                        # Export all USB Device Policy Classes, Exceptions, Groups, and Settings
                        Get-USBDevicePolicies -ClientId $clientid -ClientSecret $secret -Cloud $cloudenv -id $id -Path $sLogPath
    
            }

    } catch {
    
    Write-Host "`n`rERROR! Exporting detailed lists of each CrowdStrike USB Device Policy settings to $sLogPath\yyyyMMdd_<USB Device Policy ID>_Item.csv was unsuccessful. Exiting." -ForegroundColor Red
    # Log that a token was NOT received
    Log-Error -LogPath $sLogFile -ErrorDesc "Exporting detailed lists of each CrowdStrike USB Device Policy settings to $sLogPath\yyyyMMdd_<USB Device Policy ID>_Item.csv was unsuccessful. Exiting." -ExitGracefully $True
    Break

    }
    Return $True
    
}

Function USBDevPolList {

[CmdletBinding()]
  
  Param ([Parameter(Mandatory=$true)][string]$csvOutDir)

  Try {
  
    Write-Host "Exporting a list of all the CrowdStrike USB Device Policies to $sLogPath\Falcon-USB-Device-Policies.csv" -ForegroundColor Green
    # Log that We are exporting all of the USB Device Policies
    Log-Write -LogPath $sLogFile -LineValue "Exporting a list of all the CrowdStrike USB Device Policies to $sLogPath\Falcon-USB-Device-Policies.csv."

        # Get all Falcon USB device policies
        $fusbdevpols = Get-FalconDeviceControlPolicy -Detailed

            # Get user USB device policy metadata
            $fusbdevpols | ForEach-Object {
    
                $fusbInfo =[pscustomobject]@{
                    'Policy ID' = $_.id
                    'Policy Name' = $_.name
                    'Policy Description' = $_.description
                    'Policy OS Target' = $_.platform_name
                    'Policy Assigned Groups' = $_.groups
                    'Policy Enabled' = $_.enabled
                    'Policy Author' = $_.created_by
                    'Policy Creation Timestamp' = $_.created_timestamp
                    'Policy Modified By' = $_.modified_by
                    'Policy Modified Timestamp' = $_.modified_timestamp
        
            }

            $fusbInfo | Export-CSV $csvOutDir\Falcon-USB-Device-Policies.csv -Append -NoTypeInformation -Force -NoClobber
        }

  } Catch {
  
  Write-Host "`n`rERROR! Exporting a list of all the CrowdStrike USB Device Policies to $sLogPath\Falcon-USB-Device-Policies.csv was unsuccessful. Exiting." -ForegroundColor Red
  # Log that a token was NOT received
  Log-Error -LogPath $sLogFile -ErrorDesc "Exporting a list of all the CrowdStrike USB Device Policies to $sLogPath\Falcon-USB-Device-Policies.csv was unsuccessful. Exiting." -ExitGracefully $True
  Break

  }

}

#endregion functions

# Create the log directory if it does not already exist
CreateLogDir

# Prompt the user for the CrowdStrike Cloud environment
$cloudenv = CS-Cloud

# Prompt for the API clientid and secret
$clientid = Read-Host -Prompt 'INPUT YOUR CLIENT ID API KEY'
$secret = Read-Host -Prompt 'INPUT YOUR API SECRET'

# Force TLS 1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# Request an oAUTH2 token
$token = Request-FalconToken -ClientId $clientid -ClientSecret $secret -Cloud $cloudenv -ErrorAction SilentlyContinue

    #Validate if the token was received
    if ((Test-FalconToken -ErrorAction SilentlyContinue).token -eq $true) {
            
        Write-Host "`n`rToken received. Proceeding.`n`r" -ForegroundColor Green
        # Log that a token was received
        Log-Write -LogPath $sLogFile -LineValue "Token received successfully."
	
    }else{

	    Write-Host "`n`rERROR! A token was NOT received!`n`r" -ForegroundColor Red
        # Log that a token was NOT received
        Log-Error -LogPath $sLogFile -ErrorDesc "Token was NOT received successfully." -ExitGracefully $True
	    Break
    }	



    If(USBDevPolDetails) {

        Write-Host "`n`rThe CrowdStrike USB Device Policies were successfully exported.`n`r" -ForegroundColor Green
        # Log that a token was received
        Log-Write -LogPath $sLogFile -LineValue "The CrowdStrike USB Device Policies were successfully exported."
        # Finalize the log
        Log-Finish -LogPath $sLogFile

    }else{

    	Write-Host "`n`rERROR! The CrowdStrike USB Device Policies were NOT successfully exported!`n`r" -ForegroundColor Red
        # Log that a token was NOT received
        Log-Error -LogPath $sLogFile -ErrorDesc "The CrowdStrike USB Device Policies were NOT successfully exported." -ExitGracefully $True
	    Break

    }


