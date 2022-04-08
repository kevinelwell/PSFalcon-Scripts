#Requires -Version 5.1
#Requires -Modules PSFalcon


<#
.SYNOPSIS
  This script will export all configurations from the CrowdStrike console

.DESCRIPTION
  Script that leverages the PSFalcon PowerShell module
  https://github.com/CrowdStrike/psfalcon

.INPUTS
  Users are prompted to select the appropriate CrowdStrike Cloud  
  Users must supply their clientID and secret API keys

.OUTPUTS
  Verbose logging to C:\Temp\PSFalcon\PSFalcon-Export-Configuration.log
  Exported results to C:\Temp\PSFalcon\FalconConfig_<yyyMMdd>.zip

.NOTES
  Version:        1.2
  Script Name:    CrowdStrike-Export-Configuration.ps1
  Author:         Kevin Elwell - Booz Allen Hamilton
  Creation Date:  4/6/2022
  Purpose/Change: Initial script development
  Credits: Luca Sturlese for the logging functions - https://github.com/9to5IT/PSLogging

#>


# Import the psfalcon module - REQUIRES the PSFalcon PowerShell Module be placed in one of the PowerShell Modules directories
Import-Module -Name PSFalcon -Force -PassThru


#region Variables

# Initialize some Variables
$sLogPath = "C:\Temp\PSFalcon"
$sLogName = "PSFalcon-Export-Configuration.log"
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
            
        # Create C:\Temp\PSFalcon directory
        New-Item -Path $sLogPath -ItemType Directory

        # Start logging
        Log-Start -LogPath $sLogPath -LogName $sLogName -ScriptVersion $ScriptVersion

        # Log that we are created the C:\Temp\PSFalcon directory
        Log-Write -LogPath $sLogFile -LineValue "Created $sLogPath directory"

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

    # Change directory into C:\Temp\PSFalcon
    cd $sLogPath

    # Get todays date into the yyyyMMdd format
    $date = $(Get-Date -Format "yyyyMMdd")

    # Test if the FalconConfig_date.zip file exists
    If(Test-Path -Path $sLogPath\FalconConfig_$date.zip -PathType Leaf) {

        Write-Host "The file $sLogPath\FalconConfig_$date.zip exists." -ForegroundColor Green
        
        # Remove the existing file
        Remove-Item -Path $sLogPath\FalconConfig_$date.zip -Force
}


    If(Export-FalconConfig) {

        Write-Host "`n`rThe Falcon configurations were successfully exported.`n`r" -ForegroundColor Green
        # Log that a token was received
        Log-Write -LogPath $sLogFile -LineValue "The Falcon configurations were successfully exported."
        # Finalize the log
        Log-Finish -LogPath $sLogFile

    }else{

    	Write-Host "`n`rERROR! The Falcon configurations were NOT successfully exported!`n`r" -ForegroundColor Red
        # Log that a token was NOT received
        Log-Error -LogPath $sLogFile -ErrorDesc "The Falcon configurations were NOT successfully exported." -ExitGracefully $True
	    Break

    }


