<#
.SYNOPSIS
    Windows Audio Configurator

.DESCRIPTION
    Powershell Script to configure Windows audio devices on:
     - Audio Root Device Level
        + on driver level
     - Audio Enpoint Device Level
        + on driver level and software level

    This script is supposed to help with:
     - stopping the annoying habbit of Windows to change default audio devices
     - stopping Windows from re-enabling the NVIDIA audio endpoint on each driver update
     - getting rid of all unneeded audio endpoint entries in the Windows sound settings
     - disabling exclusive mode

    Further details and instructions will be displayed when you run this script.
    If this script is not run as admin it will automatically elevate privileges.

.EXAMPLE
    .\WindowsAudioConfigurator.ps1
#>

# Credits to Jagermeist and Tome Tanasovski
# for figuring out how to take ownership and get privileges on registry keys properly
# https://social.technet.microsoft.com/Forums/windowsserver/en-US/e718a560-2908-4b91-ad42-d392e7f8f1ad/take-ownership-of-a-registry-key-and-change-permissions
function enable-privilege
{
    param
    (
        ## The privilege to adjust. This set is taken from
        ## http://msdn.microsoft.com/en-us/library/bb530716(VS.85).aspx
        [ValidateSet(
        "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
        "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
        "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
        "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
        "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
        "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
        "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
        "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
        "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
        "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
        "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
        $Privilege,
        ## The process on which to adjust the privilege. Defaults to the current process.
        $ProcessId = $pid,
        ## Switch to disable the privilege, rather than enable it.
        [Switch] $Disable
    )

 ## Taken from P/Invoke.NET with minor adjustments.
 $definition = @'
 using System;
 using System.Runtime.InteropServices;
  
 public class AdjPriv
 {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
   ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
  
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid
  {
   public int Count;
   public long Luid;
   public int Attr;
  }
  
  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
  {
   bool retVal;
   TokPriv1Luid tp;
   IntPtr hproc = new IntPtr(processHandle);
   IntPtr htok = IntPtr.Zero;
   retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
   tp.Count = 1;
   tp.Luid = 0;
   if(disable)
   {
    tp.Attr = SE_PRIVILEGE_DISABLED;
   }
   else
   {
    tp.Attr = SE_PRIVILEGE_ENABLED;
   }
   retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
   retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
   return retVal;
  }
 }
'@

    $processHandle = (Get-Process -id $ProcessId).Handle
    $type = Add-Type $definition -PassThru
    $type[0]::EnablePrivilege($processHandle, $Privilege, $Disable)
}

Function TakeOwnershipHKLM
{
    param
    (
        [String]$subkey
    )

    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$subkey",[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::takeownership)
    $acl = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None)
    $me = [System.Security.Principal.NTAccount]"$(whoami)"
    $acl.SetOwner($me)
    $key.SetAccessControl($acl)
    $acl = $key.GetAccessControl()
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule("$(whoami)","FullControl","ContainerInherit,ObjectInherit","None","Allow")
    $acl.SetAccessRule($rule)
    $key.SetAccessControl($acl)
    $key.Close()
}

Function ToggleDefaultState
{
    param
    (
        [System.Array]$devicelist,
        [String]$headline
    )

    while($true)
    {
        $selection = 0
        Write-Host "--- $headline ---" -ForegroundColor White -BackgroundColor Black
        Write-Host ""
        Write-Host "#:`tDefault`t`tName"

        $i = 0
        foreach($ad in $devicelist)
        {
            if($ad.Default)
            {
                Write-Host "$($i):`t$($ad.Default)`t`t$($ad.FriendlyName)" -ForegroundColor Yellow -BackgroundColor Black
            }
            elseif(-not $ad.Enabled)
            {
                Write-Host "$($i):`t$($ad.Default)`t`t$($ad.FriendlyName)" -ForegroundColor Red -BackgroundColor Black
            }
            else
            {
                Write-Host "$($i):`t$($ad.Default)`t`t$($ad.FriendlyName)"
            }
            $i++
        }

        Write-Host ""
        Write-Host "Select an device to toggle it's " -NoNewline
        Write-Host "'Default'" -ForegroundColor Yellow -BackgroundColor Black -NoNewline
        Write-Host " state`r`nor hit ENTER to continue to the default device configuration: " -NoNewline
        $stringselection = Read-Host
        cls

        if(-not $stringselection)
        {
            break
        }

        [Int16]$selection = $stringselection

        if(0 -le $selection -and $selection -lt $devicelist.Count -and $devicelist[$selection].Enabled -eq $True)
        {
            $devicelist | Foreach-Object { $_.Default = $False }
            $devicelist[$selection].Default = -not $devicelist[$selection].Default
        }
    }

    return $devicelist
}

Function ToggleEnabledState
{
    param
    (
        [System.Array]$devicelist,
        [String]$headline
    )
    while($true)
    {
        $selection = 0
        Write-Host "--- $headline ---" -ForegroundColor White -BackgroundColor Black
        Write-Host ""
        Write-Host "#:`tEnabled`t`tName"

        $i = 0
        foreach($ad in $devicelist)
        {
            if($ad.Enabled)
            {
                Write-Host "$($i):`t$($ad.Enabled)`t`t$($ad.FriendlyName)" -ForegroundColor Green -BackgroundColor Black
            }
            else
            {
                Write-Host "$($i):`t$($ad.Enabled)`t`t$($ad.FriendlyName)"
            }
            
            $i++
        }

        Write-Host ""
        Write-Host "Select an audio endpoint to toggle it's " -NoNewline
        Write-Host "'Enabled'" -ForegroundColor Green -BackgroundColor Black -NoNewline
        Write-Host " state`r`nor hit ENTER to continue to the default device configuration: " -NoNewline
        $stringselection = Read-Host
        cls

        if(-not $stringselection)
        {
            break
        }

        [Int16]$selection = $stringselection

        if(0 -le $selection -and $selection -lt $devicelist.Count)
        {
            $devicelist[$selection].Enabled = -not $devicelist[$selection].Enabled
        }
    }

    return $devicelist
}

Function ToggleExclusiveMode
{
    param
    (
        [System.Array]$devicelist,
        [String]$headline
    )
    while($true)
    {
        $selection = 0
        Write-Host "--- $headline ---" -ForegroundColor White -BackgroundColor Black
        Write-Host ""
        Write-Host "#:`tExclusiveMode`t`tName"

        $i = 0
        foreach($ad in $devicelist)
        {
            if($ad.ExclusiveMode)
            {
                Write-Host "$($i):`t$($ad.ExclusiveMode)`t`t`t$($ad.FriendlyName)" -ForegroundColor Cyan -BackgroundColor Black
            }
            else
            {
                Write-Host "$($i):`t$($ad.ExclusiveMode)`t`t`t$($ad.FriendlyName)"
            }
            
            $i++
        }

        Write-Host ""
        Write-Host "Select an audio endpoint to toggle it's " -NoNewline
        Write-Host "'ExclusiveMode'" -ForegroundColor Cyan -BackgroundColor Black -NoNewline
        Write-Host " state`r`nor hit ENTER to continue to the default device configuration: " -NoNewline
        $stringselection = Read-Host
        cls

        if(-not $stringselection)
        {
            break
        }

        [Int16]$selection = $stringselection

        if(0 -le $selection -and $selection -lt $devicelist.Count)
        {
            $devicelist[$selection].ExclusiveMode = -not $devicelist[$selection].ExclusiveMode
        }
    }

    return $devicelist
}

$introHelp = @"

--- Audio Configurator ---

This script will help you configure your audio devices on Windows.
When you enable/disable audio root devices it will:
 - Enable/Disable them in the device manager on driver level

When you enable/disable audio endpoints it will:
 - Enable/Disable them in the device manager on driver level
 - Enable/Disable them in the sound settings on software level


--- Detailed Description ---

This script performs the following steps:
 - List all audio root devices and ask for enable/disable configuration
 - Enable/Disable audio root devices

 - In the following steps the script asks for input/output endpoints seperately:
     + List all audio endpoints and ask for enable/disable configuration
        --> If you disabled a device in the previous steps
            the audio endpoints of that device will not be available anymore

     + List all audio endpoints and ask for default device configuration

     + List all audio endpoints and ask for exclusive mode configuration
        --> This setting corresponds to the audio settings:
             > "Allow applications to take exclusive control of this device"
             > "Give exclusive mode applications priority"


--- Regarding NVIDIA audio root device ---

If you disable the NVIDIA audio root device, the script
will search for the system device "High Definition Audio-Controller"
located on your graphics card and disable it. This will
prevent the NVIDIA audio device being enabled again
when you update your graphics card drivers.
If you want the NVIDIA device to show up again you must
MANUALLY enabled this system device in your device manager again.

"@

# Elevate the script to admin
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))
{
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000)
    {
        Write-Warning "Not running as administrator - automatically elevating privileges..."
        $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
    }
    else
    {
        Write-Error "Cannot elevate privilegs. Please run the script as admin!"
    }
    Exit
}

cls
Write-Host $introHelp -ForegroundColor White -BackgroundColor Black
Read-Host "Press ENTER to continue"
cls

if (-not $(Get-Module -ListAvailable -Name AudioDeviceCmdlets))
{
    $url='https://github.com/frgnca/AudioDeviceCmdlets/releases/download/v3.0/AudioDeviceCmdlets.dll'
    $location = ($profile | split-path)+ "\Modules\AudioDeviceCmdlets\AudioDeviceCmdlets.dll"
    New-Item "$($profile | split-path)\Modules\AudioDeviceCmdlets" -Type directory -Force
 
    [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
    (New-Object System.Net.WebClient).DownloadFile($url, $location)
}


[System.Array]$audiodevices = @()
[System.Array]$rootdevices = @()

cls
$confirm = "n"
while($confirm -ne "y")
{
    $rootdevices = Get-PnpDevice -Class MEDIA | Where-Object { $_.Status -eq "OK" -or $_.Status -eq "Error" } | Sort-Object { $_.FriendlyName } | ForEach-Object { $_ | Add-Member -NotePropertyName Enabled -NotePropertyValue $False; $_ }
    ##########################################################################
    ### Audio root devices configuration
    ##########################################################################

    [System.Array]$rootdevices = ToggleEnabledState -headline "Audio Root Device Configuration" -devicelist $rootdevices

    ##########################################################################
    ### Enable/Disable audio root devices according to configuration
    ##########################################################################
    Write-Host "Enabling/Disabling audio root devices" -NoNewline
    
    ForEach($ad in $rootdevices)
    {
        if($ad.Enabled)
        {
            Enable-PnpDevice $ad.DeviceID -Confirm:$false
        }
        else
        {
            Disable-PnpDevice $ad.DeviceID -Confirm:$false
        }

        if($ad.FriendlyName -match "nvidia")
        {
            $GraphicsBusNumber = ((Get-PnpDeviceProperty -InstanceId "$((Get-PnpDevice -Class Display | Where-Object { $_.FriendlyName -match "nvidia" }  | Select-Object -Last 1).InstanceId)") | Where-Object { $_.KeyName -match "BusNumber" }).Data
            $HDAudioSystemDevices = Get-PnpDevice -Class System | Where-Object { $_.FriendlyName -match "High Definition" }
            $NvidiaHDAudioSystemDevice = $null
            foreach($hd in $HDAudioSystemDevices)
            {
                $hdbus = (Get-PnpDeviceProperty -InstanceId $hd.InstanceId | Where-Object { $_.KeyName -match "BusNumber" }).Data
                if($hdbus -eq $GraphicsBusNumber)
                {
                    $NvidiaHDAudioSystemDevice = $hd
                    break
                }
            }
            if($NvidiaHDAudioSystemDevice)
            {
                if($ad.Enabled)
                {
                    Enable-PnpDevice $NvidiaHDAudioSystemDevice.DeviceID -Confirm:$false
                }
                else
                {
                    Disable-PnpDevice $NvidiaHDAudioSystemDevice.DeviceID -Confirm:$false
                }
            }
        }
    }

    for($i -eq 0; $i -lt 10; $i++)
    {
        Write-Host "." -NoNewline
        Start-Sleep -s 1
    }

    Write-Host ""    

    ##########################################################################
    ### Audio endpoint devices configuration
    ##########################################################################
    Write-Host "Getting available audio endpoints..."

    cls
    
    [System.Array]$audiodevices = Get-PnpDevice -Class AudioEndpoint | Where-Object { $_.Status -eq "OK" -or $_.Status -eq "Error" } | Sort-Object { $_.FriendlyName } | ForEach-Object { $_ | Add-Member -NotePropertyName ExclusiveMode -NotePropertyValue $False; $_ | Add-Member -NotePropertyName Default -NotePropertyValue $False; $_ | Add-Member -NotePropertyName Enabled -NotePropertyValue $False; $_ }
    
    [System.Array]$outputdevices = $audiodevices | Where-Object { $_.DeviceID -match "{\d\.\d\.0\.\d*}" }
    [System.Array]$inputdevices = $audiodevices | Where-Object { $_.DeviceID -match "{\d\.\d\.1\.\d*}" }

    [System.Array]$outputdevices = ToggleEnabledState -devicelist $outputdevices -headline "Audio output device configuration"
    [System.Array]$inputdevices = ToggleEnabledState -devicelist $inputdevices -headline "Audio input device configuration"

    ##########################################################################
    ### Default audio devices configuration
    ##########################################################################
    
    [System.Array]$outputdevices = ToggleDefaultState -devicelist $outputdevices -headline "Audio output default device configuration"
    [System.Array]$inputdevices = ToggleDefaultState -devicelist $inputdevices -headline "Audio input default device configuration"

    ##########################################################################
    ### Audio endpoints exclusive mode configuration
    ##########################################################################

    [System.Array]$outputdevices = ToggleExclusiveMode -devicelist $outputdevices -headline "Audio output device Exclusive Mode configuration"
    [System.Array]$inputdevices = ToggleExclusiveMode -devicelist $inputdevices -headline "Audio input device Exclusive Mode configuration"

    ##########################################################################
    ### Configuration confirmation
    ##########################################################################
    Write-Host "--- Audio Root Device Configuration ---"
    Write-Host ""
    Write-Host "#:`tEnabled`t`tName"

    $i = 0
    foreach($ad in $rootdevices)
    {
        Write-Host "$($i):`t$($ad.Enabled)`t`t$($ad.FriendlyName)"
        $i++
    }

    Write-Host ""
    Write-Host "--- Audio Output Device Configuration ---"
    Write-Host ""
    Write-Host "#:`tEnabled`t`tDefault`t`tExclusiveMode`t`tName"

    $i = 0
    foreach($ad in $outputdevices)
    {
        Write-Host "$($i):`t$($ad.Enabled)`t`t$($ad.Default)`t`t$($ad.ExclusiveMode)`t`t`t$($ad.FriendlyName)"
        $i++
    }

    Write-Host ""
    Write-Host "--- Audio Input Device Configuration ---"
    Write-Host ""
    Write-Host "#:`tEnabled`t`tDefault`t`tExclusiveMode`t`tName"

    $i = 0
    foreach($ad in $inputdevices)
    {
        Write-Host "$($i):`t$($ad.Enabled)`t`t$($ad.Default)`t`t$($ad.ExclusiveMode)`t`t`t$($ad.FriendlyName)"
        $i++
    }

    Write-Host ""
    Write-Host "Is this configuration correct? (y/N): " -NoNewline
    $confirm = $(Read-Host).ToLower()
    cls
}


##########################################################################
### Enable/Disable Audio Endpoint devices according to configuration
##########################################################################
Write-Host "Enabling/Disabling audio endpoints..."

enable-privilege SeTakeOwnershipPrivilege > $null

ForEach($ad in $( $outputdevices + $inputdevices) )
{
    if($ad.Enabled)
    {
        Enable-PnpDevice $ad.DeviceID -Confirm:$false
    }
    else
    {
        Disable-PnpDevice $ad.DeviceID -Confirm:$false
    }

    $id = $ad.DeviceID.Substring($ad.DeviceID.LastIndexOf('.')+1).ToLower()

    $regpath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture\$($id)"

    if(-not $(Test-Path $regpath))
    {
        $regpath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render\$($id)"
    }

    [Int64]$oldvalue = (Get-ItemProperty -path $regpath -Name 'DeviceState').DeviceState
    $subkey = $($regpath.Substring($regpath.IndexOf('\')+1))
    TakeOwnershipHKLM -subkey $subkey
    if($($oldvalue -lt 268435456 -and -not $ad.Enabled) -or $($oldvalue -ge 268435456 -and $ad.Enabled))
    {
        if($oldvalue -lt 268435456 -and -not $ad.Enabled)
        {
            Set-ItemProperty -path $regpath -Name 'DeviceState' -Value $($oldvalue + 268435456)
        }
        else
        {
            Set-ItemProperty -path $regpath -Name 'DeviceState' -Value $($oldvalue - 268435456)
        }        
    }

    $subkey += "\Properties"
    TakeOwnershipHKLM -subkey $subkey

    Set-ItemProperty -path $regpath -Name '{b3f8fa53-0004-438e-9003-51a46e139bfc},3' -Value [Int16]$ad.ExclusiveMode
    Set-ItemProperty -path $regpath -Name '{b3f8fa53-0004-438e-9003-51a46e139bfc},4' -Value [Int16]$ad.ExclusiveMode
}


##########################################################################
### Default devices configuration according to config
##########################################################################
Write-Host "Configuring default state of audio devices..."
ForEach($ad in $( $outputdevices + $inputdevices) )
{
    if($ad.Default)
    {
        Set-AudioDevice $ad.DeviceID.Substring($ad.DeviceID.LastIndexOf("\")+1) > $null
    }
}


##########################################################################
### Windows Audio ducking configuration
##########################################################################
$confirm = "y"
Read-Host "Disable Windows Audio Ducking? (Y/n)"
if($confirm.ToLower() -eq "y")
{
    Write-Host "Disabling Windows Audio Ducking..."
    $regpath = "HKCU:\Software\Microsoft\Multimedia\Audio"
    Set-ItemProperty -path $regpath -Name 'UserDuckingPreference' -Value 3
}

Write-Host "Finished!"
Read-Host "Press ENTER to exit"