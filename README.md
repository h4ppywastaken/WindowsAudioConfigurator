# WindowsAudioConfigurator
Powershell Script to configure Audio Devices on Windows (Root &amp; Endpoint Devices on Driver &amp; Software Level)

## Audio Configurator

This script will help you configure your audio devices on Windows.

When you enable/disable audio root devices it will:
 - Enable/Disable them in the device manager on driver level

When you enable/disable audio endpoints it will:
 - Enable/Disable them in the device manager on driver level
 - Enable/Disable them in the sound settings on software level


## Detailed Description

This script performs the following steps:
 - List all audio root devices and ask for enable/disable configuration
 - Enable/Disable audio root devices

 - In the following steps the script asks for input/output endpoints seperately:
     - List all audio endpoints and ask for enable/disable configuration
        + If you disabled a device in the previous steps the audio endpoints of that device will not be available anymore

     - List all audio endpoints and ask for default device configuration

     - List all audio endpoints and ask for exclusive mode configuration
        + This setting corresponds to the audio settings:
           + "Allow applications to take exclusive control of this device"
           + "Give exclusive mode applications priority"


## Regarding NVIDIA audio root device

If you disable the NVIDIA audio root device, the script
will search for the system device "High Definition Audio-Controller"
located on your graphics card and disable it. This will
prevent the NVIDIA audio device being enabled again
when you update your graphics card drivers.
If you want the NVIDIA device to show up again you must
MANUALLY enabled this system device in your device manager again.

# License
This project is licensed under the MIT License. See LICENSE file for details.
