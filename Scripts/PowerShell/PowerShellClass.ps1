[string]$number = Read-Host "Enter and interger"
$number = $number + 10
$number

<#
Exercise 4-3, Syntactical Exercise:
Invoke-WmiMethod

Start a notepad process normally and use Invoke-WmiMethod to stop the process.
Rubric
• Use the Invoke-WmiMethod command
• Stop the notepad process that was started
#>
Get-WmiObject -Class Win32_Process -Filter "name='notepad.exe'" | Invoke-WmiMethod -name Terminate
###############################################################
<#
Exercise 4-4, Syntactical Exercise:
Get-CimInstance -Filter

End State
List all of the processes with a WorkingSetSize that is greater than 100MB
and print only the Name, Handle, and WorkingSetSize.
Rubric

• Use the Get-CimInstance command with the -Filter flag
• List all processes with a working set greater than 100MB
• Print just the Name, Handle, and WorkingSetSize of the processes
#>

Get-CimInstance -ClassName Win32_Process -Filter "WorkingSetSize>$(100*102400)" | Select-Object Name, Handle, WorkingSetSize

#############################################
<#
Exercise 4-5, Syntactical Exercise:
Invoke-CimMethod 
#>


###########################################
<#
Exercise 5-1, Syntactical Exercise:
WMIC, Aliases

End State
Retrieve a list of local storage devices on the system.
Output must contain only the “core set” (or main) properties of the class
representative of local storage devices.
Rubric
• Retrieve a list of local storage devices
• Output must contain only the “core set” of properties of the local storage devices’ class
#>
wmic diskdrive list brief
############################################
#Win10
Set-NetConnectionProfile -InterfaceAlias Ethernet -NetworkCategory Private

Enable-PSRemoting -skippnetworkprofilecheck

netsh advfirewall firewall set rule group="remote administration" new enable=yes

#Win7
net start winmgmt

netsh advfirewall firewall set rule group="remote administration" new enable=yes

############################################
wmic /node:<COMPUTERNAME> /user:<USERNAME> `<DESIRED WMIC SYNTAX>

wmic /node:10.10.0.10 /user:Administrator path Win32_
Process get /value
##########################################
<#
Exercise 5-3, Practical Exercise: WMIC,
Remoting, Format

Background
You are a penetration tester looking for a way to create a custom exploit
for a system (“PR Win10” VM). Therefore, you need to gather technical
information on its hardware, specifically the processor, which you then will
forward to your supporting exploit developers. They expect this technical
information in a CSV format so they can easily access the data. You
decide to use WMIC to retrieve this information. You know the class you
need will be the Win32_Processor class, and the information (properties)
you need will consist of the following: DeviceID, Name, Caption,
AddressWidth, L2CacheSize, L3CacheSize, NumberOfEnabledCore, and
NumberOfLogicalProcessors.
#>

wmic /node:x.x.x.x /user:Administrator path Win32_processor get DeviceID, Name, Caption, AddressWidth, L2CacheSize, L3CacheSize, NumberOfLogicalProcessors, NumberOfenabledCore /format:csv > ./Desktop/processor.csv

###########################################

<#
Exercise 5-4, Syntactical Exercise:
WMIC, Where

End State
Retrieve a list of local storage devices on a remote system (“PR Win10” VM).
Have the list contain only the instance that has a DeviceID of “C:”
Output this in a readable format.
Rubric
• Retrieve a list of local storage devices on a remote system
• Filter list to just the instance with the DeviceID of “C:”
• Output is in a readable format
#>

wmic /node:x.x.x.x /user:Administrator path Win32_logicaldisk where "DeviceID-'C:'" get DeviceID, DriveType, FreeSpace, ProviderName, Size, VolumeName

############################################

<#
Exercise 5-5, Syntactical Exercise:
WMIC, Where

End State
Retrieve a set of specific running services from the system.
The running services’ names should start with the letter “W” and should
have a StartMode of Auto.
Output only the “Name” and “State” properties for those services.
Rubric
• Retrieve a list of running services with names beginning with “W”
• Output only the “Name” and “State” properties of those services
#>

wmic /node:10.10.0.10 /user:Administrator Service where "name like 'W%' AND state='Running' startmode='Auto'" get Name, State

#########################################
<#
Exercise 5-6, Syntactical Exercise:
PowerShell Analogs

Redo Module 5 Exercise 4, but using PowerShell.
Retrieve a set of specific running services from the system.
The running services’ names should start with the letter “W” and should
have a StartMode of Auto.
Output only the “Name” and “State” properties for those services.
Rubric
• Use PowerShell
• Retrieve a list of running services with names beginning with “W”
• Output only the “Name” and “State” properties of those services
#>

##############################################

<#
Test Examples
#>

