function Get-FreeSpace {
    
    Get-WmiObject -Class Win32_logicaldisk -Filter "FreeSpace>$(300000000000)" | select-object DeviceID, FreeSpace, VolumeName | Sort-Object VolumeName
    
    
}
Export-ModuleMember -Function Get-FreeSpace