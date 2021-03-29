function Get-RunningService {
    
    Get-Service | Where-Object {$_.status -eq 'Running'} | Select-Object Name, DisplayName | Sort-Object -Property DisplayName
}