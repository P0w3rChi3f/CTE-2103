$password =  ConvertTo-SecureString "baseball" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("Adminstrator", $password)
invoke-command -ComputerName 192.1968.77.153 -Credential $creds {get-process -Name notepad | stop process}
################################################################################################
wmic /user:Administrator /node:192.168.77.153 /password:baseball  process where "Name='notepad.exe'" terminate