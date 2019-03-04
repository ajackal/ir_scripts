function postResultsToSplunk($input_type, $input_content)
{
    echo "[*] sending information to Splunk..."
    # Function builds the objects necessary to send results to Splunk's HTTP Event Collector.
    $data_to_send = New-Object psobject -Property @{
        'InputType' = $input_type;
        'InputContent' = $input_content
    }
    $token = "91C89412-C607-48FE-B0CC-7042A5548A67"
    $headers = @{"Authorization" = "Splunk $token"}
    $body = @{
        "host" = $env:COMPUTERNAME;
        "source" = "IR-triage-script";
        "sourcetype" = "IR-RESTapi";
        "index" = "main";
        "event" = @{
                "case_number" = "EJDIE34500";
                "type" = $input_type
                "info" = $input_content;
            } 
    }

    $json_body = ConvertTo-Json -InputObject $body -Compress
    Invoke-RestMethod -Method POST -Uri "http://192.168.1.50:8088/services/collector/event" -Headers $headers -ContentType "application/json" -Body $json_body
    
}


function powerShell5Cmdlets()
{
    # Checks PowerShell version, if 5.0 runs the new cmdlets, otherwise runs legacy (WMI) cmdlets.
    if ($PSVersionTable.PSVersion.Major -eq 5)
    {
          
        try
        {
            # Dumps Local User Accounts, whether they are enabled and a description (if given):
            $local_users = Get-LocalUser | Select-Object *
                
        } catch {
            
            $local_users = "Error running Get-LocalUser cmdlet."
        } 

        $local_users | ForEach-Object{ postResultsToSplunk 'LocalUsers' $_ }    
        
        try
        {
            # Grabs all network connection profiles information
            $network_profile = Get-NetConnectionProfile

        } catch {
            
            $network_profile = "Error running Get-NetConnectionProfile cmdlet."
        }    

        $network_profile | ForEach-Object{ $_ | Select-Object * | ConvertTo-Json -Compress; postResultsToSplunk 'NetworkProfile' $_ }
         
        try
        {
            # Dumps current DNS cache; very volitale.
            $dns_cache = Get-DnsClientCache

        } catch {
            
            $dns_cache = "Error running Get-DnsClientCache cmdlet."
        }
        
        $dns_cache | ForEach-Object{ $_ | Select-Object * | ConvertTo-Json -Compress; postResultsToSplunk 'DnsClientCache' $_ }
    
        
        try
        {
            # Gets DNS Server Address for each interface.
            $dns_server_address = Get-DnsClientServerAddress

        } catch {
            
            $dns_server_address = "Error running Get-DnsClientServerAddress cmdlet."
        }

        $dns_server_address | ForEach-Object{ $_ | Select-Object * | ConvertTo-Json -Compress; postResultsToSplunk 'DnsClientServerAddress' $_ }

    } else {
    
        
        try
        {
            # Gets Local Accounts of the computer using the legacy WMI Objects:
            $local_users_wmi = Get-WmiObject -class Win32_UserAccount -Filter "LocalAccount='True'" | Select-Object PsComputername, Name, Status, Disabled, AccountType, Lockout, PasswordRequired, PasswordChangeable, SID

        } catch {
            
            $local_users_wmi = "Errorr running legacy Local User (WMI) cmdlet."
        }

        $local_users_wmi | ForEach-Object{ $_ | Select-Object * | ConvertTo-Json -Compress; postResultsToSplunk 'LocalUsers' $_ }

        
        try
        {
            # Gets Computer Hardware information & Last Logged In User information:
            $computer_system_info = Write-Output "`nComputerName`t`t: $env:computername"; Get-WmiObject -computer $env:computername -class win32_computersystem | Select-Object Username, Domain, Manufacturer, Model, SystemType, PrimaryOwnerName, TotalPhysicalMemory

        } catch {

            $computer_system_info = "Error running legacy Computer System Information (WMI) cmdlet."
        }
        
        $computer_system_info | ForEach-Object{ $_ | Select-Object * | ConvertTo-Json -Compress; postResultsToSplunk 'ComputerSystemInformation' $_ }

        
        try
        {
            # Gets current ip config settings including DNS and Default Gateway settings & converts to JSON:
            $ip_dns_config = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.ipaddress -notlike $null} | Select-Object PSComputerName, IPAddress, IPSubnet, DefaultIPGateway, Description, DHCPEnabled, DHCPServer, DNSDomain, DNSDomainSuffixSearchOrder, DNSServerSearchOrder, WINSPrimaryServer, WINSSecondaryServer
            $ip_dns_config = $ip_dns_config | Select-Object * |  ForEach-Object {$_.IPaddress = $_.IPAddress.Replace("\{",""); $_.DefaultIPGateway = $_.DefaultIPGateway.Replace("\{",""); $_.IPSubnet = $_.IPSubnet.Replace("\{",""); $_}

        } catch {
            
            $ip_dns_config = "Error running legacy IP/DNS Config (WMI) cmdlet."
        }
        
        $ip_dns_config | ForEach-Object{ $_ | Select-Object * | ConvertTo-Json -Compress; postResultsToSplunk 'IpDnsConfig' $_ }
    }
}


function unprivilegedCmdlets()
{
    
    try
    {
        # Gets the current list of services, both running and stopped:
        $services = Get-Service

    } catch {
        
        $services = "Error running Get-Service cmdlet."
    }
    
    $services | ForEach-Object{ $_ | Select-Object * | ConvertTo-Json -Compress; postResultsToSplunk 'Services' $_ }


    
    try
    {
        # Grabs installed software.
        $registry_software = Get-ChildItem "HKLM:\Software"

    } catch {
        
        $registry_software = "Error running Get-ChildItem on HKLM:\Software registry key."
    }
    
    $registry_software | ForEach-Object{ $_ | Select-Object * | ConvertTo-Json -Compress; postResultsToSplunk 'RegistrySoftware' $_ }


    
    try
    {
        # Grabs System information from the Registry
        $registry_system = Get-ChildItem "HKLM:\System"

    } catch {
        
        $registry_system = "Error running Get-ChildItem on HKLM:\System registry key."
    }
    
    $registry_system | ForEach-Object{ $_ | Select-Object * | ConvertTo-Json -Compress; postResultsToSplunk 'RegistrySystem' $_ }


    
    $tasks = @()
    function getTasks($path) 
    {
        # Function & required COM object to retrieve all scheudled tasks:
        $out = @()

        $schedule.GetFolder($path).GetTasks(0) | ForEach-Object {
            $xml = [xml]$_.xml
            $out += New-Object psobject -Property @{
                "Name" = $_.Name
                "Path" = $_.Path
                "LastRunTime" = $_.LastRunTime
                "NextRunTime" = $_.NextRunTime
                "Actions" = ($xml.Task.Actions.Exec | ForEach-Object {"$($_.Command) $($_.Arguments)"})
            }
        }

        $schedule.GetFolder($path).GetFolders(0) | ForEach-Object {
            $out += getTasks($_.Path)
        }

        $out
    }

    try
    {
        $schedule = New-Object -ComObject "Schedule.Service"
        $schedule.Connect()

        $tasks += getTasks("\")
    } catch {
        $tasks = "Error retrieving Scheduled Tasks list."
    }
    $tasks | ForEach-Object{ $_ | Select-Object * | ConvertTo-Json -Compress; postResultsToSplunk 'ScheduledTasks' $_ }


    # Get PowerShell Transcriptions from C:\temp\PowerShellLogs
    try
    {
        $default_transcription_path = 'C:\temp\PowerShellLogs'
        $transcription_file_path = Get-ItemProperty "HKLM:\software\Policies\Microsoft\Windows\PowerShell\Transcription" | Select-Object -ExpandProperty OutputDirectory
        if (Test-Path -Path $default_transcription_path)
        {
            $ps_transcription_logs = Get-ChildItem C:\temp\PowerShellLogs\ | ForEach-Object{Get-Content C:\temp\PowerShellLogs\$_}

        } 
        elseif ($transcription_file_path -ne $default_transcription_path)
        {
            $ps_transcription_logs = Get-ChildItem $transcription_file_path | ForEach-Object{Get-Content $transcription_file_path\$_}

        } else {
            $ps_transcription_logs = "[!] Error: PowerShell Log directory doesn't exist."
        }
    } catch {

        $ps_transcription_logs = "Error retrieving PowerShell Transcription logs. Is Transcription enabled on this machine?"
    }
    
    $ps_transcription_logs | ForEach-Object{ $_ | Select-Object * | ConvertTo-Json -Compress; postResultsToSplunk 'PowerShellTranscriptionLogs' $_ }


    
    try
    {
        # Write PowerShell log metadata:
        $getScriptBlockLog = Get-WinEvent -FilterHashTable @{ 
            LogName = "Microsoft-Windows-PowerShell/Operational"; 
            ID = 4102, 4103, 4104
        }
    } catch {
        
        $getScriptBlockLog = "Error retrieving Deep Script Block logs."
    }
    
    $getScriptBlockLog | ForEach-Object{ $_ | Select-Object * | ConvertTo-Json -Compress; postResultsToSplunk 'PowerShellLogs' $_ }
    
    # Prints the detailed Script Block Log message of each event.
    # $getScriptBlockLog.Message
    
    try
    {
        # Write New Process Creation log metadata:
        $newProcessCreation = Get-WinEvent -FilterHashTable @{ 
            LogName = "Security"; 
            ID = 4688
        }
    } catch {

        $newProcessCreation = "Error retrieving New Process Creation (ID=4688) from Security logs."
    }
    
    $newProcessCreation | ForEach-Object{ $_ | Select-Object * | ConvertTo-Json -Compress; postResultsToSplunk 'WinEventLogsSecurity' $_}
    
    # Prints the detailed message for each event.
    # $newProcessCreation.Message

    # Gets a list of drives configured &or connected to the machine.
    try
    {
        $drives = Get-PSDrive

    } catch {
        
        $drives = "Error getting drives list."
    }
    
    $drives | ForEach-Object{ $_ | Select-Object * | ConvertTo-Json -Compress; postResultsToSplunk 'PSDrive' $_ }
}


### REQUIRES ELEVATED PRIVILEGES ###

function privilegedCmdlets(){
    # TODO: Find the WMI Object to retreive this information so it will parse correctly in Splunk.
    # Grabs Network Statistics for all connections. Requires Elevated Privileges.
    try
    {
        $network_connections_object = @()
        $network_connections = netstat.exe -ano | Select-String -Pattern "established", "listening"
        foreach ($line in $network_connections)
        {
            # Formatting flat netstat.exe results into a PowerShell Object
            # Remove leading whitespace.
            $line = $line -replace '^\s+',''

            # Split each line by the whitespace.
            $line = $line -split '\s+'

            $ProcessIDName = Get-Process -Id $line[4] | Select-Object -Property ProcessName

            # Define the properties for each Object.
            $properties = @{
                Protocol = $line[0]
                LocalAddressIP = ($line[1] -split ":")[0]
                LocalAddressPort = ($line[1] -split ":")[1]
                ForeignAddressIP = ($line[2] -split ":")[0]
                ForeignAddressPort = ($line[2] -split ":")[1]
                State = $line[3]
                ProcessIDNumber = $line[4]
                ProcessIDName = $ProcessIDName.ProcessName
            }
            # echo $properties
            $network_connections_object += New-Object -TypeName PSObject -Property $properties
        }

    } catch {

        $network_connections_object = "Error retrieving network connection information."
    }
    
    $network_connections_object | ForEach-Object{ $_ | Select-Object * | ConvertTo-Json -Compress; postResultsToSplunk 'NetworkConnections' $_ }
        
    # OR
    # Not sure if I can identify the owning process with the PowerShell Module.
    # Doesn't appear that I can get the Owning Process from this module.
    # Get-NetTCPConnection
    # Lists directory information for the currently logged in user:

    try
    {
        # DO without option -Hidden for the viewable stuff, do with option -Hidden to see Hidden folders only!
    
        $user_filepath = "C:\Users\$env:USERNAME"

        $user_folder = Get-ChildItem $user_filepath

        $user_subfolders = $user_folder | ForEach-Object{ Get-ChildItem $user_filepath/$_ }

        #Use to get recursion and to get file hashes
        Get-ChildItem | %{ if($_.Mode -like "d*"){ echo "$_ is a directory!"}

    } catch {
        
        $user_subfolders = "Error getting the directory listing of the user directory and/or subdirectories." 
    }
    
    $user_subfolders | ForEach-Object{ $_ | Select-Object * | ConvertTo-Json -Compress; postResultsToSplunk 'UserSubFolders' $_ }
    


    # Gets a list of the running processes and what program started that process.
    # -IncludeUserName option requires Elevated Privileges
    try
    {
        $process_list = Get-Process -IncludeUserName

    } catch {
        
        $process_list = "Error running Get-Process cmdlet with -IncludeUserName option. Were you running as Admin?"
    }
    
    $process_list | ForEach-Object{ $_ | Select-Object * | ConvertTo-Json -Compress; postResultsToSplunk 'Processes' $_ }


    # Grabs the directory listing of the Prefetch
    # Must be run with Elevated Privileges
    try
    {
        $prefetch_listing = Get-ChildItem -Hidden C:\Windows\Prefetch

    } catch {

        $prefetch_listing = "Error retrieving the prefetch directory listing."
    }
    
    $prefetch_listing | ForEach-Object{ $_ | Select-Object * | ConvertTo-Json -Compress; postResultsToSplunk 'Prefetch' $_ }

}


# get NTUSER.dat

function main()
{
    # Calls function containing PowerShell 5 only commands, or if running < 5.0 their WMI equivalents
    try
    {
        echo "trying powershell 5 commands..."
        powerShell5Cmdlets

    } catch {

        $error = "Error running powerShell5Cmdlets."
        echo $error
        postResultsToSplunk 'ERROR' $error
    }

    # Runs all the cmdlets that don't required elevated privileges
    try
    {
        echo "trying unprivileged cmdlets..."
        unprivilegedCmdlets

    } catch {
        
        $error = "Error running unprivilegedCmdlets."
        postResultsToSplunk 'ERROR' $error
    }

    # Checks to see if the script is running with elevated privileges and executes the privilegedCmdlets if True
    if( ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
         [Security.Principal.WindowsBuiltInRole]"Administrator")){
         
         try
         {
             echo "running as an administrator; trying privileged cmdlets...."
             privilegedCmdlets

         } catch {

            $error = "Error running privilegedCmdlets."
            postResultsToSplunk 'ERROR' $error
         }

    } else {

        $no_admin = "Script not running as an administrator, skipping privilegedCmdlets"
        postResultsToSplunk 'ERROR' $no_admin
    }
    

}

main