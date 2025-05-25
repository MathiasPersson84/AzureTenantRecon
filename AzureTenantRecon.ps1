Write-Host ("`n")
Write-Host -ForegroundColor Cyan    ("               ______     _                       _____                      _   ____                       ______   ")
Write-Host -ForegroundColor Blue    ("              / / / /    / \    _____   _ _ __ __|_   _|__ _ __   __ _ _ __ | |_|  _ \ ___  ___ ___  _ __   \ \ \ \  ")
Write-Host -ForegroundColor Red     ("             / / / /    / _ \  |_  / | | | '__/ _ \| |/ _ \ '_ \ / _`  | '_ \| __| |_) / _ \/ __/ _ \| '_ \   \ \ \ \ ")
Write-Host -ForegroundColor Yellow  ("             \ \ \ \   / ___ \  / /| |_| | | |  __/| |  __/ | | | (_| | | | | |_|  _ <  __/ (_| (_) | | | |  / / / / ")
Write-Host -ForegroundColor Green   ("              \_\_\_\ /_/   \_\/___|\__,_|_|  \___||_|\___|_| |_|\__,_|_| |_|\__|_| \_\___|\___\___/|_| |_| /_/_/_/  ")
Write-Host ("`n")
Write-Host -ForegroundColor Cyan    ("                                                      Created by:")
Write-Host -ForegroundColor White   ("                                                      Mathias Persson")
Write-Host ("`n")
Write-Host -ForegroundColor Cyan    ("      DESCRIPTION")
Write-Host -ForegroundColor Blue    ("          This tool gathers passive information on a specified domain. ") 
Write-Host -ForegroundColor Blue    ("          The purpose is to provide an easy way to see if a domain is managed or federated within the Microsoft ecosystem. ")
Write-Host -ForegroundColor Blue    ("          It will also do an IP lookup to see what IPs are connected to the specified domain, what region/regions the IPs belong to as well as any associated mailservers.")
Write-Host -ForegroundColor Blue    ("          Lastly it will provide the Tenant ID for the specified domain. ")
Write-Host ("`n")
Write-Host -ForegroundColor Cyan    ("      SYNTAX")
Write-Host -ForegroundColor White   ("          Get-DomainAzureStatus")
Write-Host -ForegroundColor Blue    ("              Initiates the information gathering. The user will be prompted to enter a domain. (Example: test.com). ")
Write-Host -ForegroundColor Blue    ("              It will then try to gather information about the specified domain. ")
Write-Host ("`n")
                                                                                                                   






function Test-Domain {
    <#
        .SYNOPSIS
            Validates the syntax of a domain name, checks if it exists via DNS, and retrieves associated IPv4 and IPv6 addresses as well as associated mailserver.
    
        .DESCRIPTION
            This function takes a domain name as input, checks whether it's correctly formatted, verifies if it exists by querying DNS NS records, collects any A (IPv4) and AAAA (IPv6) DNS records associated with it, and checks associated mailservers.
            The results are returned as a custom PowerShell object containing validation status, IP addresses, and mailservers.

        .PARAMETER Domain
            The domain name to validate and check DNS records for (e.g., "example.com").

        .OUTPUTS
            PSCustomObject with the following properties:
                - Domain            : The domain name that was tested.
                - ValidFormat       : Boolean indicating if the domain's format is valid.
                - ExistsInDns       : Boolean indicating if the domain exists in DNS.
                - MailServer        : The name of the mailserver (if it exists)
                - IPv4Addresses     : An array of resolved IPv4 addresses.
                - IPv6Addresses     : An array of resolved IPv6 addresses.

        .EXAMPLE
            PS C:\> Test-Domain -Domain "microsoft.com"

                Domain          : microsoft.com
                ValidFormat     : True
                ExistsInDns     : True
                IPv4Addresses   : {20.112.0.1}
                IPv6Addresses   : {}

            This example checks "microsoft.com" for correct format, DNS existence, and resolves its IPs.

        .NOTES
            Author          : Mathias Persson
            Created         : May 25 2025
            Dependencies    : Requires internet access and the Resolve-DnsName cmdlet (available in PowerShell 5.1+ or PowerShell Core).

            
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    $ipv4 = @()
    $ipv6 = @()

    # Validate domain format
    $formatRegex = '^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$'
    $isValidFormat = $Domain -match $formatRegex

    # Check if domain exists
    $dnsExists = $false
    if ($isValidFormat) {
        try {
            $dnsResult = Resolve-DnsName -Name $Domain -Type NS -ErrorAction Stop
            $dnsExists = $true

            # Get A (IPv4) and AAAA (IPv6) addresses
            try {
                $aRecords = Resolve-DnsName -Name $Domain -Type A -ErrorAction SilentlyContinue
                if ($aRecords) {
                    $ipv4 = $aRecords | Where-Object { $_.RecordData } | Select-Object -ExpandProperty RecordData
                }
            } catch {}

            try {
                $aaaaRecords = Resolve-DnsName -Name $Domain -Type AAAA -ErrorAction SilentlyContinue
                if ($aaaaRecords) {
                    $ipv6 = $aaaaRecords | Where-Object { $_.RecordData } | Select-Object -ExpandProperty RecordData
                }
            } catch {}

            try {
                $mxResult = Resolve-DnsName -Name $Domain -Type MX -ErrorAction SilentlyContinue
                if ($mxResult) {
                    $mxServer = $mxResult | Where-Object { $_.RecordData} | Select-Object -ExpandProperty RecordData
                }
            } catch {}

        } catch {
            $dnsExists = $false
        }
    }

    # Return result
    return [PSCustomObject]@{
        Domain          = $Domain
        ValidFormat     = $isValidFormat
        ExistsInDNS     = $dnsExists
        MailServer      = $mxServer
        IPv4Addresses   = $ipv4
        IPv6Addresses   = $ipv6
    }

}


function Get-TenantId {
    <#
        .SYNOPSIS
            Retrieves the Azure AD tenant ID associated with a specified domain.
        
        .DESCRIPTION
            This function queries the OpenID Connect (OIDC) metadata endpoint for a given domain using Microsoft's login service.
            It extracts the tenant ID from the "issuer" URL in the OpenID configuration.
            This is useful for verifying whether a domain is federated with Azure AD and retrieving its unique tenant identifier.

        .PARAMETER Domain
            The domain name to retrieve the possible tenant ID for (e.g., example.com).

        .OUTPUTS
            System.String
            The Azure AD tenant ID as a string if found, otherwise $null.
        
        .EXAMPLE
            PS C:\> Get-TenantId -Domain "example.com"

            [+] Tenant ID:
            a1b2c3d4-e5f6-7890-abcd-1234567890ef

            This example retrieves the tenant ID for the domain example.com

        .NOTES
            Author          : Mathias Persson
            Created         : May 25 2025
            Dependencies    : Uses the OpenID Connect well-known endpoint provided by Microsoft. Requires internet access.

        .LINK
            https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc
    
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    # Find the tenant ID of the specified domain
    try {
        $url = "https://login.microsoftonline.com/$Domain/.well-known/openid-configuration"
        $response = Invoke-RestMethod -Uri $url -UseBasicParsing

        if ($response.issuer -match 'https://sts.windows.net/([^/]+)') {
            $tenantId = $matches[1]
            Write-Host -ForegroundColor Green ("`n[+] Tenant ID:")
            Write-Host $tenantId
            Write-Host ("")
            return $tenantId
        } else {
            Write-Host -ForegroundColor Red ("`n[-] Couldn't get Tenant ID from OpenID configuration.")
            Write-Host ("")
            return $null
        }
    } catch {
        Write-Host -ForegroundColor Red ("`n[-] Failed to get OpenID configuration.")
        Write-Host $_.Exception.Message
        return $null
    }
}


function Get-AzureDomainIpInfo {
    <#
        .SYNOPSIS
            Checks whether a domain's IP address belongs to Microsoft's IP address space and identifies its Azure region.

        .DESCRIPTION
            This function takes one or more IP addresses and performs the following steps:
            - Queries ipinfo.io to determine if the IP address is owned by Microsoft.
            - Queries Microsof's Azure Service Tags API to identify the Azure regions associated with the IP.
            - Outputs relevant metadata including IP ownership and region in the console.

        .PARAMETER ipAddresses
            An array of one or more IP addresses to be analyzed.

        .OUTPUTS
            Console output showing:
            - Whether the IP belongs to Microsoft.
            - The Azure regions (if found) associated with the IP.

        .EXAMPLE
            PS C:\> Get-AzureDomainIpInfo -ipAddresses "2603:1030:20e:3::23c"

            IP Address              : 2603:1030:20e:3::23c
            Belongs to Microsoft    : True

            [+] IP resides in the following Azure region:

            ipAddress        : 2603:1030:20e:3::23c
            cloudId          : Public
            serviceTagId     : AzureCloud.eastus
            serviceTagRegion : eastus
            addressPrefix    : 2603:1030:20e::/48
        
        .NOTES
            Author          : Mathias Persson
            Created         : May 25 2025
            Dependencies    : Uses external APIs (ipinfo.io and azservicetags.azurewebsites.net). Requires internet access.

        .LINK
            https://ipinfo.io
            https://azservicetags.azurewebsites.net
        

    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ipAddresses
    )

    if (-not $ipAddresses) {
        Write-Host -ForegroundColor Red ("[-] No IP addresses were found for the specified domain.")
        return 
    }

    # Call the Test-Domain function
    $domainInfo = Test-Domain -Domain $Domain

    # Loop through the gathered IP addresses and check them against ipinfo.io to see wether they belong to Microsoft or not, 
    Write-Host -ForegroundColor Cyan ("`n[*] Information from ipinfo.io: `n")

    foreach ($ip in $ipAddresses) {
        try {
            # Check IP info
            $ipResponse = Invoke-WebRequest -Uri "https://ipinfo.io/$ip" -UseBasicParsing
            $info = $ipResponse.Content | ConvertFrom-Json
            
            # Check what region the IP is based in
            $ipRegionResponse = Invoke-WebRequest -Uri "https://azservicetags.azurewebsites.net/api/iplookup?ipAddresses=$ip" -UseBasicParsing
            $regionInfo = $ipRegionResponse.Content | ConvertFrom-Json
            $matchedTags= $regionInfo.matchedServiceTags[0]

            $isMicrosoft = $info.Org -match "Microsoft Corporation"

            Write-Host ("`n")
            Write-Host -ForegroundColor Cyan ("IP Address               : $($info.ip)")
            Write-Host -ForegroundColor Cyan ("Belongs to Microsoft     : $isMicrosoft")
            Write-Host ("")
            Write-Host -ForegroundColor Green ("`n[+] IP resides in the following Azure region:")
            $matchedTags= $regionInfo.matchedServiceTags[0] | Out-Host
            Write-Host ("`n")
            Write-Host ("<===============>")

        } catch {
            Write-Host -ForegroundColor Red ("[-] Failed to get information from $ip : $($_.Exception.Message)")
        }
    }

}


function Get-DomainAzureStatus {
    <#
        .SYNOPSIS
            The main function of the tool. Checks if a domain is managed by Azure Active Directory and analyzes its associated IP addresses, utilizing the other functions of the tool.
            
        .DESCRIPTION
            This function:
            - Prompts the user to input a domain name.
            - Validates the domain format and existence using DNS records.
            - Queries Microsoft's "getuserrealm.srf" endpoint to determine if the domain is Managed (Azure AD), Federated (e.g., ADFS), or Unknown.
            - Collects mailservers associated with the domain.
            - Collects IPv4 and IPv6 addresses associated with the domain.
            - Determines if these IPs are owned by Microsoft and identifies their Azure regions.
            - Retrieves the tenant ID associated with the domain via Microsoft's OpenID Connect configuration.
        
        .PARAMETER None
            This function does not accept any parameters. It prompts the user for input interactively.
            
        .OUTPUTS
            - Console outpu detailing domain validation.
            - Azure AD management status.
            - IP ownership and Azure region info.
            - Tenant ID if retrievable.

        .EXAMPLE
            PS C:\> Get-DomainAzureStatus

            Submit domain to lookup. (Example: example.com): contoso.com

            PS C:\> Get-DomainAzureStatus

            Submit domain to lookup. (Example: example.com): contoso.com
            [*] Domain validation result:

            Domain        : contoso.com
            ValidFormat   : True
            ExistsInDNS   : True
            MailServer    :10 contoso-com.mail.protection.outlook.com.
            IPv4Addresses : {20.70.246.20}
            IPv6Addresses : {}

            [+] Domain is managed by Azure AD.                                                                                      

            [*] Information from ipinfo.io: 
                                                                                                                
            IP Address               : 20.70.246.20
            Belongs to Microsoft     : True

            [+] IP resides in the following Azure region:

            ipAddress        : 20.70.246.20
            cloudId          : Public
            serviceTagId     : AzureCloud.australiaeast
            serviceTagRegion : australiaeast
            addressPrefix    : 20.70.128.0/17
    
        .NOTES
            Author          : Mathias Persson
            Created         : May 25 2025
            Dependencies    : Uses several Microsoft public endpoints and third-party services. This is an interactive function intended for investigative or administrative use.

        .LINK
            https://login.microsoftonline.com/getuserrealm.srf
            https://ipinfo.io
            https://azservicetags.azurewebsites.net
            https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-whatis

    #>

    [CmdletBinding()]
    param ()

    do {
        # Ask for domain to check if it's managed by Azure
        $userRealm = Read-Host ("Submit domain to lookup. (Example: example.com)")
        $domainValidation = Test-Domain -Domain $userRealm

        # Print result of domain check
        Write-Host -ForegroundColor Green ("`n[*] Domain validation result:")
        $domainValidation | Format-List | Out-Host

        if (-not $domainValidation.ValidFormat) {
            Write-Host -ForegroundColor Red ("[-] Invalid domain format. Try again.")
        } elseif (-not $domainValidation.ExistsInDNS) {
            Write-Host -ForegroundColor Red ("[-] Domain does not exist.")
        }
    } while (-not ($domainValidation.ValidFormat -and $domainValidation.ExistsInDNS))

    try {
        # Query getuserrealm.srf endpoint 
        [xml]$xmlContent = Invoke-WebRequest -Uri "https://login.microsoftonline.com/getuserrealm.srf?login=$userRealm&xml=1" -UseBasicParsing
        
        # Return wether domain is managed by Azure or not
        $nsType = $xmlContent.DocumentElement.NameSpaceType

        switch ($nsType) {
            "Managed" {
                Write-Host -ForegroundColor Green ("[+] Domain is managed by Azure AD.")
            }
            "Federated" {
                Write-Host -ForegroundColor Yellow ("[!] Domain is federated (ADFS or similar).")
            }
            default {
                Write-Host -ForegroundColor Red ("[-] Couldn't determine domain status.")
            }
        }
    } catch {
        Write-Host -ForegroundColor Red ("[-] Failure to contact Microsoft API.")
        Write-Host $_.Exception.Message
    }

    # Combine the IPv4 and IPv6 addresses
    $allIps = @()
    if ($domainValidation.IPv4Addresses) { $allIps += $domainValidation.IPv4Addresses}
    if ($domainValidation.IPv6Addresses) { $allIps += $domainValidation.IPv6Addresses}

    # Check if IP's belong to Microsoft
    if ($allIps) {
        Get-AzureDomainIpInfo -IPAddresses $allIps
    } else {
        Write-Host -ForegroundColor Red ("[-] No IP addresses to check.")
    }

    # Get Tenant ID via OpenID configuration
    $tenantId = Get-TenantId -Domain $userRealm

    if ($tenantId) {
        # Printed in the "Get-TenantId" function
    } else {
        Write-Host -ForegroundColor Red ("`n[-] Couldn't get Tenant ID from OpenID configuration.")
    }

}


