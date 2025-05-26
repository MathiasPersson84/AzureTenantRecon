# AzureTenantRecon



               ______     _                       _____                      _   ____                       ______  
              / / / /    / \    _____   _ _ __ __|_   _|__ _ __   __ _ _ __ | |_|  _ \ ___  ___ ___  _ __   \ \ \ \ 
             / / / /    / _ \  |_  / | | | '__/ _ \| |/ _ \ '_ \ / _` | '_ \| __| |_) / _ \/ __/ _ \| '_ \   \ \ \ \
             \ \ \ \   / ___ \  / /| |_| | | |  __/| |  __/ | | | (_| | | | | |_|  _ <  __/ (_| (_) | | | |  / / / /
              \_\_\_\ /_/   \_\/___|\__,_|_|  \___||_|\___|_| |_|\__,_|_| |_|\__|_| \_\___|\___\___/|_| |_| /_/_/_/ 
                                                                                                                    



AzureTenantRecon is a PowerShell tool created for educational purpose, to showcase how one can perform passive recon on an Azure domain.
The tool validates a domain, checks if it's managed by Microsoft Azure, retrieves IP address information, identifies the Azure region, and extracts the associated tenant ID.
The tool only uses public API endpoints and websites.

---

## Features

- Validates domain format.
- Resolves DNS (NS, A, AAAA, MX) and checks domain existence.
- Checks if the domain is:
  - Managed by Azure
  - Federated (e.g., ADFS)
  - Neither managed or federated
- Gathers the mailserver associated to the domain.
- Gathers public IPv4 and IPv6 addresses for the domain.
- Checks if the IP belongs to Microsoft IP address space.
- Identifies the Azure region of the IP address via "azservicetags".
- Retrieves the Azure Tenant ID using OpenId configuration.

---

## Requirements

- PowerShell 5.1+ (or PowerShell Core 7+)
- Internet access (for API lookups)

---

## Usage

### 1. Clone the Respository
```powershell
git clone https://github.com/MathiasPersson84/AzureTenantRecon.git
cd AzureTenantRecon
```

### 2. Import the tool
```powershell
. .\AzureTenantRecon.ps1
```

### 3. Run the tool
```powershell
Get-DomainAzureStatus
```

---

## Example
```powershell
PS C:\> Get-DomainAzureStatus

            Submit domain to lookup. (Example: example.com): contoso.com

            PS C:\> Get-DomainAzureStatus

            Submit domain to lookup. (Example: example.com): contoso.com
            [*] Domain validation result:

            Domain        : contoso.com
            ValidFormat   : True
            ExistsInDNS   : True
            MailServer    : 10 contoso-com.mail.protection.outlook.com.
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
```
---

## Disclaimer

This tool relies on external APIs provided by Microsoft and ipinfo.io. Ensure you are compliant with their usage terms when using this script in production environments.

---
