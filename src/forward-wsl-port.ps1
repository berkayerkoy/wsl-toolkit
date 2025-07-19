#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Forward a Windows port to a WSL port and configure Windows Firewall.

.DESCRIPTION
    This script sets up port forwarding from Windows to WSL using netsh and creates
    appropriate Windows Firewall rules to allow traffic on the specified port.
    It can also remove existing port forwarding and firewall rules.

.PARAMETER WindowsPort
    The port on Windows that will receive traffic.

.PARAMETER WSLPort
    The port in WSL that traffic will be forwarded to.

.PARAMETER DistroName
    The name of the WSL distribution. If not specified, uses the default WSL distribution.

.PARAMETER Protocol
    The protocol to forward (TCP or UDP). Default is TCP.

.PARAMETER Remove
    Remove the port forwarding rule and firewall rule instead of creating them.

.PARAMETER FirewallRuleName
    Custom name for the firewall rule. If not specified, generates a name automatically.

.EXAMPLE
    .\forward-wsl-port.ps1 -WindowsPort 8080 -WSLPort 3000
    Forward Windows port 8080 to WSL port 3000 using TCP protocol.

.EXAMPLE
    .\forward-wsl-port.ps1 -WindowsPort 8080 -WSLPort 3000 -Protocol TCP -DistroName Ubuntu-22.04
    Forward Windows port 8080 to WSL port 3000 using TCP protocol for specific distro.

.EXAMPLE
    .\forward-wsl-port.ps1 -WindowsPort 8080 -WSLPort 3000 -Remove
    Remove the port forwarding rule for Windows port 8080.

.NOTES
    - Requires Administrator privileges
    - Requires WSL to be installed and running
    - The WSL distribution must be running for port forwarding to work
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Windows port to forward from")]
    [ValidateRange(1, 65535)]
    [int]$WindowsPort,
    
    [Parameter(Mandatory = $true, HelpMessage = "WSL port to forward to")]
    [ValidateRange(1, 65535)]
    [int]$WSLPort,
    
    [Parameter(Mandatory = $false, HelpMessage = "WSL distribution name")]
    [string]$DistroName = "",
    
    [Parameter(Mandatory = $false, HelpMessage = "Protocol to forward (TCP or UDP)")]
    [ValidateSet("TCP", "UDP")]
    [string]$Protocol = "TCP",
    
    [Parameter(Mandatory = $false, HelpMessage = "Remove port forwarding and firewall rule")]
    [switch]$Remove,
    
    [Parameter(Mandatory = $false, HelpMessage = "Custom firewall rule name")]
    [string]$FirewallRuleName = ""
)

# Function to write colored output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

# Function to get WSL IP address
function Get-WSLIPAddress {
    param([string]$DistroName)
    
    try {
        if ($DistroName) {
            $wslIP = wsl -d $DistroName -- hostname -I | ForEach-Object { $_.Trim().Split(' ')[0] }
        } else {
            $wslIP = wsl -- hostname -I | ForEach-Object { $_.Trim().Split(' ')[0] }
        }
        
        if ([string]::IsNullOrWhiteSpace($wslIP)) {
            throw "Could not retrieve WSL IP address"
        }
        
        return $wslIP.Trim()
    }
    catch {
        Write-ColorOutput "Error getting WSL IP address: $($_.Exception.Message)" "Red"
        throw
    }
}

# Function to check if WSL is running
function Test-WSLRunning {
    param([string]$DistroName)
    
    try {
        if ($DistroName) {
            $result = wsl -d $DistroName --exec echo "test" 2>&1
        } else {
            $result = wsl --exec echo "test" 2>&1
        }
        
        return $result -eq "test"
    }
    catch {
        return $false
    }
}

# Function to create firewall rule
function New-PortForwardFirewallRule {
    param(
        [int]$Port,
        [string]$Protocol,
        [string]$RuleName
    )
    
    try {
        # Check if rule already exists
        $existingRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
        
        if ($existingRule) {
            Write-ColorOutput "Firewall rule '$RuleName' already exists. Removing old rule..." "Yellow"
            Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
        }
        
        # Create inbound rule
        New-NetFirewallRule -DisplayName $RuleName `
                           -Direction Inbound `
                           -Protocol $Protocol `
                           -LocalPort $Port `
                           -Action Allow `
                           -Profile Any `
                           -Description "WSL Port Forward - Allow inbound $Protocol traffic on port $Port" | Out-Null
        
        Write-ColorOutput "Created firewall rule: $RuleName" "Green"
        return $true
    }
    catch {
        Write-ColorOutput "Error creating firewall rule: $($_.Exception.Message)" "Red"
        return $false
    }
}

# Function to remove firewall rule
function Remove-PortForwardFirewallRule {
    param([string]$RuleName)
    
    try {
        $existingRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
        
        if ($existingRule) {
            Remove-NetFirewallRule -DisplayName $RuleName
            Write-ColorOutput "Removed firewall rule: $RuleName" "Green"
            return $true
        } else {
            Write-ColorOutput "Firewall rule '$RuleName' not found" "Yellow"
            return $false
        }
    }
    catch {
        Write-ColorOutput "Error removing firewall rule: $($_.Exception.Message)" "Red"
        return $false
    }
}

# Function to create port forwarding rule
function New-PortForwardRule {
    param(
        [int]$WindowsPort,
        [int]$WSLPort,
        [string]$WSLIPAddress,
        [string]$Protocol
    )
    
    try {
        # Remove existing rule if it exists
        $existingRule = netsh interface portproxy show v4tov4 | Select-String "0.0.0.0\s+$WindowsPort"
        if ($existingRule) {
            Write-ColorOutput "Removing existing port forward rule for port $WindowsPort..." "Yellow"
            netsh interface portproxy delete v4tov4 listenport=$WindowsPort listenaddress=0.0.0.0 | Out-Null
        }
        
        # Create new port forwarding rule
        $netshCommand = "netsh interface portproxy add v4tov4 listenport=$WindowsPort listenaddress=0.0.0.0 connectport=$WSLPort connectaddress=$WSLIPAddress"
        Invoke-Expression $netshCommand | Out-Null
        
        # Verify the rule was created
        $verifyRule = netsh interface portproxy show v4tov4 | Select-String "0.0.0.0\s+$WindowsPort"
        if ($verifyRule) {
            Write-ColorOutput "Created port forwarding rule: Windows:$WindowsPort -> WSL($WSLIPAddress):$WSLPort" "Green"
            return $true
        } else {
            throw "Failed to verify port forwarding rule creation"
        }
    }
    catch {
        Write-ColorOutput "Error creating port forwarding rule: $($_.Exception.Message)" "Red"
        return $false
    }
}

# Function to remove port forwarding rule
function Remove-PortForwardRule {
    param([int]$WindowsPort)
    
    try {
        # Check if rule exists
        $existingRule = netsh interface portproxy show v4tov4 | Select-String "0.0.0.0\s+$WindowsPort"
        
        if ($existingRule) {
            netsh interface portproxy delete v4tov4 listenport=$WindowsPort listenaddress=0.0.0.0 | Out-Null
            Write-ColorOutput "Removed port forwarding rule for port $WindowsPort" "Green"
            return $true
        } else {
            Write-ColorOutput "Port forwarding rule for port $WindowsPort not found" "Yellow"
            return $false
        }
    }
    catch {
        Write-ColorOutput "Error removing port forwarding rule: $($_.Exception.Message)" "Red"
        return $false
    }
}

# Function to show current port forwarding rules
function Show-PortForwardRules {
    Write-ColorOutput "`nCurrent port forwarding rules:" "Cyan"
    netsh interface portproxy show v4tov4
}

# Main script execution
try {
    Write-ColorOutput "WSL Port Forwarding Script" "Cyan"
    Write-ColorOutput "=========================" "Cyan"
    
    # Generate firewall rule name if not provided
    if ([string]::IsNullOrWhiteSpace($FirewallRuleName)) {
        $FirewallRuleName = "WSL-PortForward-$Protocol-$WindowsPort"
    }
    
    if ($Remove) {
        Write-ColorOutput "`nRemoving port forwarding configuration..." "Yellow"
        
        # Remove port forwarding rule
        Remove-PortForwardRule -WindowsPort $WindowsPort
        
        # Remove firewall rule
        Remove-PortForwardFirewallRule -RuleName $FirewallRuleName
        
        Write-ColorOutput "`nPort forwarding removal completed!" "Green"
    }
    else {
        Write-ColorOutput "`nSetting up port forwarding..." "Yellow"
        Write-ColorOutput "Windows Port: $WindowsPort" "White"
        Write-ColorOutput "WSL Port: $WSLPort" "White"
        Write-ColorOutput "Protocol: $Protocol" "White"
        Write-ColorOutput "Distro: $(if($DistroName) { $DistroName } else { 'Default' })" "White"
        
        # Check if WSL is running
        if (-not (Test-WSLRunning -DistroName $DistroName)) {
            Write-ColorOutput "`nWSL is not running. Starting WSL..." "Yellow"
            if ($DistroName) {
                wsl -d $DistroName --exec echo "WSL Started" | Out-Null
            } else {
                wsl --exec echo "WSL Started" | Out-Null
            }
            Start-Sleep -Seconds 2
        }
        
        # Get WSL IP address
        Write-ColorOutput "`nGetting WSL IP address..." "Yellow"
        $wslIP = Get-WSLIPAddress -DistroName $DistroName
        Write-ColorOutput "WSL IP Address: $wslIP" "White"
        
        # Create firewall rule
        Write-ColorOutput "`nConfiguring Windows Firewall..." "Yellow"
        $firewallSuccess = New-PortForwardFirewallRule -Port $WindowsPort -Protocol $Protocol -RuleName $FirewallRuleName
        
        # Create port forwarding rule
        Write-ColorOutput "`nCreating port forwarding rule..." "Yellow"
        $forwardSuccess = New-PortForwardRule -WindowsPort $WindowsPort -WSLPort $WSLPort -WSLIPAddress $wslIP -Protocol $Protocol
        
        if ($firewallSuccess -and $forwardSuccess) {
            Write-ColorOutput "`nPort forwarding setup completed successfully!" "Green"
            Write-ColorOutput "You can now access your WSL service at: http://localhost:$WindowsPort" "Green"
            
            # Show current rules
            Show-PortForwardRules
        } else {
            Write-ColorOutput "`nPort forwarding setup completed with errors. Please check the output above." "Red"
            exit 1
        }
    }
    
    Write-ColorOutput "`nTips:" "Cyan"
    Write-ColorOutput "- The WSL distribution must be running for port forwarding to work" "Gray"
    Write-ColorOutput "- Port forwarding rules persist until manually removed or system restart" "Gray"
    Write-ColorOutput "- Use -Remove parameter to clean up the configuration" "Gray"
    Write-ColorOutput "- Use 'netsh interface portproxy show v4tov4' to view all port forwarding rules" "Gray"
}
catch {
    Write-ColorOutput "Script execution failed: $($_.Exception.Message)" "Red"
    exit 1
}
