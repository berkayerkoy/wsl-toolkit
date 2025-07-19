#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Install WSL distribution from a local tar file or download URL.

.DESCRIPTION
    This script installs a WSL distribution from either a local tar file path or a download URL.
    It will automatically update the distribution after installation and clean up downloaded files if applicable.

.PARAMETER DistroName
    The name for the WSL distribution instance.

.PARAMETER WSLRootPath
    The root path where the WSL distribution will be installed.

.PARAMETER TarFilePath
    Path to a local tar file. If provided, the script will install from this file.

.PARAMETER DownloadUrl
    URL to download the tar file from. Used only if TarFilePath is not provided.

.PARAMETER SkipUpdate
    Skip the automatic update of the distribution after installation.

.EXAMPLE
    .\import-wsl.ps1 -DistroName "MyUbuntu" -WSLRootPath "C:\WSL" -TarFilePath "C:\Downloads\ubuntu.tar" -Username "john"

.EXAMPLE
    .\import-wsl.ps1 -DistroName "MyUbuntu" -WSLRootPath "C:\WSL\MyUbuntu" -DownloadUrl "https://example.com/ubuntu.tar.gz" -Username "john"

.EXAMPLE
    .\import-wsl.ps1 -DistroName "MyUbuntu" -WSLRootPath "C:\WSL" -TarFilePath "C:\Downloads\ubuntu.tar"

.EXAMPLE
    $securePassword = ConvertTo-SecureString "MyPassword123" -AsPlainText -Force
    .\import-wsl.ps1 -DistroName "MyUbuntu" -WSLRootPath "C:\WSL" -TarFilePath "C:\Downloads\ubuntu.tar" -Username "john" -Password $securePassword

.NOTES
    - Requires Administrator privileges
    - Requires WSL to be enabled on the system
    - Internet connection required if downloading from URL
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Name for the WSL distribution instance")]
    [ValidateNotNullOrEmpty()]
    [string]$DistroName,
    
    [Parameter(Mandatory = $true, HelpMessage = "Root path where the WSL distribution will be installed")]
    [ValidateNotNullOrEmpty()]
    [string]$WSLRootPath,
    
    [Parameter(Mandatory = $false, HelpMessage = "Path to local tar file")]
    [string]$TarFilePath,
    
    [Parameter(Mandatory = $false, HelpMessage = "URL to download tar file from")]
    [string]$DownloadUrl,
    
    [Parameter(Mandatory = $false, HelpMessage = "Username to create in the distribution")]
    [ValidateNotNullOrEmpty()]
    [string]$Username = "wsluser",
    
    [Parameter(Mandatory = $false, HelpMessage = "Password for the user (if not provided, will prompt interactively)")]
    [SecureString]$Password,
    
    [Parameter(Mandatory = $false, HelpMessage = "Skip automatic update after installation")]
    [switch]$SkipUpdate
)

# Validate parameters
if ([string]::IsNullOrWhiteSpace($TarFilePath) -and [string]::IsNullOrWhiteSpace($DownloadUrl)) {
    throw "Either TarFilePath or DownloadUrl must be provided."
}

if (![string]::IsNullOrWhiteSpace($TarFilePath) -and ![string]::IsNullOrWhiteSpace($DownloadUrl)) {
    Write-Host "Both TarFilePath and DownloadUrl provided. Using TarFilePath and ignoring DownloadUrl." -ForegroundColor Yellow
    $DownloadUrl = $null
}

# Function to check if WSL is enabled
function Test-WSLEnabled {
    try {
        wsl --status 2>$null | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

# Function to check if distribution name already exists
function Test-DistributionExists {
    param([string]$Name)
    
    $existingDistros = wsl --list --quiet 2>$null
    return $existingDistros -contains $Name
}

# Function to validate tar file
function Test-TarFile {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        return $false
    }
    
    $fileInfo = Get-Item $FilePath
    if ($fileInfo.Length -eq 0) {
        return $false
    }
    
    # Check if file has proper tar signature or is compressed
    $fileExtension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    $validExtensions = @('.tar', '.tar.gz', '.tgz', '.tar.xz', '.tar.bz2')
    
    if ($fileExtension -in $validExtensions) {
        return $true
    }
    
    # Check file signature for tar files
    try {
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath) | Select-Object -First 512
        # Look for tar file magic numbers or ustar signature
        $signature = [System.Text.Encoding]::ASCII.GetString($fileBytes[257..261])
        if ($signature -match "ustar") {
            return $true
        }
        
        # Check for gzip signature (for .tar.gz files)
        if ($fileBytes[0] -eq 0x1F -and $fileBytes[1] -eq 0x8B) {
            return $true
        }
        
        # Check for xz signature
        if ($fileBytes[0] -eq 0xFD -and $fileBytes[1] -eq 0x37 -and $fileBytes[2] -eq 0x7A -and $fileBytes[3] -eq 0x58 -and $fileBytes[4] -eq 0x5A -and $fileBytes[5] -eq 0x00) {
            return $true
        }
    }
    catch {
        Write-Host "Warning: Could not validate tar file signature, but will attempt installation." -ForegroundColor Yellow
        return $true
    }
    
    return $false
}

# Function to download file with progress
function Invoke-FileDownload {
    param(
        [string]$Url,
        [string]$OutputPath
    )
    
    try {
        Write-Host "Downloading from: $Url" -ForegroundColor Yellow
        Write-Host "Destination: $OutputPath" -ForegroundColor Gray
        
        # Create directory if it doesn't exist
        $outputDir = Split-Path $OutputPath -Parent
        if (-not (Test-Path $outputDir)) {
            New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
        }
        
        # Download with progress
        $ProgressPreference = 'Continue'
        Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing -TimeoutSec 600
        
        # Verify download
        if (-not (Test-Path $OutputPath)) {
            throw "Downloaded file does not exist at: $OutputPath"
        }
        
        $fileInfo = Get-Item $OutputPath
        if ($fileInfo.Length -eq 0) {
            throw "Downloaded file is empty (0 bytes)"
        }
        
        Write-Host "Download completed successfully. Size: $([math]::Round($fileInfo.Length / 1MB, 1)) MB" -ForegroundColor Green
        
        # Check if the downloaded file is actually an HTML error page
        $fileHeader = Get-Content $OutputPath -TotalCount 3 -ErrorAction SilentlyContinue | Out-String
        if ($fileHeader -and $fileHeader -match "<!DOCTYPE|<html|<HTML") {
            throw "Downloaded file appears to be an HTML page, not the expected tar file. The URL may be incorrect."
        }
        
        return $true
    }
    catch {
        throw "Failed to download file: $($_.Exception.Message)"
    }
}

# Function to prompt for password securely
function Get-UserPassword {
    param([string]$Username)
    
    Write-Host "Password is required for user '$Username'." -ForegroundColor Yellow
    $password = Read-Host "Enter password for user '$Username'" -AsSecureString
    
    if ($password.Length -eq 0) {
        Write-Host "Password cannot be empty. Please try again." -ForegroundColor Red
        return Get-UserPassword -Username $Username
    }
    
    $confirmPassword = Read-Host "Confirm password for user '$Username'" -AsSecureString
    
    # Convert SecureString to plain text for comparison
    $BSTR1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    $plainPassword1 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR1)
    
    $BSTR2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmPassword)
    $plainPassword2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR2)
    
    if ($plainPassword1 -ne $plainPassword2) {
        Write-Host "Passwords do not match. Please try again." -ForegroundColor Red
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR1)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR2)
        return Get-UserPassword -Username $Username
    }
    
    # Clean up
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR1)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR2)
    
    return $password
}

# Function to create user and assign sudo privileges
function Add-WSLUser {
    param(
        [string]$DistroName,
        [string]$Username,
        [SecureString]$Password
    )
    
    Write-Host "`nCreating user '$Username' in distribution '$DistroName'..." -ForegroundColor Yellow
    
    try {
        # Check if user already exists
        $userCheck = wsl -d $DistroName -u root -e sh -c "id -u $Username 2>/dev/null"
        if ($LASTEXITCODE -eq 0) {
            Write-Host "User '$Username' already exists in the distribution." -ForegroundColor Yellow
            
            # Set the default user for the distribution
            Write-Host "Setting '$Username' as the default user for distribution '$DistroName'..." -ForegroundColor Gray
            wsl -d $DistroName -u root -e sh -c "printf '[user]\ndefault = $Username\n' > /etc/wsl.conf"
            Write-Host "Default user set to '$Username'" -ForegroundColor Green
            return
        }
        
        # Detect distribution type to use appropriate user creation commands
        Write-Host "Detecting distribution type for user creation..." -ForegroundColor Gray
        
        # Get OS release info to determine distribution type
        $osInfo = wsl -d $DistroName -u root -e sh -c "cat /etc/os-release 2>/dev/null || cat /etc/lsb-release 2>/dev/null || echo 'ID=unknown'" 2>$null
        
        # Prepare password handling
        $passwordProvided = $null -ne $Password
        if (-not $passwordProvided) {
            Write-Host "No password provided. You will be prompted to enter a password." -ForegroundColor Yellow
            $Password = Get-UserPassword -Username $Username
            $passwordProvided = $true
        }
        
        $plainPassword = ""
        if ($passwordProvided) {
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
            $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        }
        
        if ($osInfo -match "ID.*ubuntu|ID.*debian") {
            Write-Host "Detected Debian/Ubuntu-based distribution" -ForegroundColor Green
            Write-Host "Creating user with useradd and adding to sudo group..." -ForegroundColor Gray
            
            # Always use non-interactive creation with full paths
            Write-Host "Creating user with provided password..." -ForegroundColor Gray
            wsl -d $DistroName -u root -e sh -c "/usr/sbin/useradd -m -s /bin/bash $Username && echo '${Username}:${plainPassword}' | /usr/sbin/chpasswd"
            
            # Add user to sudo group
            wsl -d $DistroName -u root -e /usr/sbin/usermod -aG sudo $Username
            Write-Host "User '$Username' added to sudo group" -ForegroundColor Green
        }
        elseif ($osInfo -match "ID.*fedora|ID.*rhel|ID.*centos|ID.*rocky|ID.*almalinux") {
            Write-Host "Detected RedHat-based distribution" -ForegroundColor Green
            Write-Host "Creating user with useradd and adding to wheel group..." -ForegroundColor Gray
            
            # Create user with home directory using full path
            wsl -d $DistroName -u root -e /usr/sbin/useradd -m -s /bin/bash $Username
            
            # Set password non-interactively
            Write-Host "Setting user password..." -ForegroundColor Gray
            wsl -d $DistroName -u root -e sh -c "echo '${Username}:${plainPassword}' | /usr/sbin/chpasswd"
            
            # Add user to wheel group (sudo equivalent)
            wsl -d $DistroName -u root -e /usr/sbin/usermod -aG wheel $Username
            Write-Host "User '$Username' added to wheel group" -ForegroundColor Green
        }
        elseif ($osInfo -match "ID.*opensuse|ID.*sles") {
            Write-Host "Detected openSUSE/SLES distribution" -ForegroundColor Green
            Write-Host "Creating user with useradd and adding to wheel group..." -ForegroundColor Gray
            
            # Create user with home directory and wheel group using full path
            wsl -d $DistroName -u root -e /usr/sbin/useradd -m -s /bin/bash -G wheel $Username
            
            # Set password non-interactively
            Write-Host "Setting user password..." -ForegroundColor Gray
            wsl -d $DistroName -u root -e sh -c "echo '${Username}:${plainPassword}' | /usr/sbin/chpasswd"
            
            Write-Host "User '$Username' added to wheel group" -ForegroundColor Green
        }
        elseif ($osInfo -match "ID.*alpine") {
            Write-Host "Detected Alpine Linux distribution" -ForegroundColor Green
            Write-Host "Creating user with adduser and adding to wheel group..." -ForegroundColor Gray
            
            # Create user non-interactively using full path
            Write-Host "Creating user with provided password..." -ForegroundColor Gray
            wsl -d $DistroName -u root -e sh -c "/usr/sbin/adduser -D -s /bin/ash $Username && echo '${Username}:${plainPassword}' | /usr/sbin/chpasswd"
            
            # Add user to wheel group
            wsl -d $DistroName -u root -e /usr/sbin/addgroup $Username wheel
            Write-Host "User '$Username' added to wheel group" -ForegroundColor Green
        }
        elseif ($osInfo -match "ID.*arch") {
            Write-Host "Detected Arch Linux distribution" -ForegroundColor Green
            Write-Host "Creating user with useradd and adding to wheel group..." -ForegroundColor Gray
            
            # Create user with home directory and wheel group using full path
            wsl -d $DistroName -u root -e /usr/sbin/useradd -m -s /bin/bash -G wheel $Username
            
            # Set password non-interactively
            Write-Host "Setting user password..." -ForegroundColor Gray
            wsl -d $DistroName -u root -e sh -c "echo '${Username}:${plainPassword}' | /usr/sbin/chpasswd"
            
            Write-Host "User '$Username' added to wheel group" -ForegroundColor Green
        }
        else {
            Write-Host "Unknown distribution type. Using generic user creation..." -ForegroundColor Yellow
            
            # Try generic user creation with full paths
            wsl -d $DistroName -u root -e sh -c "/usr/sbin/useradd -m -s /bin/bash $Username 2>/dev/null || /usr/sbin/adduser -D $Username 2>/dev/null"
            
            # Set password non-interactively
            Write-Host "Setting user password..." -ForegroundColor Gray
            wsl -d $DistroName -u root -e sh -c "echo '${Username}:${plainPassword}' | /usr/sbin/chpasswd 2>/dev/null || echo '${Username}:${plainPassword}' | chpasswd 2>/dev/null"
            
            # Try to add to common sudo groups
            wsl -d $DistroName -u root -e sh -c "/usr/sbin/usermod -aG sudo $Username 2>/dev/null || /usr/sbin/usermod -aG wheel $Username 2>/dev/null || /usr/sbin/addgroup $Username wheel 2>/dev/null || echo 'Could not add to sudo group automatically'"
            Write-Host "Attempted to add user to sudo/wheel group" -ForegroundColor Yellow
        }
        
        # Clear password from memory
        $plainPassword = $null
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "User '$Username' created successfully with sudo privileges." -ForegroundColor Green
        } else {
            Write-Host "Warning: User creation may have failed or been partially completed." -ForegroundColor Yellow
        }
        
        # Set the default user for the distribution
        Write-Host "Setting '$Username' as the default user for distribution '$DistroName'..." -ForegroundColor Gray
        
        try {
            # Create wsl.conf with proper format
            wsl -d $DistroName -u root -e sh -c "printf '[user]\ndefault = $Username\n' > /etc/wsl.conf"
            Write-Host "Default user set to '$Username'" -ForegroundColor Green
        }
        catch {
            Write-Host "Warning: Could not set default user automatically. You can set it manually or use: wsl -d $DistroName -u $Username" -ForegroundColor Yellow
        }
        
    }
    catch {
        Write-Host "Warning: Failed to create user: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "You can create the user manually after installation." -ForegroundColor Yellow
    }
}
function Update-WSLDistribution {
    param([string]$DistroName)
    
    Write-Host "`nUpdating $DistroName distribution..." -ForegroundColor Yellow
    
    try {
        # Detect distribution type and run appropriate update commands
        Write-Host "Detecting distribution type..." -ForegroundColor Gray
        
        # Get OS release info to determine distribution type
        $osInfo = wsl -d $DistroName -e sh -c "cat /etc/os-release 2>/dev/null || cat /etc/lsb-release 2>/dev/null || echo 'ID=unknown'" 2>$null
        
        if ($osInfo -match "ID.*ubuntu|ID.*debian") {
            Write-Host "Detected Debian/Ubuntu-based distribution" -ForegroundColor Green
            Write-Host "Running: apt update && apt upgrade -y" -ForegroundColor Gray
            wsl -d $DistroName -e sh -c "apt update && apt upgrade -y"
        }
        elseif ($osInfo -match "ID.*fedora|ID.*rhel|ID.*centos|ID.*rocky|ID.*almalinux") {
            Write-Host "Detected RedHat-based distribution" -ForegroundColor Green
            Write-Host "Running: dnf update -y || yum update -y" -ForegroundColor Gray
            wsl -d $DistroName -e sh -c "dnf update -y 2>/dev/null || yum update -y 2>/dev/null"
        }
        elseif ($osInfo -match "ID.*opensuse|ID.*sles") {
            Write-Host "Detected openSUSE/SLES distribution" -ForegroundColor Green
            Write-Host "Running: zypper refresh && zypper update -y" -ForegroundColor Gray
            wsl -d $DistroName -e sh -c "zypper refresh && zypper update -y"
        }
        elseif ($osInfo -match "ID.*alpine") {
            Write-Host "Detected Alpine Linux distribution" -ForegroundColor Green
            Write-Host "Running: apk update && apk upgrade" -ForegroundColor Gray
            wsl -d $DistroName -e sh -c "apk update && apk upgrade"
        }
        elseif ($osInfo -match "ID.*arch") {
            Write-Host "Detected Arch Linux distribution" -ForegroundColor Green
            Write-Host "Running: pacman -Syu --noconfirm" -ForegroundColor Gray
            wsl -d $DistroName -e sh -c "pacman -Syu --noconfirm"
        }
        else {
            Write-Host "Unknown distribution type. Attempting generic update commands..." -ForegroundColor Yellow
            # Try common package managers
            wsl -d $DistroName -e sh -c "apt update && apt upgrade -y 2>/dev/null || dnf update -y 2>/dev/null || yum update -y 2>/dev/null || zypper update -y 2>/dev/null || apk upgrade 2>/dev/null || pacman -Syu --noconfirm 2>/dev/null || echo 'No supported package manager found'"
        }
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Distribution update completed successfully." -ForegroundColor Green
        } else {
            Write-Host "Warning: Distribution update may have failed or been partially completed." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Warning: Failed to update distribution: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Main script execution
try {
    Write-Host "=== WSL Distribution Installation from Tar File ===" -ForegroundColor Green
    
    # Check if running as administrator
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        throw "This script must be run as Administrator. Please restart PowerShell as Administrator and try again."
    }
    
    # Check if WSL is enabled
    Write-Host "`nChecking WSL status..." -ForegroundColor Yellow
    if (-not (Test-WSLEnabled)) {
        Write-Host "WSL is not enabled or not installed. Please enable WSL first:" -ForegroundColor Red
        Write-Host "1. Run: dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart" -ForegroundColor White
        Write-Host "2. Run: dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart" -ForegroundColor White
        Write-Host "3. Restart your computer" -ForegroundColor White
        Write-Host "4. Run: wsl --set-default-version 2" -ForegroundColor White
        throw "WSL is not properly configured."
    }
    
    # Check if distribution name already exists
    if (Test-DistributionExists -Name $DistroName) {
        throw "A WSL distribution with the name '$DistroName' already exists. Please choose a different name or unregister the existing distribution."
    }
    
    # Validate and normalize paths
    $WSLRootPath = [System.IO.Path]::GetFullPath($WSLRootPath)
    
    # Handle subfolder logic: use distro name as subfolder under WSLRootPath
    # unless WSLRootPath already ends with the distro name
    $finalWSLPath = $WSLRootPath
    $rootDirName = Split-Path $WSLRootPath -Leaf
    
    if ($rootDirName -ne $DistroName) {
        $finalWSLPath = Join-Path $WSLRootPath $DistroName
        Write-Host "Using distro name as subfolder: $finalWSLPath" -ForegroundColor Gray
    } else {
        Write-Host "WSLRootPath already contains distro name, using as-is: $finalWSLPath" -ForegroundColor Gray
    }
    
    Write-Host "`nConfiguration:" -ForegroundColor Green
    Write-Host "  Distribution Name: $DistroName" -ForegroundColor White
    Write-Host "  WSL Root Path: $finalWSLPath" -ForegroundColor White
    Write-Host "  Username: $Username" -ForegroundColor White
    
    # Determine if we're using local file or downloading
    $downloadedFile = $false
    $actualTarPath = $TarFilePath
    
    if ([string]::IsNullOrWhiteSpace($TarFilePath)) {
        # Download from URL
        Write-Host "  Source: Download URL" -ForegroundColor White
        Write-Host "  URL: $DownloadUrl" -ForegroundColor White
        
        # Determine file name from URL
        $uri = [System.Uri]$DownloadUrl
        $fileName = [System.IO.Path]::GetFileName($uri.LocalPath)
        if ([string]::IsNullOrWhiteSpace($fileName) -or $fileName -notmatch '\.(tar|tar\.gz|tgz|tar\.xz|tar\.bz2)$') {
            $fileName = "downloaded_distro.tar.gz"
        }
        
        $tempDir = Join-Path $env:TEMP "WSL_Install_$(Get-Random)"
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
        $actualTarPath = Join-Path $tempDir $fileName
        
        # Download the file
        Invoke-FileDownload -Url $DownloadUrl -OutputPath $actualTarPath
        $downloadedFile = $true
    } else {
        # Use local file
        Write-Host "  Source: Local File" -ForegroundColor White
        Write-Host "  File Path: $TarFilePath" -ForegroundColor White
        
        $actualTarPath = [System.IO.Path]::GetFullPath($TarFilePath)
    }
    
    # Validate tar file
    Write-Host "`nValidating tar file..." -ForegroundColor Yellow
    if (-not (Test-TarFile -FilePath $actualTarPath)) {
        throw "The specified file is not a valid tar file or does not exist: $actualTarPath"
    }
    Write-Host "Tar file validation passed." -ForegroundColor Green
    
    # Create WSL root directory
    Write-Host "`nCreating WSL root directory: $finalWSLPath" -ForegroundColor Yellow
    if (-not (Test-Path $finalWSLPath)) {
        New-Item -Path $finalWSLPath -ItemType Directory -Force | Out-Null
    }
    
    # Import the distribution
    Write-Host "`nImporting WSL distribution '$DistroName'..." -ForegroundColor Yellow
    Write-Host "Command: wsl --import $DistroName $finalWSLPath $actualTarPath --version 2" -ForegroundColor Gray
    
    wsl --import $DistroName $finalWSLPath $actualTarPath --version 2
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "WSL distribution imported successfully!" -ForegroundColor Green
        
        # Update the distribution if not skipped
        if (-not $SkipUpdate) {
            Update-WSLDistribution -DistroName $DistroName
        } else {
            Write-Host "Skipping distribution update as requested." -ForegroundColor Yellow
        }
        
        # Create user and assign sudo privileges
        Add-WSLUser -DistroName $DistroName -Username $Username -Password $Password
        
        # Clean up downloaded file if applicable
        if ($downloadedFile -and (Test-Path $actualTarPath)) {
            Write-Host "`nCleaning up downloaded file..." -ForegroundColor Yellow
            try {
                $tempDir = Split-Path $actualTarPath -Parent
                Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "Downloaded file cleaned up successfully." -ForegroundColor Green
            }
            catch {
                Write-Host "Warning: Could not clean up downloaded file: $actualTarPath" -ForegroundColor Yellow
            }
        }
        
        Write-Host "`n=== Installation Completed Successfully! ===" -ForegroundColor Green
        Write-Host ""
        Write-Host "Distribution Details:" -ForegroundColor Cyan
        Write-Host "  WSL Instance Name: $DistroName" -ForegroundColor White
        Write-Host "  Installation Path: $finalWSLPath" -ForegroundColor White
        Write-Host "  Default User: $Username" -ForegroundColor White
        Write-Host "  Source: $(if ($downloadedFile) { "Downloaded from $DownloadUrl" } else { "Local file $TarFilePath" })" -ForegroundColor White
        Write-Host ""
        
        Write-Host "To start your distribution, run:" -ForegroundColor Yellow
        Write-Host "wsl -d $DistroName" -ForegroundColor White
        Write-Host ""
        Write-Host "To start with your user account:" -ForegroundColor Yellow
        Write-Host "wsl -d $DistroName -u $Username" -ForegroundColor White
        
    } else {
        throw "WSL import failed with exit code: $LASTEXITCODE"
    }
    
} catch {
    Write-Host "`n=== Installation Failed ===" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    
    # Clean up on failure
    if (Test-Path $finalWSLPath) {
        Write-Host "Cleaning up WSL root directory due to failure..." -ForegroundColor Yellow
        try {
            Remove-Item $finalWSLPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "WSL root directory cleaned up." -ForegroundColor Green
        }
        catch {
            Write-Host "Warning: Could not clean up WSL root directory: $finalWSLPath" -ForegroundColor Yellow
        }
    }
    
    # Clean up downloaded file if applicable
    if ($downloadedFile -and (Test-Path $actualTarPath)) {
        Write-Host "Cleaning up downloaded file due to failure..." -ForegroundColor Yellow
        try {
            $tempDir = Split-Path $actualTarPath -Parent
            Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "Downloaded file cleaned up." -ForegroundColor Green
        }
        catch {
            Write-Host "Warning: Could not clean up downloaded file." -ForegroundColor Yellow
        }
    }
    
    # Try to unregister the WSL distribution if it was partially created
    try {
        $existingDistros = wsl --list --quiet 2>$null
        if ($existingDistros -contains $DistroName) {
            Write-Host "Removing partially created WSL distribution..." -ForegroundColor Yellow
            wsl --unregister $DistroName 2>$null
            Write-Host "WSL distribution unregistered." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Note: Could not unregister WSL distribution (it may not have been created)." -ForegroundColor Gray
    }
    
    exit 1
}
