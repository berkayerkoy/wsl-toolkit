#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Export an existing WSL distribution to a tar file.

.DESCRIPTION
    This script exports an existing WSL distribution to a tar file that can be used for backup,
    distribution, or importing on other systems. The script validates the distribution exists,
    provides options for compression, and includes verification of the exported file.

.PARAMETER DistroName
    The name of the WSL distribution to export.

.PARAMETER OutputPath
    The path where the tar file will be saved. If a directory is provided, a filename will be generated.

.PARAMETER Force
    Overwrite the output file if it already exists.

.PARAMETER StopDistro
    Stop the distribution before exporting (recommended for consistency).

.PARAMETER Compress
    Use compression for the tar file (creates .tar.gz instead of .tar).

.EXAMPLE
    .\export-wsl.ps1 -DistroName "Ubuntu-22.04" -OutputPath "C:\Backups\"
    Export Ubuntu-22.04 to C:\Backups\ with automatic filename generation.

.EXAMPLE
    .\export-wsl.ps1 -DistroName "MyCustomDistro" -OutputPath "C:\Backups\my-distro-backup.tar" -Force
    Export to a specific file, overwriting if it exists.

.EXAMPLE
    .\export-wsl.ps1 -DistroName "Ubuntu-22.04" -OutputPath "C:\Backups\ubuntu.tar.gz" -Compress -StopDistro
    Export with compression and stop the distro first for consistency.

.NOTES
    - Requires Administrator privileges
    - WSL distribution must exist
    - Large distributions may take significant time to export
    - Consider stopping the distribution before export for data consistency
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Name of the WSL distribution to export")]
    [ValidateNotNullOrEmpty()]
    [string]$DistroName,
    
    [Parameter(Mandatory = $true, HelpMessage = "Output path for the tar file")]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,
    
    [Parameter(Mandatory = $false, HelpMessage = "Overwrite output file if it exists")]
    [switch]$Force,
    
    [Parameter(Mandatory = $false, HelpMessage = "Stop the distribution before exporting")]
    [switch]$StopDistro,
    
    [Parameter(Mandatory = $false, HelpMessage = "Use compression (creates .tar.gz)")]
    [switch]$Compress
)

# Function to write colored output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
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

# Function to check if distribution exists
function Test-DistributionExists {
    param([string]$Name)
    
    try {
        $existingDistros = wsl --list --quiet 2>$null | Where-Object { $_.Trim() -ne "" }
        return $existingDistros -contains $Name
    }
    catch {
        return $false
    }
}

# Function to get distribution status
function Get-DistributionStatus {
    param([string]$Name)
    
    try {
        $runningDistros = wsl --list --running --quiet 2>$null | Where-Object { $_.Trim() -ne "" }
        $allDistros = wsl --list --quiet 2>$null | Where-Object { $_.Trim() -ne "" }
        
        if ($allDistros -contains $Name) {
            if ($runningDistros -contains $Name) {
                return "Running"
            } else {
                return "Stopped"
            }
        } else {
            return "NotFound"
        }
    }
    catch {
        return "Unknown"
    }
}

# Function to stop distribution
function Stop-Distribution {
    param([string]$Name)
    
    try {
        Write-ColorOutput "Stopping WSL distribution '$Name'..." "Yellow"
        wsl --terminate $Name 2>$null
        
        # Wait a moment for shutdown
        Start-Sleep -Seconds 2
        
        $status = Get-DistributionStatus -Name $Name
        if ($status -eq "Stopped") {
            Write-ColorOutput "Distribution '$Name' stopped successfully." "Green"
            return $true
        } else {
            Write-ColorOutput "Warning: Distribution may still be running." "Yellow"
            return $false
        }
    }
    catch {
        Write-ColorOutput "Error stopping distribution: $($_.Exception.Message)" "Red"
        return $false
    }
}

# Function to get distribution information
function Get-DistributionInfo {
    param([string]$Name)
    
    try {
        Write-ColorOutput "Getting distribution information..." "Gray"
        
        # Get WSL version
        $wslVersion = wsl --list --verbose 2>$null | Where-Object { $_ -match $Name } | ForEach-Object {
            if ($_ -match '\s+(\d+)\s*$') {
                return $matches[1]
            }
        }
        
        # Get distribution size (approximate)
        $distroPath = ""
        try {
            # Try to get the installation path from registry or common locations
            $registryPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss"
            $lxssKeys = Get-ChildItem $registryPath -ErrorAction SilentlyContinue
            
            foreach ($key in $lxssKeys) {
                $distroNameReg = Get-ItemProperty $key.PSPath -Name "DistributionName" -ErrorAction SilentlyContinue
                if ($distroNameReg -and $distroNameReg.DistributionName -eq $Name) {
                    $basePath = Get-ItemProperty $key.PSPath -Name "BasePath" -ErrorAction SilentlyContinue
                    if ($basePath) {
                        $distroPath = $basePath.BasePath
                        break
                    }
                }
            }
        }
        catch {
            # Ignore registry errors
        }
        
        $sizeInfo = "Unknown"
        if ($distroPath -and (Test-Path $distroPath)) {
            try {
                $size = (Get-ChildItem $distroPath -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                if ($size -gt 0) {
                    $sizeInfo = "{0:N1} MB" -f ($size / 1MB)
                }
            }
            catch {
                # Ignore size calculation errors
            }
        }
        
        return @{
            Name = $Name
            Version = $wslVersion
            Path = $distroPath
            Size = $sizeInfo
        }
    }
    catch {
        Write-ColorOutput "Warning: Could not retrieve all distribution information." "Yellow"
        return @{
            Name = $Name
            Version = "Unknown"
            Path = "Unknown"
            Size = "Unknown"
        }
    }
}

# Function to generate filename if directory is provided
function Get-OutputFilePath {
    param(
        [string]$OutputPath,
        [string]$DistroName,
        [bool]$UseCompression
    )
    
    $resolvedPath = [System.IO.Path]::GetFullPath($OutputPath)
    
    # Check if the path is a directory
    if (Test-Path $resolvedPath -PathType Container) {
        # Generate filename
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $extension = if ($UseCompression) { ".tar.gz" } else { ".tar" }
        $filename = "${DistroName}-export-${timestamp}${extension}"
        $resolvedPath = Join-Path $resolvedPath $filename
    }
    elseif ([System.IO.Path]::GetExtension($resolvedPath) -eq "") {
        # No extension provided, add appropriate one
        $extension = if ($UseCompression) { ".tar.gz" } else { ".tar" }
        $resolvedPath += $extension
    }
    
    return $resolvedPath
}

# Function to export distribution
function Export-Distribution {
    param(
        [string]$DistroName,
        [string]$OutputPath
    )
    
    try {
        Write-ColorOutput "`nExporting WSL distribution '$DistroName'..." "Yellow"
        Write-ColorOutput "Output file: $OutputPath" "Gray"
        Write-ColorOutput "Command: wsl --export $DistroName $OutputPath" "Gray"
        
        # Ensure output directory exists
        $outputDir = Split-Path $OutputPath -Parent
        if (-not (Test-Path $outputDir)) {
            New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
            Write-ColorOutput "Created output directory: $outputDir" "Gray"
        }
        
        # Export the distribution
        $startTime = Get-Date
        wsl --export $DistroName $OutputPath
        $endTime = Get-Date
        $duration = $endTime - $startTime
        
        if ($LASTEXITCODE -eq 0) {
            Write-ColorOutput "Export completed successfully!" "Green"
            Write-ColorOutput "Export duration: $($duration.ToString('mm\:ss'))" "Gray"
            return $true
        } else {
            Write-ColorOutput "Export failed with exit code: $LASTEXITCODE" "Red"
            return $false
        }
    }
    catch {
        Write-ColorOutput "Error during export: $($_.Exception.Message)" "Red"
        return $false
    }
}

# Main script execution
try {
    Write-ColorOutput "=== WSL Distribution Export Tool ===" "Cyan"
    Write-ColorOutput "====================================" "Cyan"
    
    # Check if running as administrator
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        throw "This script must be run as Administrator. Please restart PowerShell as Administrator and try again."
    }
    
    # Check if WSL is enabled
    Write-ColorOutput "`nChecking WSL status..." "Yellow"
    if (-not (Test-WSLEnabled)) {
        throw "WSL is not enabled or not installed. Please enable WSL first."
    }
    Write-ColorOutput "WSL is available." "Green"
    
    # Check if distribution exists
    Write-ColorOutput "`nChecking distribution '$DistroName'..." "Yellow"
    if (-not (Test-DistributionExists -Name $DistroName)) {
        Write-ColorOutput "Available distributions:" "Gray"
        wsl --list --quiet | Where-Object { $_.Trim() -ne "" } | ForEach-Object {
            Write-ColorOutput "  - $_" "Gray"
        }
        throw "WSL distribution '$DistroName' does not exist."
    }
    
    # Get distribution information
    $distroInfo = Get-DistributionInfo -Name $DistroName
    $distroStatus = Get-DistributionStatus -Name $DistroName
    
    Write-ColorOutput "Distribution found!" "Green"
    Write-ColorOutput "Distribution Details:" "Cyan"
    Write-ColorOutput "  Name: $($distroInfo.Name)" "White"
    Write-ColorOutput "  Status: $distroStatus" "White"
    Write-ColorOutput "  WSL Version: $($distroInfo.Version)" "White"
    Write-ColorOutput "  Installation Path: $($distroInfo.Path)" "White"
    Write-ColorOutput "  Estimated Size: $($distroInfo.Size)" "White"
    
    # Generate final output path
    $finalOutputPath = Get-OutputFilePath -OutputPath $OutputPath -DistroName $DistroName -UseCompression $Compress
    
    # Check if output file already exists
    if ((Test-Path $finalOutputPath) -and -not $Force) {
        throw "Output file already exists: $finalOutputPath`nUse -Force to overwrite."
    }
    
    if (Test-Path $finalOutputPath) {
        Write-ColorOutput "`nRemoving existing output file..." "Yellow"
        Remove-Item $finalOutputPath -Force
    }
    
    Write-ColorOutput "`nExport Configuration:" "Cyan"
    Write-ColorOutput "  Source Distribution: $DistroName" "White"
    Write-ColorOutput "  Output File: $finalOutputPath" "White"
    Write-ColorOutput "  Compression: $(if ($Compress) { 'Enabled (.tar.gz)' } else { 'Disabled (.tar)' })" "White"
    Write-ColorOutput "  Stop Before Export: $(if ($StopDistro) { 'Yes' } else { 'No' })" "White"
    
    # Warning about running distribution
    if ($distroStatus -eq "Running" -and -not $StopDistro) {
        Write-ColorOutput "`nWARNING: Distribution is currently running!" "Yellow"
        Write-ColorOutput "Exporting a running distribution may result in inconsistent data." "Yellow"
        Write-ColorOutput "Consider using -StopDistro parameter for better consistency." "Yellow"
        
        $confirm = Read-Host "`nContinue anyway? (y/N)"
        if ($confirm -notmatch '^[Yy]$') {
            Write-ColorOutput "Export cancelled by user." "Yellow"
            exit 0
        }
    }
    
    # Stop distribution if requested
    if ($StopDistro -and $distroStatus -eq "Running") {
        Stop-Distribution -Name $DistroName | Out-Null
    }
    
    # Perform the export
    $exportSuccess = Export-Distribution -DistroName $DistroName -OutputPath $finalOutputPath
    
    if ($exportSuccess) {
        # Get final file information
        $exportedFile = Get-Item $finalOutputPath
        
        Write-ColorOutput "`n=== Export Completed Successfully! ===" "Green"
        Write-ColorOutput ""
        Write-ColorOutput "Export Details:" "Cyan"
        Write-ColorOutput "  Source: $DistroName" "White"
        Write-ColorOutput "  Output File: $finalOutputPath" "White"
        Write-ColorOutput "  File Size: $([math]::Round($exportedFile.Length / 1MB, 1)) MB" "White"
        Write-ColorOutput "  Created: $($exportedFile.CreationTime)" "White"
        Write-ColorOutput ""
        
        Write-ColorOutput "To import this distribution on another system:" "Yellow"
        Write-ColorOutput "wsl --import <NewDistroName> <InstallPath> `"$finalOutputPath`"" "White"
        Write-ColorOutput ""
        Write-ColorOutput "Or use the import-wsl.ps1 script:" "Yellow"
        Write-ColorOutput ".\import-wsl.ps1 -DistroName <NewName> -WSLRootPath <Path> -TarFilePath `"$finalOutputPath`"" "White"
        
    } else {
        Write-ColorOutput "`n=== Export Failed ===" "Red"
        
        # Clean up failed export file
        if (Test-Path $finalOutputPath) {
            Write-ColorOutput "Cleaning up failed export file..." "Yellow"
            try {
                Remove-Item $finalOutputPath -Force -ErrorAction SilentlyContinue
                Write-ColorOutput "Failed export file removed." "Green"
            }
            catch {
                Write-ColorOutput "Warning: Could not remove failed export file: $finalOutputPath" "Yellow"
            }
        }
        
        exit 1
    }
    
} catch {
    Write-ColorOutput "`n=== Export Failed ===" "Red"
    Write-ColorOutput "Error: $($_.Exception.Message)" "Red"
    
    # Clean up on failure
    if (Test-Path $finalOutputPath) {
        Write-ColorOutput "Cleaning up failed export file..." "Yellow"
        try {
            Remove-Item $finalOutputPath -Force -ErrorAction SilentlyContinue
            Write-ColorOutput "Failed export file removed." "Green"
        }
        catch {
            Write-ColorOutput "Warning: Could not remove failed export file: $finalOutputPath" "Yellow"
        }
    }
    
    exit 1
}
