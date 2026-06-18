# Step 1: Extract certificate from 360 installer (read-only, safe)
$installerPath = "E:\cclaw\DrvCeooLinstaller_1029_53d5d.exe"
$cerOutputPath = "E:\cclaw\360_Qihu_Block.cer"

Write-Host "=== Step 1: Extracting 360 certificate ===" -ForegroundColor Cyan
$sig = Get-AuthenticodeSignature -FilePath $installerPath

if ($sig.SignerCertificate -eq $null) {
    Write-Host "ERROR: No digital signature found on this file!" -ForegroundColor Red
    exit 1
}

Write-Host "Subject: $($sig.SignerCertificate.Subject)"
Write-Host "Thumbprint: $($sig.SignerCertificate.Thumbprint)"
Write-Host "Status: $($sig.Status)"

# Export to .cer file
$certBytes = $sig.SignerCertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
[System.IO.File]::WriteAllBytes($cerOutputPath, $certBytes)
Write-Host "Certificate exported to: $cerOutputPath" -ForegroundColor Green

# Step 2: Configure Software Restriction Policy via Registry
Write-Host ""
Write-Host "=== Step 2: Configuring Software Restriction Policy ===" -ForegroundColor Cyan

# The certificate hash for registry
$certHash = $sig.SignerCertificate.GetCertHashString()

# Registry path for Software Restriction Policies
$srpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"

# Check if running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "WARNING: Not running as Administrator." -ForegroundColor Yellow
    Write-Host "Software restriction policy requires admin rights."
    Write-Host "The certificate has been exported to: $cerOutputPath"
    Write-Host ""
    Write-Host "Please run this script as Administrator, or follow manual steps below:"
    Write-Host "1. Open gpedit.msc"
    Write-Host "2. Computer Config > Windows Settings > Security Settings > Software Restriction Policies"
    Write-Host "3. Right-click > New Software Restriction Policy"
    Write-Host "4. Additional Rules > New Certificate Rule"
    Write-Host "5. Browse to: $cerOutputPath"
    Write-Host "6. Set Security Level: Disallowed"
    Write-Host "7. In Enforcement properties: select 'Enforce certificate rules'"
    exit 0
}

# Create the CodeIdentifiers key if it doesn't exist
if (-not (Test-Path $srpPath)) {
    New-Item -Path $srpPath -Force | Out-Null
    Write-Host "Created registry key: $srpPath"
}

# Set default security level
New-ItemProperty -Path $srpPath -Name "DefaultLevel" -Value 0x00000000 -PropertyType DWord -Force | Out-Null

# Set policy for certificate rules enforcement
New-ItemProperty -Path $srpPath -Name "PolicyScope" -Value 0x00000000 -PropertyType DWord -Force | Out-Null

# Set to enforce certificate rules
New-ItemProperty -Path $srpPath -Name "EnforcementMode" -Value 0x00000001 -PropertyType DWord -Force | Out-Null

# Create the certificate rules path
$certRulesPath = "$srpPath\0\Certificates"
if (-not (Test-Path $certRulesPath)) {
    New-Item -Path $certRulesPath -Force | Out-Null
    Write-Host "Created registry key: $certRulesPath"
}

# Add the certificate rule (use thumbprint as identifier)
$rulePath = "$certRulesPath\$certHash"
if (-not (Test-Path $rulePath)) {
    New-Item -Path $rulePath -Force | Out-Null
}

# Set the certificate rule properties
$certBlob = [System.Convert]::ToBase64String($sig.SignerCertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
New-ItemProperty -Path $rulePath -Name "ItemData" -Value $certBlob -PropertyType String -Force | Out-Null
New-ItemProperty -Path $rulePath -Name "SaferFlags" -Value 0x00000000 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $rulePath -Name "Description" -Value "Block all software signed by Beijing Qihu Technology Co., Ltd. (360)" -PropertyType String -Force | Out-Null

Write-Host "Certificate rule added successfully!" -ForegroundColor Green
Write-Host "Rule: ALL software signed by Beijing Qihu Technology Co., Ltd. is now BLOCKED"
Write-Host ""

# Refresh policy
Write-Host "Refreshing policy..."
gpupdate /force /target:computer 2>$null

Write-Host ""
Write-Host "=== DONE ===" -ForegroundColor Green
Write-Host "360 software is now blocked via certificate rule."
Write-Host "Certificate file saved to: $cerOutputPath"
Write-Host ""
Write-Host "To verify: run secpol.msc > Software Restriction Policies > Certificate Rules"
