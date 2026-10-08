# NetSentinel API key generator. Run this on YOUR computer, not the server.
# The key is created and stored here, encrypted with Windows DPAPI for your account only.
# The server receives only its SHA-256 digest, which cannot be turned back into the key.
param([string]$Name = "$env:USERNAME-$env:COMPUTERNAME")
$ErrorActionPreference = 'Stop'
$dir  = Join-Path $HOME '.netsentinel'
$file = Join-Path $dir 'api-key.dpapi'
if (Test-Path $file) { throw "A key already exists at $file. Delete it first to make a new one." }

$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$idBytes  = New-Object byte[] 6;  $rng.GetBytes($idBytes)
$secBytes = New-Object byte[] 32; $rng.GetBytes($secBytes)
$keyId  = -join ($idBytes | ForEach-Object { $_.ToString('x2') })
$secret = [Convert]::ToBase64String($secBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
$key    = "nsk_${keyId}_$secret"
$digest = -join ([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($key)) |
                 ForEach-Object { $_.ToString('x2') })

New-Item -ItemType Directory -Force $dir | Out-Null
ConvertTo-SecureString $key -AsPlainText -Force | ConvertFrom-SecureString | Set-Content -Path $file
Remove-Variable key, secret, secBytes

Write-Host "Key saved, encrypted for your Windows account only: $file"
Write-Host "Register it on the server. This line contains NO secret:"
Write-Host "  netsentinel keys register --key-id $keyId --sha256 $digest --name `"$Name`""
Write-Host ""
Write-Host "To use it later in PowerShell:"
Write-Host '  $k = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR((Get-Content "$HOME\.netsentinel\api-key.dpapi" | ConvertTo-SecureString)))'
