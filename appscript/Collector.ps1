# ========================================================================
# ANTIGRAVITY ENGINE - FULL METADATA, PERFORMANCE & LOG DIAGNOSTIC BRIDGE
# ========================================================================
# Jalankan skrip ini dengan mengklik kanan -> Run with PowerShell
# Hasil keluaran akan berupa berkas JSON Terpadu di Desktop Anda.
# ========================================================================

$OutputFilePath = "$env:USERPROFILE\Desktop\Antigravity_Full_Diagnostic.json"
$DiagnosticData = @{}

Clear-Host
Write-Host "===========================================================" -ForegroundColor Custom
Write-Host "      ANTIGRAVITY SYSTEM DIAGNOSTIC DATA COLLECTOR v2.0    " -ForegroundColor Green
Write-Host "===========================================================" -ForegroundColor Custom

# ------------------------------------------------------------------------
# 1. MENGAMBIL INFORMASI HARDWARE & METADATA PERANGKAT
# ------------------------------------------------------------------------
Write-Host "⏳ [1/4] Mengambil Informasi Hardware & Pengaturan Perangkat..." -ForegroundColor Cyan
try {
    $OS = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $CS = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $CPU = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue
    $Disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue

    $DiagnosticData.DeviceMetadata = @{
        HostName     = $CS.Name
        OS_Version   = $OS.Caption + " (Build " + $OS.BuildNumber + ")"
        Architecture = $OS.OSArchitecture
        Total_RAM_GB = [Math]::Round($CS.TotalPhysicalMemory / 1GB, 2)
        CPU_Model    = $CPU.Name
        Free_Space_C = [Math]::Round($Disk.FreeSpace / 1GB, 2)
    }
}
catch {
    Write-Host "⚠️ Gagal mengambil beberapa metadata hardware dasar." -ForegroundColor Warning
}

# ------------------------------------------------------------------------
# 2. AUDIT MANIFES APLIKASI TERINSTAL (SAFE REGISTRY SCAN - ANTI CORRUPT KEY)
# ------------------------------------------------------------------------
Write-Host "⏳ [2/4] Audit Manifes Aplikasi yang Terinstal (Safe Registry Scan)..." -ForegroundColor Cyan
$RegistryPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
)

$InstalledApps = @()

foreach ($Path in $RegistryPaths) {
    if (Test-Path $Path) {
        $SubKeys = Get-ChildItem $Path -ErrorAction SilentlyContinue
        foreach ($Key in $SubKeys) {
            try {
                # Menggunakan akses method bawaan .NET secara granular untuk menghindari InvalidCastException
                $DisplayName = $Key.GetValue("DisplayName")
                $SystemComponent = $Key.GetValue("SystemComponent")
                
                if ($DisplayName -and $SystemComponent -ne 1) {
                    $DisplayVersion = $Key.GetValue("DisplayVersion")
                    $InstallDate = $Key.GetValue("InstallDate")
                    
                    # Normalisasi string tanggal biner/mentah registri (YYYYMMDD) menjadi format standar YYYY-MM-DD
                    if ($InstallDate -match '^\d{8}$') {
                        try {
                            $InstallDate = [datetime]::ParseExact($InstallDate, 'yyyyMMdd', $null).ToString("yyyy-MM-dd")
                        }
                        catch {
                            $InstallDate = "Unknown"
                        }
                    }

                    $InstalledApps += [PSCustomObject]@{
                        DisplayName    = [string]$DisplayName
                        DisplayVersion = if ($DisplayVersion) { [string]$DisplayVersion } else { "N/A" }
                        InstallDate    = if ($InstallDate -and $InstallDate -ne "") { [string]$InstallDate } else { "Unknown" }
                    }
                }
            }
            catch {
                # Abaikan key corrupt/invalid cast tipe data biner pihak ketiga, lanjutkan loop
                continue
            }
        }
    }
}

$DiagnosticData.InstalledApplications = $InstalledApps | Sort-Object DisplayName

# ------------------------------------------------------------------------
# 3. MENGAMBIL RAMPEL RESOURCE & RIWAYAT DEGRADASI PERFORMA
# ------------------------------------------------------------------------
Write-Host "⏳ [3/4] Mengambil Sampel Performa & Riwayat Resource Terkini..." -ForegroundColor Cyan
try {
    $CpuSample = (Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Measure-Object -Property LoadPercentage -Average).Average
    $TotalRam = $OS.TotalVisibleMemorySize
    $FreeRam = $OS.FreePhysicalMemory
    $RamUsagePct = [Math]::Round((($TotalRam - $FreeRam) / $TotalRam) * 100, 2)

    # Menarik log khusus peristiwa penurunan performa ekstrem (Booting lambat, RAM Kritis)
    $ResourceAlerts = @()
    $RawAlerts = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; 
        Level   = 1, 2, 3
    } -MaxEvents 30 -ErrorAction SilentlyContinue

    if ($RawAlerts) {
        foreach ($Alert in $RawAlerts) {
            $ResourceAlerts += [PSCustomObject]@{
                TimeCreated = $Alert.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                Id          = $Alert.Id
                Message     = $Alert.Message
            }
        }
    }

    $DiagnosticData.ResourceSnapshots = @{
        CurrentCpuLoadPct = if ($CpuSample) { [Math]::Round($CpuSample, 2) } else { 0 }
        CurrentRamLoadPct = $RamUsagePct
        AvailableRamMB    = [Math]::Round($FreeRam / 1KB, 2)
        PerformanceAlerts = $ResourceAlerts
    }
}
catch {
    $DiagnosticData.ResourceSnapshots = @{
        CurrentCpuLoadPct = 0
        CurrentRamLoadPct = 0
        AvailableRamMB    = 0
        PerformanceAlerts = @()
    }
}

# ------------------------------------------------------------------------
# 4. MEMBACA LOG KEJADIAN WINDOWS EVENT VIEWER (SYSTEM)
# ------------------------------------------------------------------------
Write-Host "⏳ [4/4] Membaca Log Kejadian Windows Event Viewer (System)..." -ForegroundColor Cyan
try {
    $SystemLogs = @()
    # Menarik 300 entri log rumpun System berkategori Warning, Error, dan Critical
    $RawLogs = Get-WinEvent -LogName System -MaxEvents 300 -ErrorAction SilentlyContinue | Where-Object { $_.Level -le 3 }

    if ($RawLogs) {
        foreach ($Log in $RawLogs) {
            $SystemLogs += [PSCustomObject]@{
                time   = $Log.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                id     = $Log.Id
                level  = $Log.LevelDisplayName
                source = $Log.ProviderName
                msg    = $Log.Message
            }
        }
    }
    $DiagnosticData.SystemLogs = $SystemLogs
}
catch {
    Write-Host "⚠️ Gagal membaca log subsistem Event Viewer Windows." -ForegroundColor Warning
    $DiagnosticData.SystemLogs = @()
}

# ------------------------------------------------------------------------
# KILAS BALIK & EKSPOR DATA KE JSON TERPADU
# ------------------------------------------------------------------------
Write-Host "💾 Menulis berkas hasil diagnosis ke format JSON Terpadu..." -ForegroundColor Custom
try {
    # Konversi nested object ke format string JSON berkedalaman struktur level 6
    $JsonOutput = $DiagnosticData | ConvertTo-Json -Depth 6
    [System.IO.File]::WriteAllText($OutputFilePath, $JsonOutput, [System.Text.Encoding]::UTF8)
    
    Write-Host "===========================================================" -ForegroundColor Green
    Write-Host "✅ SUKSES BERSAMA ANTIGRAVITY CORES!" -ForegroundColor Green
    Write-Host "Berkas tersimpan di: $OutputFilePath" -ForegroundColor White
    Write-Host "Silakan unggah berkas tersebut ke Google Apps Script UI Anda." -ForegroundColor White
    Write-Host "===========================================================" -ForegroundColor Green
}
catch {
    Write-Host "❌ Gagal mengekspor file JSON hasil diagnostik: $_" -ForegroundColor Danger
}