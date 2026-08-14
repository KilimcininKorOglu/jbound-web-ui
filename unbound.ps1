# Unbound DNS Kayıt Yönetim Scripti
# Bu script Windows istemcilerden Unbound DNS sunucularına kayıt eklemeyi otomatize eder

param(
    [Parameter(Mandatory=$false)]
    [string[]]$UnboundServers = @("192.0.2.4", "192.0.2.5"), # Unbound sunucu IP'lerini buraya girin

    [Parameter(Mandatory=$false)]
    [string]$Username = "user01",

    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = "/etc/unbound/local_records.conf",

    # unbound-checkconf bu dosyayı doğrular. local_records.conf tek başına
    # doğrulanamaz, çünkü include ile server clause içine gömülür.
    [Parameter(Mandatory=$false)]
    [string]$MainConfigFile = "/etc/unbound/unbound.conf"
)

# Renk kodları
$Red = "Red"
$Green = "Green"
$Yellow = "Yellow"
$Cyan = "Cyan"
$White = "White"

function Write-ColorOutput {
    param($Message, $Color = "White")

    # Null kontrolü
    if ([string]::IsNullOrEmpty($Color)) {
        $Color = "White"
    }

    try {
        Write-Host $Message -ForegroundColor $Color
    }
    catch {
        Write-Host $Message -ForegroundColor White
    }
}

function Test-SSHConnection {
    param($Server, $Username)
    try {
        $result = ssh -o ConnectTimeout=5 -o BatchMode=yes "$Username@$Server" "echo 'test'" 2>$null
        return $result -eq "test"
    }
    catch {
        return $false
    }
}

function Add-UnboundRecord {
    param($Server, $Username, $Domain, $IPAddress, $ConfigFile)

    try {
        Write-ColorOutput "[$Server] Kayıt ekleniyor: $Domain -> $IPAddress" $Cyan

        # Zone'u transparent olarak ayarla (eğer yoksa)
        $rootDomain = ($Domain -split '\.' | Select-Object -Skip 1) -join '.'
        if ($rootDomain) {
            $searchText = "local-zone: `"$rootDomain.`" transparent"
            $addText = "         local-zone: `"$rootDomain.`" transparent"
            $zoneCommand = "grep -qF '$searchText' $ConfigFile || echo '$addText' >> $ConfigFile"
            ssh "$Username@$Server" $zoneCommand
            if ($LASTEXITCODE -ne 0) {
                Write-ColorOutput "[$Server] Zone satırı eklenemedi (ssh çıkış kodu: $LASTEXITCODE)" $Red
                return $false
            }
        }

        # Aynı domain için kayıt varsa tekrar ekleme
        $domainPattern = "local-data: `"$Domain. IN A"
        ssh "$Username@$Server" "grep -qF '$domainPattern' $ConfigFile"
        $grepExitCode = $LASTEXITCODE
        if ($grepExitCode -eq 0) {
            Write-ColorOutput "[$Server] Bu domain için kayıt zaten var, atlanıyor: $Domain" $Yellow
            return $true
        }
        if ($grepExitCode -gt 1) {
            Write-ColorOutput "[$Server] Mevcut kayıtlar okunamadı (ssh çıkış kodu: $grepExitCode)" $Red
            return $false
        }

        # A kaydını ekle (9 space ile)
        $dataText = "         local-data: `"$Domain. IN A $IPAddress`""
        $recordCommand = "echo '$dataText' >> $ConfigFile"
        ssh "$Username@$Server" $recordCommand
        if ($LASTEXITCODE -ne 0) {
            Write-ColorOutput "[$Server] Kayıt eklenemedi (ssh çıkış kodu: $LASTEXITCODE)" $Red
            return $false
        }

        Write-ColorOutput "[$Server] Kayıt başarıyla eklendi" $Green
        return $true
    }
    catch {
        Write-ColorOutput "[$Server] Kayıt eklenirken hata: $($_.Exception.Message)" $Red
        return $false
    }
}

function Test-UnboundConfig {
    param($Server, $Username, $MainConfigFile)

    try {
        Write-ColorOutput "[$Server] Config doğrulanıyor: $MainConfigFile" $Cyan
        $output = ssh "$Username@$Server" "sudo unbound-checkconf $MainConfigFile 2>&1"

        if ($LASTEXITCODE -ne 0) {
            Write-ColorOutput "[$Server] ❌ Config doğrulaması başarısız (çıkış kodu: $LASTEXITCODE)" $Red
            foreach ($line in $output) {
                Write-ColorOutput "[$Server]   $line" $Red
            }
            return $false
        }

        Write-ColorOutput "[$Server] ✅ Config geçerli" $Green
        return $true
    }
    catch {
        Write-ColorOutput "[$Server] Config doğrulanırken hata: $($_.Exception.Message)" $Red
        return $false
    }
}

function Invoke-UnboundReload {
    param($Server, $Username)

    try {
        Write-ColorOutput "[$Server] Config yeniden yükleniyor (reload_keep_cache)..." $Yellow
        $output = ssh "$Username@$Server" "sudo unbound-control reload_keep_cache 2>&1"

        if ($LASTEXITCODE -ne 0) {
            Write-ColorOutput "[$Server] reload_keep_cache kullanılamadı (çıkış kodu: $LASTEXITCODE)" $Yellow
            foreach ($line in $output) {
                Write-ColorOutput "[$Server]   $line" $Yellow
            }
            return $false
        }

        Write-ColorOutput "[$Server] ✅ Config yeniden yüklendi, cache korundu" $Green
        return $true
    }
    catch {
        Write-ColorOutput "[$Server] Yeniden yükleme sırasında hata: $($_.Exception.Message)" $Yellow
        return $false
    }
}

function Invoke-UnboundServiceReload {
    param($Server, $Username)

    try {
        Write-ColorOutput "[$Server] Servise reload sinyali gönderiliyor..." $Yellow
        $output = ssh "$Username@$Server" "sudo systemctl reload unbound 2>&1"

        if ($LASTEXITCODE -ne 0) {
            Write-ColorOutput "[$Server] systemctl reload kullanılamadı (çıkış kodu: $LASTEXITCODE)" $Yellow
            foreach ($line in $output) {
                Write-ColorOutput "[$Server]   $line" $Yellow
            }
            return $false
        }

        # SIGHUP sonrası config hatalıysa unbound kapanabilir, durumu doğrula
        $serviceStatus = ssh "$Username@$Server" "sudo systemctl is-active unbound" 2>$null
        if ($serviceStatus -ne "active") {
            Write-ColorOutput "[$Server] ❌ Reload sonrası servis aktif değil: $serviceStatus" $Red
            return $false
        }

        Write-ColorOutput "[$Server] ✅ Config yeniden yüklendi, cache temizlendi" $Green
        return $true
    }
    catch {
        Write-ColorOutput "[$Server] Reload sinyali gönderilirken hata: $($_.Exception.Message)" $Yellow
        return $false
    }
}

function Restart-UnboundService {
    param($Server, $Username)

    try {
        Write-ColorOutput "[$Server] Unbound servisi yeniden başlatılıyor..." $Yellow
        ssh "$Username@$Server" "sudo systemctl restart unbound"

        # Servis durumunu kontrol et (2 saniyede bir, maksimum 30 saniye)
        $maxAttempts = 15
        $attempt = 0

        do {
            Start-Sleep 2
            $attempt++
            Write-ColorOutput "[$Server] Servis durumu kontrol ediliyor... (Deneme: $attempt)" $Cyan

            $serviceStatus = ssh "$Username@$Server" "sudo systemctl is-active unbound" 2>$null

            if ($serviceStatus -eq "active") {
                Write-ColorOutput "[$Server] ✅ Unbound servisi başarıyla yeniden başlatıldı!" $Green
                return $true
            }
        } while ($attempt -lt $maxAttempts)

        Write-ColorOutput "[$Server] ❌ Servis başlatılamadı veya zaman aşımı" $Red
        return $false
    }
    catch {
        Write-ColorOutput "[$Server] Servis yeniden başlatılırken hata: $($_.Exception.Message)" $Red
        return $false
    }
}

function Show-Banner {
    Write-Host @"
╔══════════════════════════════════════════════════════════╗
║              UNBOUND DNS KAYIT YÖNETİCİSİ                ║
║                                                          ║
║  Bu script Unbound DNS sunucularınıza otomatik olarak    ║
║  DNS kayıtları ekler ve config'i yeniden yükler          ║
╚══════════════════════════════════════════════════════════╝
"@ -ForegroundColor $Cyan
    Write-Host ""
}

# Ana script başlangıcı
Clear-Host
Show-Banner

# SSH bağlantılarını test et
Write-ColorOutput "SSH bağlantıları test ediliyor..." $Yellow
$validServers = @()

foreach ($server in $UnboundServers) {
    Write-ColorOutput "[$server] Bağlantı test ediliyor..." $Cyan
    if (Test-SSHConnection -Server $server -Username $Username) {
        Write-ColorOutput "[$server] ✅ Bağlantı başarılı" $Green
        $validServers += $server
    }
    else {
        Write-ColorOutput "[$server] ❌ Bağlantı başarısız" $Red
        Write-ColorOutput "Not: SSH key-based authentication kullandığınızdan emin olun" $Yellow
    }
}

if ($validServers.Count -eq 0) {
    Write-ColorOutput "❌ Hiçbir sunucuya bağlanılamadı. Script sonlandırılıyor." $Red
    exit 1
}

Write-ColorOutput "`n✅ $($validServers.Count) sunucu kullanılabilir: $($validServers -join ', ')" $Green

# Yenileme gerekip gerekmediğini takip etmek için değişken
$needsReload = $false

# Ana döngü - kayıt ekleme
do {
    Write-Host ("`n" + ("=" * 60)) -ForegroundColor $Cyan
    Write-ColorOutput "YENİ DNS KAYDI EKLEME" $Cyan
    Write-Host ("=" * 60) -ForegroundColor $Cyan

    # Domain adı al
    do {
        $domain = Read-Host "`nDomain adını girin (örn: mail.google.com)"
        if ([string]::IsNullOrWhiteSpace($domain)) {
            Write-ColorOutput "Domain adı boş olamaz!" $Red
        }
        elseif ($domain -notmatch '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') {
            Write-ColorOutput "Geçerli bir domain adı girin!" $Red
            $domain = ""
        }
    } while ([string]::IsNullOrWhiteSpace($domain))

    # IP adresi al
    do {
        $ipAddress = Read-Host "IP adresini girin (örn: 10.10.10.10)"
        if ([string]::IsNullOrWhiteSpace($ipAddress)) {
            Write-ColorOutput "IP adresi boş olamaz!" $Red
        }
        elseif ($ipAddress -notmatch '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$') {
            Write-ColorOutput "Geçerli bir IPv4 adresi girin!" $Red
            $ipAddress = ""
        }
    } while ([string]::IsNullOrWhiteSpace($ipAddress))

    # Özet göster
    Write-Host ("`n" + ("-" * 50)) -ForegroundColor $Yellow
    Write-ColorOutput "KAYIT ÖZETİ:" $Yellow
    Write-ColorOutput "Domain: $domain" $White
    Write-ColorOutput "IP: $ipAddress" $White
    Write-ColorOutput "Hedef sunucular: $($validServers -join ', ')" $White
    Write-Host ("-" * 50) -ForegroundColor $Yellow

    $confirm = Read-Host "`nBu kayıtları eklemek istediğinizden emin misiniz? (E/H)"

    if ($confirm -eq "E" -or $confirm -eq "e") {
        $allSuccessful = $true

        # Tüm sunuculara kayıt ekle
        foreach ($server in $validServers) {
            $success = Add-UnboundRecord -Server $server -Username $Username -Domain $domain -IPAddress $ipAddress -ConfigFile $ConfigFile
            if (-not $success) {
                $allSuccessful = $false
            }
        }

        if ($allSuccessful) {
            Write-ColorOutput "`n✅ Tüm sunuculara kayıtlar başarıyla eklendi!" $Green
            $needsReload = $true  # Yenileme gerektiğini işaretle
        }
        else {
            Write-ColorOutput "`n❌ Bazı sunucularda kayıt ekleme başarısız oldu!" $Red
        }
    }
    else {
        Write-ColorOutput "İşlem iptal edildi." $Yellow
    }

    # Devam etme onayı
    Write-Host ("`n" + ("=" * 60)) -ForegroundColor $Cyan
    $continue = Read-Host "Başka bir kayıt eklemek istiyor musunuz? (E/H)"

} while ($continue -eq "E" -or $continue -eq "e")

# Eğer kayıt eklendiyse yenilemeyi sor
if ($needsReload) {
    Write-Host ("`n" + ("=" * 60)) -ForegroundColor $Cyan
    $finalReloadConfirm = Read-Host "Unbound servislerini yenilemek istiyor musunuz? (E/H)"

    if ($finalReloadConfirm -eq "E" -or $finalReloadConfirm -eq "e") {
        Write-ColorOutput "`n🔄 Servisler yenileniyor..." $Yellow

        $reloadResults = @()
        foreach ($server in $validServers) {
            # Config bozuksa servise dokunma, aksi halde unbound açılmaz
            if (-not (Test-UnboundConfig -Server $server -Username $Username -MainConfigFile $MainConfigFile)) {
                Write-ColorOutput "[$server] Config geçersiz, yenileme yapılmadı" $Yellow
                $reloadResults += @{Server = $server; Success = $false}
                continue
            }

            # En hafif yoldan başla, her kademe başarısız olursa bir sonrakine geç
            $result = Invoke-UnboundReload -Server $server -Username $Username

            if (-not $result) {
                Write-ColorOutput "[$server] systemctl reload deneniyor" $Yellow
                $result = Invoke-UnboundServiceReload -Server $server -Username $Username
            }

            if (-not $result) {
                Write-ColorOutput "[$server] Servisi yeniden başlatmaya geçiliyor" $Yellow
                $result = Restart-UnboundService -Server $server -Username $Username
            }

            $reloadResults += @{Server = $server; Success = $result}
        }

        # Sonuçları özetle
        Write-Host ("`n" + ("=" * 60)) -ForegroundColor $Cyan
        Write-ColorOutput "YENİLEME SONUÇLARI:" $Cyan
        Write-Host ("=" * 60) -ForegroundColor $Cyan

        foreach ($result in $reloadResults) {
            if ($result.Success) {
                Write-ColorOutput "[$($result.Server)] ✅ Başarılı" $Green
            }
            else {
                Write-ColorOutput "[$($result.Server)] ❌ Başarısız" $Red
            }
        }
    }
}

Write-ColorOutput "`n👋 Script tamamlandı. İyi çalışmalar!" $Green