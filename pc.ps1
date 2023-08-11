function Check {
    ######################################################## START ########################################################
    ####################### PC-01 #######################
    Write-Host "[PC-01] 최대 암호 사용 기간이 90일 이하로 설정되어 있는지 점검"
    $adminName = $env:USERNAME
    $expiration = net user $adminName | Select-String "암호 만료"
    $account = net accounts | Select-String "암호 사용 기간"

    $min_password_priod_of_use = $account | Select-String "최소"
    $min_password_priod_of_use = $min_password_priod_of_use.Line.Substring($min_password_priod_of_use.Line.IndexOf("최소 암호 사용 기간 (일):") + "최소 암호 사용 기간 (일):".Length).Trim()


    $max_password_priod_of_use = $account | Select-String "최대"
    $max_password_priod_of_use = $max_password_priod_of_use.Line.Substring($max_password_priod_of_use.Line.IndexOf("최대 암호 사용 기간 (일):") + "최소 암호 사용 기간 (일):".Length).Trim()

    $password_expiration = $expiration.Line.Substring($expiration.Line.IndexOf("암호 만료 날짜") + "암호 만료 날짜".Length).Trim()
    if($password_expiration -eq "기한 없음"){
        Write-Host "[취약] 암호 만료 날짜가 기한 없음으로 설정되어 있습니다." -ForegroundColor Red
    }
    if($max_password_priod_of_use -gt 90) {
        Write-Host "[취약] 최대 암호 기간이 $($max_password_priod_of_use)일으로 90일 이상으로 설정되어있습니다." -ForegroundColor Red
    }else{
        Write-Host "[양호] 최대 암호 기간이 $($max_password_priod_of_use)일으로 90일 미만으로 설정되어있습니다." -ForegroundColor Green
    }

    Write-Host ""

    ####################### PC-02 #######################
    Write-Host "[PC-02] 패스워드 설정 정책이 복잡성을 만족하는지 점검"

    Write-Host "[정보] 패스워드 복잡성 수동 점검 요망" -ForegroundColor Magenta

    $userAccount = Get-WmiObject -Class Win32_UserAccount -Filter "Name='$adminName'"
    $passwordRequired = $userAccount.PasswordRequired

    if($passwordRequired){
        Write-Host "[양호] 암호를 사용중입니다." -ForegroundColor Green
    }else{
        Write-Host "[취약] 암호를 사용하지 않고있습니다." -ForegroundColor Red
    }

    Write-Host ""

    ####################### PC-03 #######################
    Write-Host "[PC-03] 기본 공유 폴더(C$, D$, Admin$), 미사용 공유 폴더가 존재하는지 점검,`n공유 폴더를 사용하는 경우 접근 권한에 Everyone이 존재하거나 접근을 위한 암호가 설정되어 있는지 점검"

    $sharedFolder = net share | Select-String "기본 공유"

    if($sharedFolder){
        foreach($line in $sharedFolder){
            if ($line -match "기본 공유") {
                $sharedName = $line -replace '\s+', ' ' -split ' ' | Select-Object -Index 0
                Write-Host "[취약] $($sharedName)(이)라는 기본 공유 파일이 존재합니다." -ForegroundColor Red
            }
        }
    }else{
        Write-Host "[양호] 기본 공유 파일이 존재하지 않습니다." -ForegroundColor Green
    }

    Write-Host ""

    ####################### PC-04 #######################
    Write-Host "[PC-04] 사용하지 않는 서비스나 디폴트로 설치되어 실행되고 있는 서비스가 있는지 점검"

    try {
        $runningServices = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' }
        $Good = $true

        foreach ($service in $runningServices) {
            try {
                if (
                    $service.DisplayName -eq 'Alerter' -or
                    $service.DisplayName -eq 'Automatic Updates' -or
                    $service.DisplayName -eq 'Clipbook' -or
                    $service.DisplayName -eq 'Computer Browser' -or
                    $service.DisplayName -eq 'Cryptographic Services' -or
                    $service.DisplayName -eq 'DHCP Client' -or
                    $service.DisplayName -eq 'Distributed Link Tracking Client' -or
                    $service.DisplayName -eq 'DNS Client' -or
                    $service.DisplayName -eq 'Error reporting Service' -or
                    $service.DisplayName -eq 'Human Interface Device Access' -or
                    $service.DisplayName -eq 'MAPI CD-Burning COM Service' -or
                    $service.DisplayName -eq 'Infrared Monitor' -or
                    $service.DisplayName -eq 'Messenger' -or
                    $service.DisplayName -eq 'NetMeeting Remote Desktop Sharing' -or
                    $service.DisplayName -eq 'Portable Media Serial Number' -or
                    $service.DisplayName -eq 'Print Spooler' -or
                    $service.DisplayName -eq 'Remote Registry' -or
                    $service.DisplayName -eq 'Simple TCP/IP Services' -or
                    $service.DisplayName -eq 'Universal Plug and Play Device Host' -or
                    $service.DisplayName -eq 'Wireless Zero Configuration'
                ) {
                    Write-Host "[취약] $($service.DisplayName)라는 불필요한 서비스가 구동 중입니다." -ForegroundColor Red
                    $Good = $false
                }
            } catch {
                Write-Host "서비스 조회 오류: $($service.DisplayName) - $($_.Exception.Message)" -ForegroundColor Red
            }
        }

        if ($Good) {
            Write-Host "[양호] 일반적으로 불필요한 서비스가 중지되어 있습니다." -ForegroundColor Green
        }
    } catch {
        Write-Host "오류 발생: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host ""

    ####################### PC-05 #######################
    Write-Host "[PC-05] 사용자 PC에서 상용 메신저를 사용하고 있는지를 점검"
    Write-Host "[정보] Windows Messenger가 실행 중인경우 실행 허용 안 함으로 설정 및 상용 메신저가 설치되어있는지 확인 후 삭제 요망" -ForegroundColor Magenta

    $processes = Get-WmiObject -Class Win32_Process

    foreach ($process in $processes) {
        if (
            $process.Name -like '*KakaoTalk*' -or
            $process.Name -like '*Discord*'
        ) {
            Write-Host "[취약] PID가 $($process.ProcessId)인 $($process.Name)(이)라는 상용 메신저가 실행 중입니다." -ForegroundColor Red
        }
    }

    $uninstallKey32 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

    $programs = Get-ChildItem $uninstallKey32 |
                Get-ItemProperty |
                Where-Object { $_.DisplayName -and $_.UninstallString } |
                Select-Object DisplayName, DisplayVersion

    foreach ($program in $programs) {
        if (
            $program.DisplayName -like '*카카오톡*' -or
            $program.DisplayName -like '*토크온*'
        ) {
            Write-Host "[취약] $($program.DisplayName)(이)라는 상용 메신저가 설치되어 있습니다." -ForegroundColor Red
        }
    }


    $uninstallKey64 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    $programs = Get-ChildItem $uninstallKey64 |
                Get-ItemProperty |
                Where-Object { $_.DisplayName -and $_.UninstallString } |
                Select-Object DisplayName, DisplayVersion

    foreach ($program in $programs) {
        if (
            $program.DisplayName -like '*카카오톡*' -or
            $program.DisplayName -like '*토크온*'
        ) {
            Write-Host "[취약] $($program.DisplayName)(이)라는 상용 메신저가 설치되어 있습니다." -ForegroundColor Red
        }
    }

    Write-Host ""

    ####################### PC-06 #######################
    Write-Host "[PC-06] 시스템에 관련한 공개된 취약점에 대한 최신 보안패치를 적용하였는지 점검"

    $hotfixes = Get-HotFix | Where-Object { $_.Description -like "Security Update*" }

    $patchOk = $True
    foreach ($hotfix in $hotfixes) {
        if (-not $hotfix.InstalledOn) {
            $patchOk = $false
        }
    }

    if(-not $patchOk){
        Write-Host "[취약] 최신 보안 업데이트가 설치되지 않았습니다." -ForegroundColor Red
        foreach ($hotfix in $hotfixes) {
        if (-not $hotfix.InstalledOn) {
            Write-Host "핫픽스 ID: $($hotfix.HotFixID)" -ForegroundColor Red
        }
    }
    }else{
        Write-Host "[양호] 보안 업데이트가 최신으로 설치되었습니다." -ForegroundColor Green
    }

    ######### 윈도우 레지스트리 키로 윈도우 버전 확인(window11이 window10으로 표시되는 경우가 있다) #########
    #$currentVersionKey = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    #$windowsVersion = $currentVersionKey.ProductName
    #
    #$version = ($windowsVersion -split ' ')[0,1] -join ' '
    #
    #if($version -eq 'Windows 10' -or $version -eq 'Windows 11'){
    #    Write-Host "[양호] 현재 윈도우 버전이 $($windowsVersion)입니다." -ForegroundColor Green
    #}else{
    #    Write-Host "[취약] 현재 윈도우 버전이 $($windowsVersion)입니다. Windows 10(11)으로 업그레이드할 것을 권장합니다." -ForegroundColor Red
    #}

    $windowsVersion = (Get-WmiObject Win32_OperatingSystem).Caption
    $version = ($windowsVersion -split ' ')[1,2] -join ' '
    if($version -eq 'Windows 10' -or $version -eq 'Windows 11'){
        Write-Host "[양호] 현재 윈도우 버전은 $($version)입니다." -ForegroundColor Green
    }else{
        Write-Host "[취약] 현재 윈도우 버전은 $($version)입니다. Windows 10(11)으로 업그레이드할 것을 권장합니다." -ForegroundColor Red
    }

    Write-Host ""

    ####################### PC-07 #######################
    Write-Host "[PC-07] 시스템에 최신 서비스팩이 적용되어 있는지 점검"
    Write-Host "[정보] Windows Update 사이트에 접속하여 최신 서비스팩 여부 확인 및 적용 확인 요망" -ForegroundColor Magenta
    Write-Host ""

    ####################### PC-08 #######################
    Write-Host "[PC-08] 운영체제에 설치된 응용프로그램(MS-Office, 한글, 어도비, 아크로뱃 등)의 최신 보안패치가 되어 있는지 점검"
    Write-Host "[정보] 설치된 응용 프로그램의 최신 패치가 적용되어 있는지 점검 요망" -ForegroundColor Magenta
    Write-Host ""

    ####################### PC-09 #######################
    Write-Host "[PC-09] 시스템에 백신이 설치되어 있는지 점검, 설치된 백신이 주기적으로 자동 업데이트되도록 설정되어 있는지 백신의 환경설정 점검"
    $runningServices = Get-Service | Where-Object { $_.Status -eq 'Running' }

    $running1 = $false
    $running2 = $false

    foreach ($service in $runningServices) {
        if($service.DisplayName -like "*Windows Defender*"){
            $running1 = $true
            Write-Host "[양호] $($service.DisplayName)이 실행중입니다." -ForegroundColor Green
        }elseif($service.DisplayName -like "*AhnLab Safe Transaction Service*"){
            $running2 = $true
            Write-Host "[양호] $($service.DisplayName)가 실행중입니다." -ForegroundColor Green
        }
    }

    if(-not $running1){
        Write-Host "[취약] Windows Defender Firewall이 실행중이지 않습니다." -ForegroundColor Red
    }
    if(-not $running2){
        Write-Host "[취약] AhnLab Safe Transaction Service가 실행중이지 않습니다." -ForegroundColor Red
    }

    Write-Host "[정보] 최신 업데이트 점검 요망" -ForegroundColor Magenta

    Write-Host ""

    ####################### PC-10 #######################
    Write-Host "[PC-10] 시스템에 설치된 백신 프로그램의 환경 설정에 실시간 감시 기능이 적용되어 있는지 점검"

    $realTimeProtection = Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled

    if ($realTimeProtection) {
        Write-Host "[양호] Windows Defender의 실시간 보호가 켜져 있습니다." -ForegroundColor Green
    } else {
        Write-Host "[취약] Windows Defender의 실시간 보호가 꺼져 있습니다." -ForegroundColor Red
    }

    Write-Host ""

    ####################### PC-11 #######################
    Write-Host "[PC-11] 시스템의 방화벽 기능이 활성화되어 있는지 점검"

    $fireWallMgr = New-Object -ComObject HNetCfg.FwMgr
    $fireWallOK = $fireWallMgr.LocalPolicy.CurrentProfile.FirewallEnabled

    if($fireWallOK){
        Write-Host "[양호] Windows 방화벽이 사용중입니다." -ForegroundColor Green
    }else{
        Write-Host "[취약] Windows 방화벽이 사용중이지 않습니다." -ForegroundColor Red
    }

    Write-Host ""

    ####################### PC-12 #######################
    Write-Host "[PC-12] 화면보호기 대기 시간 및 화면보호기 재시작 시 암호 설정 여부 점검"

    $screenSaverWaitTime = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name ScreenSaveTimeOut -ErrorAction SilentlyContinue

    if ($null -eq $screenSaverWaitTime) {
        Write-Host "[취약] 화면 보호기 대기 시간 설정이 되어있지 않습니다." -ForegroundColor Red
    }elseif($screenSaverWaitTime -gt 10){
        Write-Host "[취약] 화면 보호기 대기 시간이 10분 초과로 되어있습니다." -ForegroundColor Red
    }else{
        Write-Host "[양호] 화면 보호기 대기 시간이 10분 이하로 되어있습니다." -ForegroundColor Green
    }

    $screenSaverSecure = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name ScreenSaverIsSecure -ErrorAction SilentlyContinue
    if ($screenSaverSecure -eq 1) {
        Write-Host "[양호] 화면 보호기에 암호가 설정되어 있습니다." -ForegroundColor Green
    } else {
        Write-Host "[취약] 화면 보호기에 암호가 설정되어 있지 않습니다." -ForegroundColor Red
    }

    Write-Host ""

    ####################### PC-13 #######################
    Write-Host "[PC-13] 이동식 미디어에 대한 보안대책 수립 여부 점검"

    $drivesAutoRun = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue| Select-Object -ExpandProperty NoDriveTypeAutoRun
    if($drivesAutoRun -eq 255){
        Write-Host "[양호] 모든 드라이브의 자동 실행이 제한되어 있습니다." -ForegroundColor Green
    }else{
        Write-Host "[취약] 모든 드라이브의 자동 실행이 제한되어 있지 않습니다." -ForegroundColor Red
    }

    Write-Host ""

    ####################### PC-14 #######################
    Write-Host "[PC-14] 장기간(3개월) 사용하지 않은 ActiveX 존재 여부 점검"
    Write-Host "[정보] 설치된 ActiveX를 주기적(매달 1번 권고)으로 점검하고 불필요한 ActiveX 삭제 요망" -ForegroundColor Magenta
    Write-Host ""

    ####################### PC-15 #######################
    Write-Host "[PC-15] 윈도우 복구 콘솔 자동 로그인 설정이 허용되어 있는지 점검"

    $securityLevel = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" -Name SecurityLevel -ErrorAction SilentlyContinue
    if($securityLevel -ne $null){
        if($securityLevel.SecurityLevel -eq 1){
            Write-Host "[양호] 복구 콘솔 자동 로그인 허용이 사용으로 설정되어있습니다." -ForegroundColor Green
        }elseif($securityLevel.SecurityLevel -eq 0){
            Write-Host "[취약] 복구 콘솔 자동 로그인 허용이 사용 안 함으로 설정되어있습니다." -ForegroundColor Red
        }
    }else{
        Write-Host "[취약] 복구 콘솔 자동 로그인 설정을 확인할 수 없습니다." -ForegroundColor Red
    }

    Write-Host ""

    ####################### PC-16 #######################
    Write-Host "[PC-16] 하드 디스크의 파일 시스템이 NTFS를 사용하고 있는 지를 점검"

    $fileSystem = Get-WmiObject -Query "SELECT * FROM Win32_Volume" | Where-Object { $_.DriveLetter -ne $null } | Select-Object DriveLetter, FileSystem
    $ntfsCount = 0
    $fat32Count = 0

    foreach($line in $fileSystem){  
        if($line.Filesystem -eq 'FAT32'){
            $fat32Count += 1
        }else{
            $ntfsCount += 1
        }
    }

    if($ntfsCount -eq 0 -and $fat32Count -ge 1){
        Write-Host "[취약] 모든 디스크 볼륨의 파일 시스템이 FAT32입니다." -ForegroundColor Red
    }elseif($fat32Count -eq 0 -and $ntfsCount -ge 1){
        Write-Host "[양호] 모든 디스크 볼륨의 파일 시스템이 NTFS입니다." -ForegroundColor Green
    }else{
        Write-Host "[취약] 파일 시스템이 NTFS인 디스크의 개수는 $($ntfsCount)이며 파일 시스템이 FAT32인 디스크의 개수는 $($fat32Count)입니다." -ForegroundColor Red
        $fileSystem
    }

    Write-Host ""

    ####################### PC-17 #######################
    Write-Host "[PC-17] 사용자 PC에 하나의 OS만 설치되어 있는지 점검"

    $bcdeditResult = bcdedit
    $bootLoaderCount = ($bcdeditResult | Select-String "부팅 로더").Count

    if ($bootLoaderCount -eq 1) {
        Write-Host "[양호] PC 내에 하나의 OS만 설치되어 있습니다." -ForegroundColor Green
    }else{
        Write-Host "[취약] PC 내에 2개 이상의 OS가 설치되어 있습니다." -ForegroundColor Red
    }

    Write-Host ""

    ####################### PC-18 #######################
    Write-Host "[PC-18] 브라우저 인터넷 옵션에 있는 고급 설정에 '브라우저를 닫을 때 임시 인터넷 파일 폴더 비우기 기능'이 활성화 되어 있는지 점검"

    $emptyFolder = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Cache" -Name Persistent -ErrorAction SilentlyContinue

    if($emptyFolder -ne $null)
    {
        if($emptyFolder.Persistent -eq 0){
            Write-Host "[양호] 브라우저를 닫을 때 임시 인터넷 파일 폴더 비우기 설정이 사용으로 설정되어 있습니다." -ForegroundColor Green
        }else{
            Write-Host "[취약] 브라우저를 닫을 때 임시 인터넷 파일 폴더 비우기 설정이 사용으로 설정되어 있지 않습니다." -ForegroundColor Red
        }
    }

    Write-Host ""

    ####################### PC-19 #######################
    Write-Host "[PC-19] 원격 지원을 사용하지 않도록 설정하고 있는지 점검"

    $remoteAssistanceKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
    $remoteAssistanceValue = Get-ItemProperty -Path $remoteAssistanceKey -Name fAllowToGetHelp -ErrorAction SilentlyContinue


    if ($remoteAssistanceValue -ne $null) {
        if($remoteAssistanceValue.fAllowToGetHelp -eq 0){
            Write-Host "[양호] 원격 지원이 비활성화 되어있습니다." -ForegroundColor Green
        }else{
            Write-Host "[취약] 원격 지원이 활성화 되어있습니다." -ForegroundColor Red
        }
    
    }

    ######################################################### END #########################################################
}

function SaveFile {
    ######################################################## START ########################################################
    ####################### PC-01 #######################
    Write-Output "[PC-01] 최대 암호 사용 기간이 90일 이하로 설정되어 있는지 점검"
    $adminName = $env:USERNAME
    $expiration = net user $adminName | Select-String "암호 만료"
    $account = net accounts | Select-String "암호 사용 기간"

    $min_password_priod_of_use = $account | Select-String "최소"
    $min_password_priod_of_use = $min_password_priod_of_use.Line.Substring($min_password_priod_of_use.Line.IndexOf("최소 암호 사용 기간 (일):") + "최소 암호 사용 기간 (일):".Length).Trim()


    $max_password_priod_of_use = $account | Select-String "최대"
    $max_password_priod_of_use = $max_password_priod_of_use.Line.Substring($max_password_priod_of_use.Line.IndexOf("최대 암호 사용 기간 (일):") + "최소 암호 사용 기간 (일):".Length).Trim()

    $password_expiration = $expiration.Line.Substring($expiration.Line.IndexOf("암호 만료 날짜") + "암호 만료 날짜".Length).Trim()
    if($password_expiration -eq "기한 없음"){
        Write-Output "[취약] 암호 만료 날짜가 기한 없음으로 설정되어 있습니다."
    }
    if($max_password_priod_of_use -gt 90) {
        Write-Output "[취약] 최대 암호 기간이 $($max_password_priod_of_use)일으로 90일 이상으로 설정되어있습니다."
    }else{
        Write-Output "[양호] 최대 암호 기간이 $($max_password_priod_of_use)일으로 90일 미만으로 설정되어있습니다."
    }

    Write-Output ""

    ####################### PC-02 #######################
    Write-Output "[PC-02] 패스워드 설정 정책이 복잡성을 만족하는지 점검"

    Write-Output "[정보] 패스워드 복잡성 수동 점검 요망"

    $userAccount = Get-WmiObject -Class Win32_UserAccount -Filter "Name='$adminName'"
    $passwordRequired = $userAccount.PasswordRequired

    if($passwordRequired){
        Write-Output "[양호] 암호를 사용중입니다."
    }else{
        Write-Output "[취약] 암호를 사용하지 않고있습니다."
    }

    Write-Output ""

    ####################### PC-03 #######################
    Write-Output "[PC-03] 기본 공유 폴더(C$, D$, Admin$), 미사용 공유 폴더가 존재하는지 점검,`n공유 폴더를 사용하는 경우 접근 권한에 Everyone이 존재하거나 접근을 위한 암호가 설정되어 있는지 점검"

    $sharedFolder = net share | Select-String "기본 공유"

    if($sharedFolder){
        foreach($line in $sharedFolder){
            if ($line -match "기본 공유") {
                $sharedName = $line -replace '\s+', ' ' -split ' ' | Select-Object -Index 0
                Write-Output "[취약] $($sharedName)(이)라는 기본 공유 파일이 존재합니다."
            }
        }
    }else{
        Write-Output "[양호] 기본 공유 파일이 존재하지 않습니다."
    }

    Write-Output ""

    ####################### PC-04 #######################
    Write-Output "[PC-04] 사용하지 않는 서비스나 디폴트로 설치되어 실행되고 있는 서비스가 있는지 점검"

    try {
        $runningServices = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' }
        $Good = $true

        foreach ($service in $runningServices) {
            try {
                if (
                    $service.DisplayName -eq 'Alerter' -or
                    $service.DisplayName -eq 'Automatic Updates' -or
                    $service.DisplayName -eq 'Clipbook' -or
                    $service.DisplayName -eq 'Computer Browser' -or
                    $service.DisplayName -eq 'Cryptographic Services' -or
                    $service.DisplayName -eq 'DHCP Client' -or
                    $service.DisplayName -eq 'Distributed Link Tracking Client' -or
                    $service.DisplayName -eq 'DNS Client' -or
                    $service.DisplayName -eq 'Error reporting Service' -or
                    $service.DisplayName -eq 'Human Interface Device Access' -or
                    $service.DisplayName -eq 'MAPI CD-Burning COM Service' -or
                    $service.DisplayName -eq 'Infrared Monitor' -or
                    $service.DisplayName -eq 'Messenger' -or
                    $service.DisplayName -eq 'NetMeeting Remote Desktop Sharing' -or
                    $service.DisplayName -eq 'Portable Media Serial Number' -or
                    $service.DisplayName -eq 'Print Spooler' -or
                    $service.DisplayName -eq 'Remote Registry' -or
                    $service.DisplayName -eq 'Simple TCP/IP Services' -or
                    $service.DisplayName -eq 'Universal Plug and Play Device Host' -or
                    $service.DisplayName -eq 'Wireless Zero Configuration'
                ) {
                    Write-Output "[취약] $($service.DisplayName)라는 불필요한 서비스가 구동 중입니다."
                    $Good = $false
                }
            } catch {
                Write-Output "서비스 조회 오류: $($service.DisplayName) - $($_.Exception.Message)"
            }
        }

        if ($Good) {
            Write-Output "[양호] 일반적으로 불필요한 서비스가 중지되어 있습니다."
        }
    } catch {
        Write-Output "오류 발생: $($_.Exception.Message)"
    }

    Write-Output ""

    ####################### PC-05 #######################
    Write-Output "[PC-05] 사용자 PC에서 상용 메신저를 사용하고 있는지를 점검"
    Write-Output "[정보] Windows Messenger가 실행 중인경우 실행 허용 안 함으로 설정 및 상용 메신저가 설치되어있는지 확인 후 삭제 요망"

    $processes = Get-WmiObject -Class Win32_Process

    foreach ($process in $processes) {
        if (
            $process.Name -like '*KakaoTalk*' -or
            $process.Name -like '*Discord*'
        ) {
            Write-Output "[취약] PID가 $($process.ProcessId)인 $($process.Name)(이)라는 상용 메신저가 실행 중입니다."
        }
    }

    $uninstallKey32 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

    $programs = Get-ChildItem $uninstallKey32 |
                Get-ItemProperty |
                Where-Object { $_.DisplayName -and $_.UninstallString } |
                Select-Object DisplayName, DisplayVersion

    foreach ($program in $programs) {
        if (
            $program.DisplayName -like '*카카오톡*' -or
            $program.DisplayName -like '*토크온*'
        ) {
            Write-Output "[취약] $($program.DisplayName)(이)라는 상용 메신저가 설치되어 있습니다."
        }
    }


    $uninstallKey64 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    $programs = Get-ChildItem $uninstallKey64 |
                Get-ItemProperty |
                Where-Object { $_.DisplayName -and $_.UninstallString } |
                Select-Object DisplayName, DisplayVersion

    foreach ($program in $programs) {
        if (
            $program.DisplayName -like '*카카오톡*' -or
            $program.DisplayName -like '*토크온*'
        ) {
            Write-Output "[취약] $($program.DisplayName)(이)라는 상용 메신저가 설치되어 있습니다."
        }
    }

    Write-Output ""

    ####################### PC-06 #######################
    Write-Output "[PC-06] 시스템에 관련한 공개된 취약점에 대한 최신 보안패치를 적용하였는지 점검"

    $hotfixes = Get-HotFix | Where-Object { $_.Description -like "Security Update*" }

    $patchOk = $True
    foreach ($hotfix in $hotfixes) {
        if (-not $hotfix.InstalledOn) {
            $patchOk = $false
        }
    }

    if(-not $patchOk){
        Write-Output "[취약] 최신 보안 업데이트가 설치되지 않았습니다."
        foreach ($hotfix in $hotfixes) {
        if (-not $hotfix.InstalledOn) {
            Write-Output "핫픽스 ID: $($hotfix.HotFixID)"
        }
    }
    }else{
        Write-Output "[양호] 보안 업데이트가 최신으로 설치되었습니다."
    }

    $windowsVersion = (Get-WmiObject Win32_OperatingSystem).Caption
    $version = ($windowsVersion -split ' ')[1,2] -join ' '
    if($version -eq 'Windows 10' -or $version -eq 'Windows 11'){
        Write-Output "[양호] 현재 윈도우 버전은 $($version)입니다."
    }else{
        Write-Output "[취약] 현재 윈도우 버전은 $($version)입니다. Windows 10(11)으로 업그레이드할 것을 권장합니다."
    }

    Write-Output ""

    ####################### PC-07 #######################
    Write-Output "[PC-07] 시스템에 최신 서비스팩이 적용되어 있는지 점검"
    Write-Output "[정보] Windows Update 사이트에 접속하여 최신 서비스팩 여부 확인 및 적용 확인 요망"
    Write-Output ""

    ####################### PC-08 #######################
    Write-Output "[PC-08] 운영체제에 설치된 응용프로그램(MS-Office, 한글, 어도비, 아크로뱃 등)의 최신 보안패치가 되어 있는지 점검"
    Write-Output "[정보] 설치된 응용 프로그램의 최신 패치가 적용되어 있는지 점검 요망"
    Write-Output ""

    ####################### PC-09 #######################
    Write-Output "[PC-09] 시스템에 백신이 설치되어 있는지 점검, 설치된 백신이 주기적으로 자동 업데이트되도록 설정되어 있는지 백신의 환경설정 점검"
    $runningServices = Get-Service | Where-Object { $_.Status -eq 'Running' }

    $running1 = $false
    $running2 = $false

    foreach ($service in $runningServices) {
        if($service.DisplayName -like "*Windows Defender*"){
            $running1 = $true
            Write-Output "[양호] $($service.DisplayName)이 실행중입니다."
        }elseif($service.DisplayName -like "*AhnLab Safe Transaction Service*"){
            $running2 = $true
            Write-Output "[양호] $($service.DisplayName)가 실행중입니다."
        }
    }

    if(-not $running1){
        Write-Output "[취약] Windows Defender Firewall이 실행중이지 않습니다."
    }
    if(-not $running2){
        Write-Output "[취약] AhnLab Safe Transaction Service가 실행중이지 않습니다."
    }

    Write-Output "[정보] 최신 업데이트 점검 요망"

    Write-Output ""

    ####################### PC-10 #######################
    Write-Output "[PC-10] 시스템에 설치된 백신 프로그램의 환경 설정에 실시간 감시 기능이 적용되어 있는지 점검"

    $realTimeProtection = Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled

    if ($realTimeProtection) {
        Write-Output "[양호] Windows Defender의 실시간 보호가 켜져 있습니다."
    } else {
        Write-Output "[취약] Windows Defender의 실시간 보호가 꺼져 있습니다."
    }

    Write-Output ""

    ####################### PC-11 #######################
    Write-Output "[PC-11] 시스템의 방화벽 기능이 활성화되어 있는지 점검"

    $fireWallMgr = New-Object -ComObject HNetCfg.FwMgr
    $fireWallOK = $fireWallMgr.LocalPolicy.CurrentProfile.FirewallEnabled

    if($fireWallOK){
        Write-Output "[양호] Windows 방화벽이 사용중입니다."
    }else{
        Write-Output "[취약] Windows 방화벽이 사용중이지 않습니다."
    }

    Write-Output ""

    ####################### PC-12 #######################
    Write-Output "[PC-12] 화면보호기 대기 시간 및 화면보호기 재시작 시 암호 설정 여부 점검"

    $screenSaverWaitTime = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name ScreenSaveTimeOut -ErrorAction SilentlyContinue

    if ($null -eq $screenSaverWaitTime) {
        Write-Output "[취약] 화면 보호기 대기 시간 설정이 되어있지 않습니다."
    }elseif($screenSaverWaitTime -gt 10){
        Write-Output "[취약] 화면 보호기 대기 시간이 10분 초과로 되어있습니다."
    }else{
        Write-Output "[양호] 화면 보호기 대기 시간이 10분 이하로 되어있습니다."
    }

    $screenSaverSecure = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name ScreenSaverIsSecure -ErrorAction SilentlyContinue
    if ($screenSaverSecure -eq 1) {
        Write-Output "[양호] 화면 보호기에 암호가 설정되어 있습니다."
    } else {
        Write-Output "[취약] 화면 보호기에 암호가 설정되어 있지 않습니다."
    }

    Write-Output ""

    ####################### PC-13 #######################
    Write-Output "[PC-13] 이동식 미디어에 대한 보안대책 수립 여부 점검"

    $drivesAutoRun = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue| Select-Object -ExpandProperty NoDriveTypeAutoRun
    if($drivesAutoRun -eq 255){
        Write-Output "[양호] 모든 드라이브의 자동 실행이 제한되어 있습니다."
    }else{
        Write-Output "[취약] 모든 드라이브의 자동 실행이 제한되어 있지 않습니다."
    }

    Write-Output ""

    ####################### PC-14 #######################
    Write-Output "[PC-14] 장기간(3개월) 사용하지 않은 ActiveX 존재 여부 점검"
    Write-Output "[정보] 설치된 ActiveX를 주기적(매달 1번 권고)으로 점검하고 불필요한 ActiveX 삭제 요망"
    Write-Output ""

    ####################### PC-15 #######################
    Write-Output "[PC-15] 윈도우 복구 콘솔 자동 로그인 설정이 허용되어 있는지 점검"

    $securityLevel = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" -Name SecurityLevel -ErrorAction SilentlyContinue
    if($securityLevel -ne $null){
        if($securityLevel.SecurityLevel -eq 1){
            Write-Output "[양호] 복구 콘솔 자동 로그인 허용이 사용으로 설정되어있습니다."
        }elseif($securityLevel.SecurityLevel -eq 0){
            Write-Output "[취약] 복구 콘솔 자동 로그인 허용이 사용 안 함으로 설정되어있습니다."
        }
    }else{
        Write-Output "[취약] 복구 콘솔 자동 로그인 설정을 확인할 수 없습니다."
    }

    Write-Output ""

    ####################### PC-16 #######################
    Write-Output "[PC-16] 하드 디스크의 파일 시스템이 NTFS를 사용하고 있는 지를 점검"

    $fileSystem = Get-WmiObject -Query "SELECT * FROM Win32_Volume" | Where-Object { $_.DriveLetter -ne $null } | Select-Object DriveLetter, FileSystem
    $ntfsCount = 0
    $fat32Count = 0

    foreach($line in $fileSystem){  
        if($line.Filesystem -eq 'FAT32'){
            $fat32Count += 1
        }else{
            $ntfsCount += 1
        }
    }

    if($ntfsCount -eq 0 -and $fat32Count -ge 1){
        Write-Output "[취약] 모든 디스크 볼륨의 파일 시스템이 FAT32입니다."
    }elseif($fat32Count -eq 0 -and $ntfsCount -ge 1){
        Write-Output "[양호] 모든 디스크 볼륨의 파일 시스템이 NTFS입니다."
    }else{
        Write-Output "[취약] 파일 시스템이 NTFS인 디스크의 개수는 $($ntfsCount)이며 파일 시스템이 FAT32인 디스크의 개수는 $($fat32Count)입니다."
        $fileSystem
    }

    Write-Output ""

    ####################### PC-17 #######################
    Write-Output "[PC-17] 사용자 PC에 하나의 OS만 설치되어 있는지 점검"

    $bcdeditResult = bcdedit
    $bootLoaderCount = ($bcdeditResult | Select-String "부팅 로더").Count

    if ($bootLoaderCount -eq 1) {
        Write-Output "[양호] PC 내에 하나의 OS만 설치되어 있습니다."
    }else{
        Write-Output "[취약] PC 내에 2개 이상의 OS가 설치되어 있습니다."
    }

    Write-Output ""

    ####################### PC-18 #######################
    Write-Output "[PC-18] 브라우저 인터넷 옵션에 있는 고급 설정에 '브라우저를 닫을 때 임시 인터넷 파일 폴더 비우기 기능'이 활성화 되어 있는지 점검"

    $emptyFolder = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Cache" -Name Persistent -ErrorAction SilentlyContinue

    if($emptyFolder -ne $null)
    {
        if($emptyFolder.Persistent -eq 0){
            Write-Output "[양호] 브라우저를 닫을 때 임시 인터넷 파일 폴더 비우기 설정이 사용으로 설정되어 있습니다."
        }else{
            Write-Output "[취약] 브라우저를 닫을 때 임시 인터넷 파일 폴더 비우기 설정이 사용으로 설정되어 있지 않습니다."
        }
    }

    Write-Output ""

    ####################### PC-19 #######################
    Write-Output "[PC-19] 원격 지원을 사용하지 않도록 설정하고 있는지 점검"

    $remoteAssistanceKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
    $remoteAssistanceValue = Get-ItemProperty -Path $remoteAssistanceKey -Name fAllowToGetHelp -ErrorAction SilentlyContinue


    if ($remoteAssistanceValue -ne $null) {
        if($remoteAssistanceValue.fAllowToGetHelp -eq 0){
            Write-Output "[양호] 원격 지원이 비활성화 되어있습니다."
        }else{
            Write-Output "[취약] 원격 지원이 활성화 되어있습니다."
        }
    
    }

    ######################################################### END #########################################################
}
# 결과를 저장할 디렉토리 경로
$outputDirectory = "C:\PcCheckResult"

# 디렉토리가 없을 경우 생성
if (-not (Test-Path -Path $outputDirectory -PathType Container)) {
    New-Item -Path $outputDirectory -ItemType Directory
}

# 콘솔창 출력
Check

# 실행결과 파일로 저장
SaveFile | Out-File -FilePath "$outputDirectory\Result.txt"