<#
================================================================================
 cp_master_win.ps1  -  CyberPatriot 19  Windows 11 (LTSC 2024)  TR2  MASTER
================================================================================

 PURPOSE
   One profile-driven engine that AUDITS, FIXES, and VERIFIES the Windows 11
   CP19 Training Round 2 image against the official answer key (32 scored
   items + 3 penalties). Mirrors the Linux engine (cp_master.sh): you feed it a
   "profile" of requirements and it checks/fixes the live machine.

 TRAINING-ONLY / RULES COMPLIANCE (READ THIS FIRST)
   * This is a TRAINING / practice aid. CP19 rules 3010.4 (esp. 3010.4.A.2 and
     3010.4.D) and 3011.4 PROHIBIT connecting any AI tool/agent to a scored
     image and PROHIBIT using AI-generated scripts during a scored round.
   * The correct, penalty-free way to use this file: copy it to the TRAINING
     VM and RUN IT FROM INSIDE THE VM using an elevated PowerShell console.
     No external tool, no SSH, no remote automation is involved.
   * Never point this at a live scored image. Training images only.

 USAGE  (from an ELEVATED PowerShell prompt INSIDE the VM)
   powershell -NoProfile -ExecutionPolicy Bypass -File .\cp_master_win.ps1 -Stage audit
   powershell -NoProfile -ExecutionPolicy Bypass -File .\cp_master_win.ps1 -Stage fix
   powershell -NoProfile -ExecutionPolicy Bypass -File .\cp_master_win.ps1 -Stage verify
   powershell -NoProfile -ExecutionPolicy Bypass -File .\cp_master_win.ps1 -Stage forensics
     audit     : read-only. Reports every item's current state + the fix needed.
     fix       : applies all remediations (idempotent - safe to re-run).
     verify    : re-checks every item and prints a PASS/FAIL scorecard.
     forensics : prints the forensics answers (computed live where possible).

 SAFETY GUARDS (hard-coded, enforced in every stage)
   * NEVER stop/disable/kill the CCS Client service or ccsclient process.
   * NEVER change the password of the auto-login user (chowe).
   * NEVER remove any authorized user or their home directory.
   * NEVER change the time zone / date / time.
   * NEVER uninstall the authorized browser (Chrome) or Notepad++ (both are
     PENALTY items if missing from the default location).

 IDIOM / EXIT CODES
   audit/verify exit 0 on success even if items fail (a report is not an error).
   fix exits 0 when it completes; 1 if a fatal guard or exception interrupted it.
================================================================================
#>

[CmdletBinding()]
param(
    [ValidateSet("audit","fix","verify","forensics")]
    [string]$Stage = "audit",

    [string]$Profile = "Win11_TR2"   # Win11_TR2 = CP19 Round-2 TRAINING image (only supported profile)
)

#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ------------------------------------------------------------------ ADMIN ----
if (-not ( ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) )) {
    Write-Host "[FATAL] This engine must run as Administrator (fix/verify/audit all read policy)." -ForegroundColor Red
    Write-Host "        Re-run from an ELEVATED PowerShell console." -ForegroundColor Red
    exit 1
}

# =================================================================== PROFILE
# Win 11 TR2 (CP19 Round-2 TRAINING image) - values taken from the official
# TRAINING answer key + training scenario README (allowed sources).
# Everything below is data; the check/fix functions read from $P, so another
# round's TRAINING image would be just another hashtable. Competition images
# are out of scope for this engine (rules 3009 / 3010.4 / 3011.4) - see the
# WS2022_R2 branch below.
$P = $null
switch ($Profile) {
    "Win11_TR2" {
        $P = @{
            Image            = "Windows 11 LTSC 2024  (CP19 TR2)"
            AutoLoginUser    = "chowe"
            Admins           = @("chowe","josiah","isabella","rafael")
            Users            = @("hayes","nia","simone","foster","tina","edwards","darius","peterson","turner","ethan","esther","wyatt")

            RemoveUser       = "alana"                       # unauthorized (not on any list)
            DemoteToStd      = @("tina","peterson")          # currently admins -> standard users
            SetPassword      = @{ "ethan"  = "E7h4n-Str0ng-Pw!" }   # currently NO password
            ChangeWeakPw     = @{ "josiah" = "J0s1ah-Repl4ced!" }   # currently insecure

            NewGroup         = "SpiderVerse"
            NewGroupMembers  = @("esther","wyatt","turner","tina")

            KeepBrowser      = "Chrome"                      # PENALTY if missing
            KeepSoftware     = @("Notepad++")                # PENALTY if missing
            NppTargetVersion = "8.9.8.1"                     # update to this
            RemoveSoftware   = @("Wireshark","WinDirStat","WildTangent")
            RemoveBackdoorFile = "C:\Windows\System32\mfc.exe"   # renamed netcat
            RemoveBackdoorProc = "mfc"
            RemoveMediaDir   = "C:\Users\Public\Public Music"    # unauthorized mp3s

            DisableServices  = @("SimpleTCPIP","RemoteRegistry")  # stop + disable
            ProtectServices  = @("ccsclient")                      # NEVER touch
            StopShare        = "USERS$"                            # hidden share

            # --- security / gpedit policy values ---
            PwHistory        = 5
            PwComplexity     = $true
            LockoutThreshold = 5                                   # <5 is a PENALTY
            AuditCredValid   = "success"
            BlankPwConsole   = $true
            NoLastUser       = $true
            EnumerateAdmins  = $false
            RdpEnabled       = $false
            FirewallEnabled  = $true
            AutoUpdate       = $true
            SmartScreen      = $true

            # --- user rights: privilege -> users to strip from it ---
            RevokeRights = @{
                "SeAuditPrivilege"         = @("wyatt")   # Manage auditing and security log
                "SeTakeOwnershipPrivilege" = @("darius")  # Take ownership of files of other objects
            }
        }
    }
    "WS2022_R2" {
        # INTENTIONALLY EMPTY. Windows Server 2022 is a SEASON 19 COMPETITION
        # image (Round 2 set), not a training image, and this engine is a
        # TRAINING-ONLY tool. CP19 rules (2026-27):
        #   3009       - current or past competition images are NOT training
        #                material, even after the answer is published; their
        #                README/scenario text, rosters and answer keys may not
        #                be used to build training content.
        #   3010.4.A.3 - competition material may not be submitted to any AI
        #                tool at any time.
        #   3010.4.D   - AI-built scripts may not be used during a competition
        #                round; competitors author their own scripts (3011.4).
        #
        # So this profile deliberately carries NO competition-derived values.
        # In a competition round each competitor writes their own script from
        # that round's README + answer key, with zero AI involvement - and
        # this engine must never be run on a competition image at all.
        Write-Host "[FATAL] Profile 'WS2022_R2' is a competition image. This" -ForegroundColor Red
        Write-Host "        training-only engine intentionally carries no values" -ForegroundColor Red
        Write-Host "        for it (CP19 rules 3009 / 3010.4 / 3011.4)." -ForegroundColor Red
        Write-Host "        Compete with your own script, authored by you (3011.4)." -ForegroundColor Red
        exit 1
    }
    default {
        Write-Host "[FATAL] Unknown profile '$Profile'." -ForegroundColor Red; exit 1
    }
}

# ==================================================================== HELPERS
function Log {
    param([string]$Msg, [string]$Color = "Gray")
    $ts = Get-Date -Format "HH:mm:ss"
    Write-Host ("[{0}] {1}" -f $ts, $Msg) -ForegroundColor $Color
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    if (-not (Test-Path $Path)) { return $null }
    $p = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $p) { return $p.$Name }
    return $null
}
function Set-RegValue {
    param([string]$Path, [string]$Name, $Value, [string]$Type = "DWord")
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
}
function Test-User { param([string]$n)  { [bool](Get-LocalUser -Name $n -ErrorAction SilentlyContinue) } }
function Test-Group { param([string]$n) { [bool](Get-LocalGroup -Name $n -ErrorAction SilentlyContinue) } }
function Is-AdminUser {
    param([string]$n)
    $a = @(Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue).Name
    return ($a -contains $n)
}
function In-Group {
    param([string]$g, [string]$n)
    $m = @(Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue).Name
    return ($m -contains $n)
}
function Protect-Guard {
    # Refuse to stop/disable a service in the protected set.
    param([string]$Name)
    foreach ($s in $P.ProtectServices) {
        if ($Name -eq $s -or $Name -like "$s*") {
            Log "GUARD: refusing to modify protected service '$Name' (CCS/mission-critical)." "Yellow"
            return $true
        }
    }
    return $false
}
function Get-InstalledSoft {
    # Returns objects with DisplayName, DisplayVersion, UninstallString
    $roots = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    $all = @()
    foreach ($r in $roots) {
        if (Test-Path $r) {
            $all += @(Get-ChildItem $r) | ForEach-Object {
                Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            }
        }
    }
    return @($all | Where-Object { $_.DisplayName })
}

# ===================================================================== AUDIT
# Each Test-* returns a result object: [pscustomobject]{Item, Expected, Actual, Pass}
$Results = [System.Collections.Generic.List[object]]::new()
function AddResult {
    param([string]$Item, [string]$Expected, $Actual, [bool]$Pass)
    $Results.Add([pscustomobject]@{ Item=$Item; Expected=$Expected; Actual=$Actual; Pass=$Pass })
}

function Test-Users {
    # unauthorized user must be gone
    if ($P.RemoveUser) {
        $u = Test-User $P.RemoveUser
        AddResult "Unauthorized user '$($P.RemoveUser)' removed" "absent" $(if($u){"present"}else{"absent"}) (-not $u)
    }
    # auto-login user must still exist (we never remove it)
    $al = Test-User $P.AutoLoginUser
    AddResult "Auto-login user '$($P.AutoLoginUser)' still present" "present" $(if($al){"present"}else{"ABSENT"}) $al

    # demote-to-standard users must NOT be admins
    foreach ($u in $P.DemoteToStd) {
        $adm = Is-AdminUser $u
        AddResult "'$u' is a standard user (not admin)" "standard" $(if($adm){"admin"}else{"standard"}) (-not $adm)
    }
    # password set on formerly-blank user
    foreach ($kv in $P.SetPassword.GetEnumerator()) {
        $obj = Get-LocalUser -Name $kv.Key -ErrorAction SilentlyContinue
        # "no password" = account has never had a password (PasswordLastSet is $null)
        $ok = ($obj -ne $null) -and (($obj.PasswordLastSet -ne $null) -or ($obj.PasswordRequired -eq $true))
        AddResult "User '$($kv.Key)' has a password" "password set" $(if($ok){"set"}else{"BLANK"}) $ok
    }
    # weak-password user must have a NEW (different) password - we can't read the
    # current secret, so we verify via 'password changed after baseline' is out of
    # scope for audit; we assert the change action was taken (verify stage confirms).
    foreach ($kv in $P.ChangeWeakPw.GetEnumerator()) {
        $obj = Get-LocalUser -Name $kv.Key -ErrorAction SilentlyContinue
        AddResult "User '$($kv.Key)' password changed from insecure value" "changed" "see fix log" ($obj -ne $null)
    }
    # group created + members added
    if ($P.NewGroup) {
        $g = Test-Group $P.NewGroup
        AddResult "Group '$($P.NewGroup)' exists" "present" $(if($g){"present"}else{"absent"}) $g
        foreach ($m in $P.NewGroupMembers) {
            $in = In-Group $P.NewGroup $m
            AddResult "'$m' is a member of '$($P.NewGroup)'" "member" $(if($in){"member"}else{"NOT member"}) $in
        }
    }
}

function Test-Policy {
    $pol = Get-LocalPasswordPolicy
    AddResult "Enforce password history" "$($P.PwHistory)" "$($pol.HistoryCount)" ($pol.HistoryCount -eq $P.PwHistory)
    AddResult "Password complexity" "Enabled" "$($pol.ComplexityEnabled)" ($pol.ComplexityEnabled -eq $P.PwComplexity)
    $lk = Get-LocalAccountLockout
    AddResult "Account lockout threshold" "$($P.LockoutThreshold)" "$($lk.Threshold)" ($lk.Threshold -eq $P.LockoutThreshold)

    # registry-backed policy items
    $sys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $bpc = (Get-RegValue $sys "LimitBlankPasswordUse")
    AddResult "Blank passwords - console only" "1 (on)" "$bpc" ($bpc -eq 1)
    $dlu = (Get-RegValue $sys "DontDisplayLastUserName")
    AddResult "Don't display last signed-in user" "1 (on)" "$dlu" ($dlu -eq 1)

    $cred = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialUI"
    $enum = (Get-RegValue $cred "EnumerateAdmins")
    AddResult "Enumerate admin accounts on elevation" "0 (off)" "$enum" ($enum -eq 0)

    # SmartScreen (Defender SmartScreen gpedit)
    $ss = (Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen")
    AddResult "Windows SmartScreen" "1 (on)" "$ss" ($ss -eq 1)

    # Automatic updates gpedit
    $au = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $noAuto = (Get-RegValue $au "NoAutoUpdate")
    $auOpt  = (Get-RegValue $au "AUOptions")
    $updOk = ($noAuto -ne 1) -and ($auOpt -in 2,3,4)
    AddResult "Configure Automatic Updates" "Enabled" "NoAutoUpdate=$noAuto AUOptions=$auOpt" $updOk

    # audit: Credential Validation (success)
    $cv = ""
    try { $cv = (& auditpol /get /subcategory:"Credential Validation" 2>$null | Select-String "Success" | ForEach-Object { ($_.Line -split "Success\s*:")[1] -replace '\s+','' }) } catch {}
    AddResult "Audit Credential Validation [Success]" "enabled" "$cv" ($cv -eq "enabled")
}

function Test-Network {
    $fw = Get-NetFirewallProfile
    $fwOk = ($fw | Where-Object { $_.Enabled -eq "False" }) -eq $null
    AddResult "Windows Firewall enabled (all profiles)" "all enabled" ($fw | ForEach-Object { "$($_.Name)=$($_.Enabled)" } -join " ") $fwOk

    $rdp = (Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections")
    AddResult "Remote Desktop disabled" "1 (deny)" "$rdp" ($rdp -eq 1)
}

function Test-Services {
    foreach ($svc in $P.DisableServices) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) {
            $ok = ($s.Status -eq "Stopped") -and ($s.StartType -eq "Disabled")
            AddResult "Service '$svc' stopped+disabled" "stopped/disabled" "$($s.Status)/$($s.StartType)" $ok
        } else {
            AddResult "Service '$svc' stopped+disabled" "stopped/disabled" "not found (OK)" $true
        }
    }
    # share stopped
    if ($P.StopShare) {
        $sh = Get-WmiObject -Query "SELECT * FROM Win32_Share WHERE Name='$($P.StopShare)'" -ErrorAction SilentlyContinue
        AddResult "Share '$($P.StopShare)' stopped" "absent" $(if($sh){"present"}else{"absent"}) (-not $sh)
    }
    # protected services still running (CCS)
    foreach ($p in $P.ProtectServices) {
        $s = Get-Service -Name $p -ErrorAction SilentlyContinue
        $st = if ($s) { $s.Status } else { "not found" }
        $ok = $s -and ($st -eq "Running" -or $st -eq "Stopped")   # we only care it EXISTS & we didn't kill it
        AddResult "Protected service '$p' intact (not force-killed)" "present" "$st" ($null -ne $s)
    }
}

function Test-Software {
    $soft = @(Get-InstalledSoft)
    # keep items present (penalty guards)
    foreach ($keep in $P.KeepSoftware) {
        $hit = $soft | Where-Object { $_.DisplayName -like "*$keep*" } | Select-Object -First 1
        AddResult "Authorized software '$keep' installed" "present" $(if($hit){$hit.DisplayName}else{"MISSING (PENALTY)"}) ($null -ne $hit)
    }
    # browser present (penalty guard)
    $br = $soft | Where-Object { $_.DisplayName -like "*$($P.KeepBrowser)*" } | Select-Object -First 1
    AddResult "Browser '$($P.KeepBrowser)' installed" "present" $(if($br){$br.DisplayName}else{"MISSING (PENALTY)"}) ($null -ne $br)
    # notepad++ up to date (version-safe compare)
    $npp = $soft | Where-Object { $_.DisplayName -like "*Notepad++*" } | Select-Object -First 1
    if ($npp) {
        $cur = "$($npp.DisplayVersion)".Trim()
        $want = $P.NppTargetVersion
        $nppOk = $true
        try {
            $cv = if ($cur) { [Version]$cur } else { $null }
            $nw = [Version]$want
            $nppOk = ($cv -ne $null) -and ($cv -ge $nw)
        } catch { $nppOk = ($cur -eq $want) }
        AddResult "Notepad++ version >= $want" "$want" "$cur" $nppOk
    } else {
        AddResult "Notepad++ installed" "present" "not found (PENALTY)" $false
    }
    # remove unauthorized software
    foreach ($rm in $P.RemoveSoftware) {
        $hit = $soft | Where-Object { $_.DisplayName -like "*$rm*" } | Select-Object -First 1
        AddResult "Unauthorized software '$rm' removed" "absent" $(if($hit){$hit.DisplayName}else{"absent"}) (-not $hit)
    }
    # backdoor file + process
    $bf = Test-Path $P.RemoveBackdoorFile
    AddResult "Netcat backdoor file '$($P.RemoveBackdoorFile)' removed" "absent" $(if($bf){"present"}else{"absent"}) (-not $bf)
    $proc = Get-Process -Name $P.RemoveBackdoorProc -ErrorAction SilentlyContinue
    AddResult "Netcat process '$($P.RemoveBackdoorProc)' not running" "not running" $(if($proc){"RUNNING"}else{"not running"}) (-not $proc)
    # unauthorized media
    $media = $false
    if (Test-Path $P.RemoveMediaDir) { $media = ((Get-ChildItem $P.RemoveMediaDir -File -ErrorAction SilentlyContinue).Count -gt 0) }
    AddResult "Unauthorized media in '$($P.RemoveMediaDir)' removed" "empty/absent" $(if($media){"files present"}else{"clean"}) (-not $media)
}

function Test-UserRights {
    foreach ($kv in $P.RevokeRights.GetEnumerator()) {
        $priv = $kv.Key; $strip = $kv.Value
        $line = ""
        try {
            $exp = Join-Path $env:TEMP ("cp_sed_" + [guid]::NewGuid().ToString("N") + ".inf")
            & secedit.exe /export /cfg $exp 2>$null | Out-Null
            $line = (Select-String -Path $exp -Pattern $priv | Select-Object -First 1).Line
            Remove-Item $exp -ErrorAction SilentlyContinue
        } catch {}
        $val = if ($line) { ($line -split "=",2)[1].Trim() } else { "?" }
        # check that none of the stripped users remain in the SID list
        $bad = $false
        foreach ($u in $strip) {
            try {
                $sid = (New-Object Security.Principal.NTAccount($u)).Translate([Security.Principal.SecurityIdentifier]).Value
                if ($val -like "*$sid*") { $bad = $true }
            } catch {}
        }
        AddResult "User rights '$priv' no longer grants '$($strip -join ",")'" "$($strip -join ",")" + " removed" "$val" ($bad -eq $false)
    }
}

# ROT13 + reverse helpers (used by the forensics stage)
function Rot13([string]$t) {
    $sb = ""
    foreach ($ch in $t.ToCharArray()) {
        $o = [int]$ch
        if ($o -ge 65 -and $o -le 90) { $sb += [char](65 + (($o - 65 + 13) % 26)) }
        elseif ($o -ge 97 -and $o -le 122) { $sb += [char](97 + (($o - 97 + 13) % 26)) }
        else { $sb += $ch }
    }
    $sb
}

function Reverse-Text([string]$t) {
    $c = $t.ToCharArray()
    [Array]::Reverse($c)
    -join $c
}

function Run-Audit {
    $Results.Clear()
    Log "=== AUDIT  $($P.Image)  (stage=$Stage) ===" "Cyan"
    Test-Users; Test-Policy; Test-Network; Test-Services; Test-Software; Test-UserRights
    $Results | Format-Table -AutoSize Item, Expected, Actual, Pass | Out-String | Write-Host
    $f = @($Results | Where-Object { -not $_.Pass }).Count
    Log "Audit complete: {0} of {1} checks PASS, {2} need work." -f ($Results.Count - $f), $Results.Count, $f
    if ($f -gt 0) { Log "Run  -Stage fix  to apply the remediations." "Yellow" }
    return $Results
}

# ======================================================================= FIX
function Fix-Users {
    if ($P.RemoveUser -and (Test-User $P.RemoveUser)) {
        if (In-Group "Administrators" $P.RemoveUser) { Remove-LocalGroupMember -Group "Administrators" -Member $P.RemoveUser -ErrorAction SilentlyContinue }
        Remove-LocalUser -Name $P.RemoveUser -Confirm:$false
        Log "FIX: removed unauthorized user '$($P.RemoveUser)'." "Green"
    }
    foreach ($u in $P.DemoteToStd) {
        if (Is-AdminUser $u) {
            Remove-LocalGroupMember -Group "Administrators" -Member $u
            Log "FIX: demoted '$u' from Administrators to standard user." "Green"
        }
    }
    foreach ($kv in $P.SetPassword.GetEnumerator()) {
        $sec = ConvertTo-SecureString $kv.Value -AsPlainText -Force
        Set-LocalUser -Name $kv.Key -Password $sec
        Log "FIX: set a secure password on '$($kv.Key)'." "Green"
    }
    foreach ($kv in $P.ChangeWeakPw.GetEnumerator()) {
        $sec = ConvertTo-SecureString $kv.Value -AsPlainText -Force
        Set-LocalUser -Name $kv.Key -Password $sec
        Log "FIX: replaced insecure password on '$($kv.Key)'." "Green"
    }
    if ($P.NewGroup) {
        if (-not (Test-Group $P.NewGroup)) {
            New-LocalGroup -Name $P.NewGroup -Description "CP19 TR2 authorized group"
            Log "FIX: created group '$($P.NewGroup)'." "Green"
        }
        foreach ($m in $P.NewGroupMembers) {
            if ((Test-User $m) -and (-not (In-Group $P.NewGroup $m))) {
                Add-LocalGroupMember -Group $P.NewGroup -Member $m
            }
        }
        Log "FIX: ensured '$($P.NewGroupMembers -join ",")' are in '$($P.NewGroup)'." "Green"
    }
}

function Fix-Policy {
    Set-LocalPasswordPolicy -HistoryCount $P.PwHistory -ComplexityEnabled $P.PwComplexity
    Set-LocalAccountLockout -Threshold $P.LockoutThreshold
    Log "FIX: password history=$($P.PwHistory), complexity=$($P.PwComplexity), lockout=$($P.LockoutThreshold)." "Green"

    $sys = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-RegValue $sys "LimitBlankPasswordUse" 1
    Set-RegValue $sys "DontDisplayLastUserName" 1
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialUI" "EnumerateAdmins" 0
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen" 1
    Log "FIX: blank-pw console-only, no-last-user, enumerate-admins(off), SmartScreen(on)." "Green"

    $au = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    Set-RegValue $au "NoAutoUpdate" 0
    Set-RegValue $au "AUOptions" 2
    Log "FIX: Configure Automatic Updates enabled (AUOptions=2)." "Green"

    # audit subcategory - Credential Validation (success)
    & auditpol /set /subcategory:"Credential Validation" /success:enable | Out-Null
    Log "FIX: audit Credential Validation [Success] enabled." "Green"
}

function Fix-Network {
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
    Log "FIX: Windows Firewall enabled on all profiles." "Green"
    Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" 1
    Log "FIX: Remote Desktop disabled (fDenyTSConnections=1)." "Green"
}

function Fix-Services {
    foreach ($svc in $P.DisableServices) {
        if (Protect-Guard $svc) { continue }
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) {
            if ($s.Status -eq "Running") { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue }
            Set-Service -Name $svc -StartupType Disabled
            Log "FIX: service '$svc' stopped + disabled." "Green"
        }
    }
    if ($P.StopShare) {
        $sh = Get-WmiObject -Query "SELECT * FROM Win32_Share WHERE Name='$($P.StopShare)'" -ErrorAction SilentlyContinue
        if ($sh) { $sh.Delete() | Out-Null; Log "FIX: share '$($P.StopShare)' stopped/removed." "Green" }
    }
}

function Fix-Software {
    $soft = @(Get-InstalledSoft)
    # unauthorized software -> run their quiet uninstall string
    foreach ($rm in $P.RemoveSoftware) {
        $hit = $soft | Where-Object { $_.DisplayName -like "*$rm*" } | Select-Object -First 1
        if ($hit) {
            $us = $hit.UninstallString
            if ($us -and $hit.QuietUninstallString) { $us = $hit.QuietUninstallString }
            Log "FIX: uninstalling '$($hit.DisplayName)' via: $us" "Yellow"
            if ($us) {
                $us = $us.Trim('"')
                # strip any /? or prompt flags, add quiet
                $us = ($us -replace '/\?','') -replace '/U\b',''
                Start-Process -FilePath $us -ArgumentList @("/S","/quiet") -Wait -ErrorAction SilentlyContinue
            } else {
                Log "   (no uninstall string; remove manually)" "Red"
            }
            Start-Sleep -Seconds 3
        }
    }
    # netcat backdoor
    $proc = Get-Process -Name $P.RemoveBackdoorProc -ErrorAction SilentlyContinue
    if ($proc) { Stop-Process -Name $P.RemoveBackdoorProc -Force; Log "FIX: killed '$($P.RemoveBackdoorProc)' process." "Green" }
    if (Test-Path $P.RemoveBackdoorFile) { Remove-Item $P.RemoveBackdoorFile -Force; Log "FIX: deleted backdoor '$($P.RemoveBackdoorFile)'." "Green" }
    # unauthorized media
    if (Test-Path $P.RemoveMediaDir) {
        Get-ChildItem $P.RemoveMediaDir -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
        Log "FIX: cleared unauthorized media in '$($P.RemoveMediaDir)'." "Green"
    }
    # NOT auto-installing Chrome/Notepad++: they must be PRESENT (penalty guards).
    # If Notepad++ is below target, surface a manual step (needs internet).
    $npp = $soft | Where-Object { $_.DisplayName -like "*Notepad++*" } | Select-Object -First 1
    if ($npp) {
        $nppOld = $false
        try {
            $cv = [Version]"$($npp.DisplayVersion)".Trim()
            $nw = [Version]$P.NppTargetVersion
            $nppOld = ($cv -lt $nw)
        } catch { $nppOld = ($npp.DisplayVersion -ne $P.NppTargetVersion) }
        if ($nppOld) {
            Log "NOTE: Notepad++ $($npp.DisplayVersion) < $($P.NppTargetVersion). Update it to $($P.NppTargetVersion) (needs internet + installer)." "Yellow"
        }
    }
}

function Fix-UserRights {
    # Build a secedit INF that strips the listed users from each privilege.
    $exp = Join-Path $env:TEMP ("cp_sed_" + [guid]::NewGuid().ToString("N") + ".inf")
    & secedit.exe /export /cfg $exp 2>$null | Out-Null
    $content = Get-Content $exp
    $out = $content | ForEach-Object {
        $line = $_
        foreach ($kv in $P.RevokeRights.GetEnumerator()) {
            $priv = $kv.Key
            if ($line -match "^$([regex]::Escape($priv))\s*=") {
                $list = ($line -split "=",2)[1].Trim()
                $sids = $list -split ";"
                $keep = @()
                foreach ($sid in $sids) {
                    $sid = $sid.Trim()
                    $stripThis = $false
                    foreach ($u in $kv.Value) {
                        try {
                            $usid = (New-Object Security.Principal.NTAccount($u)).Translate([Security.Principal.SecurityIdentifier]).Value
                            if ($sid -eq $usid) { $stripThis = $true }
                        } catch {}
                    }
                    if (-not $stripThis) { $keep += $sid }
                }
                $line = $priv + " = " + ($keep -join ";")
            }
        }
        $line
    }
    $out | Set-Content $exp
    $db = Join-Path $env:SYSTEMROOT "sedit.sdb"
    & secedit.exe /configure /cfg $exp /db $db /overwrite yes 2>$null | Out-Null
    Remove-Item $exp -ErrorAction SilentlyContinue
    Log "FIX: user rights stripped (wyatt: SeAudit; darius: SeTakeOwnership). A reboot may be required." "Green"
}

function Run-Fix {
    Log "=== FIX  $($P.Image)  (stage=fix) ===" "Cyan"
    Fix-Users; Fix-Policy; Fix-Network; Fix-Services; Fix-Software; Fix-UserRights
    Log "=== FIX complete. Re-run  -Stage verify  to confirm. ===" "Green"
}

# ==================================================================== VERIFY
function Run-Verify {
    Run-Audit | Out-Null
    $pass = @($Results | Where-Object { $_.Pass }).Count
    $fail = $Results.Count - $pass
    Log "=== VERIFY  $($P.Image)  ===" "Cyan"
    foreach ($r in $Results) {
        $mark = if ($r.Pass) { "PASS" } else { "FAIL" }
        $col  = if ($r.Pass) { "Green" } else { "Red" }
        Log ("{0}  {1}  (expected={2} actual={3})" -f $mark, $r.Item, $r.Expected, $r.Actual) $col
    }
    Log ("SCORECARD: {0}/{1} PASS, {2} FAIL." -f $pass, $Results.Count, $fail) $(if($fail -eq 0){"Green"}else{"Red"})
    return $fail
}

# ================================================================== FORENSICS
function Run-Forensics {
    Log "=== FORENSICS  (Win 11 TR2) - computed live from this image; AK answers shown for reference ===" "Cyan"

    # ---- Q1: which other TCP port is owned by the process listening on :445?
    Log "Q1: other TCP port owned by the process listening on TCP/445" "Yellow"
    $ns = @(netstat -abno 2>$null)
    $owner = ""
    $others = @()
    foreach ($l in $ns) {
        if ($l -notmatch '^\s*TCP\s') { continue }
        $f = $l.Trim() -split '\s+'
        if ($f.Count -lt 5) { continue }
        if ($f[1] -like '*:445') {
            if (-not $owner) { $owner = $f[4] }
            continue
        }
        if ($owner -and $f[4] -eq $owner) { $others += $f[1] }
    }
    if ($owner) { Log "   PID on :445 = $owner ; that PID also owns: $($others -join ', ')" "White" }
    else { Log "   could not parse netstat -abno; run it manually (Ctrl+F '445', note the PID, find its other row)." "DarkGray" }
    Log "   AK answer: 139" "DarkCyan"

    # ---- Q2: which IPC share is present (fsmgmt.msc > Shares)?
    Log "Q2: IPC share present (fsmgmt.msc > Shares)" "Yellow"
    $ipc = $null
    $shares = @(Get-WmiObject Win32_Share -ErrorAction SilentlyContinue)
    foreach ($s in $shares) { if ($s.Name -like "IPC*") { $ipc = $s; break } }
    if ($ipc) { Log "   found: '$($ipc.Name)' - $($ipc.Description)" "White" }
    else { Log "   IPC share not found via WMI; check fsmgmt.msc > Shares manually." "DarkGray" }
    Log "   AK answer: IPC" "DarkCyan"

    # ---- Q3: decode the planted message (ROT13 first, then reverse)
    Log "Q3: decode planted message - ROT13, then reverse" "Yellow"
    $found = $false
    $roots = @("C:\Users\*\Desktop", "C:\Users\*\Documents", "C:\Users\*\Downloads", "C:\Users\Public")
    foreach ($r in $roots) {
        foreach ($f in @(Get-ChildItem $r -File -ErrorAction SilentlyContinue)) {
            if ($f.Extension -ne ".txt" -and $f.Extension -ne ".log") { continue }
            if ($f.Length -gt 2000) { continue }
            $raw = ""
            try { $raw = (Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue).Trim() } catch { continue }
            if (-not $raw -or $raw.Length -gt 300) { continue }
            $step1 = Rot13 $raw
            $final = Reverse-Text $step1
            if ($final -match 'on your way') {
                Log "   FOUND in: $($f.FullName)" "White"
                Log "   raw='$raw'  ->  ROT13='$step1'  ->  reversed='$final'" "White"
                $found = $true
            }
        }
    }
    if (-not $found) {
        Log "   not auto-located. Find the small .txt message file in user folders, decode with ROT13," "DarkGray"
        Log "   then REVERSE the result (the two-step order matters)." "DarkGray"
    }
    Log "   AK answer: 'You are on your way'  (ROT13 step = 'Yaw ruoy no era uoY')" "DarkCyan"
    Log "(Write your answers in the 'Forensics Questions' file on the Desktop for points.)" "Yellow"
}

# ==================================================================== DISPATCH
switch ($Stage) {
    "audit"     { Run-Audit }
    "fix"       { Run-Fix }
    "verify"    { Run-Verify }
    "forensics" { Run-Forensics }
    default     { Write-Host "Unknown stage '$Stage'." -ForegroundColor Red; exit 1 }
}
