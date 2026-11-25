# CP Master Scripts — CyberPatriot Hardening & Remediation

> ## ⚖️ OPEN SOURCE — NO AFFILIATION
> These scripts are **purely open source**. They are **not affiliated with, endorsed by, or connected to any CyberPatriot team, any CAP squadron — including TX295 Composite Squadron — or the competition itself.**
>
> If a team number, squadron name, or squadron folder shows up anywhere (file names, commit history, local folders), that's a historical leftover from where the work was originally done. It carries **no meaning, no sponsorship, and no association** with any team or squadron. The scripts stand on their own.
>
> **Use them freely** — read them, copy them, modify them, share them, build on them. What you do with them and how you do it is on you!!!

## What this is

A single-engine, **profile-driven** pair of master remediation/hardening scripts for CyberPatriot training images:

| File | OS / Profile | Stages |
|---|---|---|
| `cp_master.sh` | Debian 12, Mint 21 (auto-detect + `PROFILE` env override) | `audit`, `forensics`, `fix`, `verify` |
| `cp_master_win.ps1` | Windows 11 — training image (`Win11_TR2`) | `audit`, `fix`, `verify`, `forensics` |

Design goals:

- **One engine per OS, profile = data.** All per-round targets (password policy numbers, file permissions, service names, expected users, Notepad++ target version, …) live in a profile block at the top of each script. A new round = a new profile block, not a new script.
- **Four stages, separate concerns.**
  - `audit` — read-only check table (expected / actual / pass-fail per scored item). Safe to run any time.
  - `fix` — applies remediations, idempotent, safe to re-run.
  - `verify` — re-audits after fixes; reports what still fails.
  - `forensics` — decodes the Forensics Question files (e.g., ROT13 → reverse-text pipeline) and prints the workflow to follow.
- **Safety guards are hard-coded, not configurable.** No stage will ever:
  - stop/disable/kill the **CCS Client**,
  - change **chowe's** password,
  - remove **authorized users**,
  - change the **time zone**,
  - uninstall **Chrome** or **Notepad++** (penalty-guarded apps).

## How the repository is organized

**Year → Round → Operating System.**

1. **Year** — `2026_Scripts/` holds everything for the 2026 competition year. When the next year starts, a new year folder (`2027_Scripts/`) is created the same way.
2. **Round** — inside a year folder, there is one folder per round (`Training Round 1`, `Training Round 2`, `Practice Round`, `Round 2`, `State Round`, …). Each round folder holds the scripts written for that specific round.
3. **Operating system** — inside each round folder, the scripts are split into `Linux/` and `Windows/` subfolders, since every round has a Linux image and a Windows image.

So to find a script: **year folder → round folder → OS folder → the script.**

This file (`Readme.txt` at the repo root) is the **single main readme** for the whole repository. `Old_Scripts/Readme.txt` is a legacy note for that folder only.

## File tree

```
TX295-CyberPatriotTeam/
├── Readme.txt                          # this file — the single main readme
│
├── 2026_Scripts/                       # ← the 2026 competition year
│   ├── Training Round 1/
│   │   ├── Linux/
│   │   │   └── V1.sh
│   │   └── Windows/                    (empty — scripts go here as the round is worked)
│   │
│   ├── Training Round 2/
│   │   ├── Linux/
│   │   │   ├── cap_hardening_2026.sh
│   │   │   ├── Harden_v6.sh
│   │   │   ├── Harden_v7.sh
│   │   │   ├── harden-debian12.sh
│   │   │   ├── round_config.txt
│   │   │   └── Screenshot 2026-11-11 114317.png
│   │   └── Windows/                    (empty)
│   │
│   ├── Practice Round/
│   │   ├── Linux/
│   │   │   └── V1.sh
│   │   └── Windows/                    (empty)
│   │
│   ├── Round 2/
│   │   ├── Linux/                      (empty)
│   │   └── Windows/                    (empty)
│   │
│   └── State Round/                    # the master engine (the "real" scripts)
│       ├── Linux/
│       │   └── cp_master.sh            # Debian 12 + Mint 21 engine
│       └── Windows/
│           └── cp_master_win.ps1       # Windows 11 TR2 engine
│
├── CIS benchmarks/                     # reference material (PDFs)
│   ├── CIS_Debian_Linux_12_Benchmark_v2.0.0.pdf
│   ├── CIS_Linux_Mint_22_Benchmark_v1.0.0.pdf
│   ├── CIS_Ubuntu_Linux_20.04_LTS_Benchmark_v3.0.0.pdf
│   ├── CIS_Ubuntu_Linux_20.04_LTS_STIG_Benchmark_v2.0.0.pdf
│   └── CIS_Ubuntu_Linux_22.04_LTS_Benchmark_v3.0.0.pdf
│
├── Old_Scripts/                        # earlier one-off scripts (kept for history)
│   ├── Good_script.sh
│   ├── Harden.sh
│   ├── Harden_v2.sh
│   ├── Harden_v3.sh
│   ├── Harden_v4.sh
│   ├── Home_brew_V5.sh
│   ├── cyberpatriot_user_manager.sh
│   ├── Run_after_forensic.sh
│   ├── Test.sh
│   ├── test_from_ai.sh
│   └── Readme.txt                      # legacy folder note (not the main readme)
│
└── Readmes/                            # round README pages + answer keys
    ├── Answer_Keys/
    │   ├── CP-18 Round 2 Answers and Vulnerabilities.pdf
    │   ├── CP18_Ubuntu22_Training_Answer_Key.pdf
    │   ├── CP19_Debian12_Training_Answer_Key.pdf
    │   ├── CP19_Mint21_Practice_Answer_Key.pdf
    │   ├── CP19_Mint21_Training_Answer_Key.pdf
    │   ├── CP19_Mint21_Training2_Answer_Key.pdf
    │   └── CP19_Win11_Training_Answer_Key.pdf
    ├── CyberPatriot Introductory Round & Round 2 Debian 12 README – CyberPatriot.html
    │   └── …_files/                    (saved web assets for the HTML page)
    ├── CyberPatriot Introductory Round & Round 2 Windows 11 README – CyberPatriot.html
    │   └── …_files/                    (saved web assets for the HTML page)
    ├── CyberPatriot Round 2 Windows Server 2022 README – CyberPatriot.html
    │   └── …_files/                    (saved web assets for the HTML page)
    └── Training Round 2 Debian 12 README – CyberPatriot.html
        └── …_files/                    (saved web assets for the HTML page)
```

## Usage

### Windows (PowerShell 5.1 compatible — Windows PowerShell or pwsh)

```powershell
# read-only audit table (default stage)
powershell -ExecutionPolicy Bypass -File .\cp_master_win.ps1 -Profile Win11_TR2 -Stage audit

# apply fixes
powershell -ExecutionPolicy Bypass -File .\cp_master_win.ps1 -Profile Win11_TR2 -Stage fix

# re-check
powershell -ExecutionPolicy Bypass -File .\cp_master_win.ps1 -Profile Win11_TR2 -Stage verify

# forensics walkthrough
powershell -ExecutionPolicy Bypass -File .\cp_master_win.ps1 -Profile Win11_TR2 -Stage forensics
```

Exit codes: `audit`/`verify` exit 0 on success even if items fail (a report is not an error); `fix` exits 0 when complete, 1 if a fatal guard or exception interrupted it.

### Linux (Debian 12 / Mint 21 images)

```bash
# stage = first positional arg (default: audit); profile auto-detected, overridable
./cp_master.sh audit
PROFILE=debian12 ./cp_master.sh fix
./cp_master.sh verify
./cp_master.sh forensics
```

Env overrides: `PROFILE` (auto | explicit), `AUTO_WRITE_ANSWERS` (0/1), `SUDO_PASS_FILE` (default `/tmp/.cp_sudo_pass`).

## Scope per profile

- **`Win11_TR2`** — 32 scored items + 3 penalty checks, all mapped 1:1 to profile data and consumed by the stage functions (registry-backed policy items, password/lockout policy, service state, firewall, users/groups, Notepad++ version, Chrome presence, …).
- **Debian 12 / Mint 21** — CIS-baseline families (sshd, sysctl, PAM password controls incl. `pam_unix remember`, shadow/file permissions 640, ASLR, `ip_forward`, syncookies, grub.cfg, ufw, unattended-upgrades) with profile-specific targets.
- **Windows Server 2022 — deliberately not implemented.** It's a scored-round image, so there's nothing to train against; the profile is intentionally left out.

## Reproducing a round by hand (how people actually use this)

1. **Audit first.** Read every scored requirement from the round's readme; confirm the current state of each item (the scripts' `audit` stage shows exactly which commands/registry keys to check).
2. **Fix in order of risk.** Password policy, users/groups, services, firewall, then file permissions — the `fix` stage's ordering is the suggested sequence.
3. **Verify.** Re-check every item after fixes; leave evidence (screenshots of each check).
4. **Forensics last.** Work the decode chain in a text editor (the `forensics` stage prints the chain and the expected workflow).

*Open source — use, modify, and share freely. Not affiliated with any CyberPatriot team, CAP squadron, or the competition. No warranty of any kind; you are responsible for how you use these.*
