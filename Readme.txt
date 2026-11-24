# CP19 Master Scripts — CyberPatriot Remediation (TRAINING IMAGES ONLY)

> ## ⚠️ RULES COMPLIANCE — READ FIRST
> **These scripts are for PRACTICE on TRAINING images only. They are NOT for use in any scored competition round.**
>
> NICEC rules that govern this repo (CP19 context):
>
> - **3010.4.A.2** — You may not connect any AI tool or agent to a competition image or system, directly or indirectly (SSH, APIs, MCP, automation, screen capture…).
> - **3010.4.A.3** — You may not submit/paste/upload competition or challenge material to an AI tool.
> - **3010.4.B** — You may not use competition materials to train/test/develop AI systems.
> - **3010.4.C** — You may not install, execute, or invoke any AI tool, script, or agent **within** a competition image.
> - **3010.4.D** — You may not use AI tools to generate scripts, commands, or answers for use in the competition.
> - **3011.4** — Scripts used during a round must be created **by the competitors themselves**.
> - **3011.1** — Competitors may consult free public resources during the round.
> - **3009** — Current or past competition images are **not** training material, even after answers are published; scenario text, rosters, and answer keys may not be used to build training content.
>
> **Practical consequences:**
> 1. These scripts may only be run against **training** images (e.g., CP19 Round 2's public training image).
> 2. During a real round you perform the same work **by hand**, using your own notes and free public resources — you may not run, reference, or paste these scripts (or their output) into or from a competition image.
> 3. **Keep this repository PRIVATE.** It embeds the training image's target values and answer-key references; publishing it publicly would distribute answer-key material.
>
> ---

## What this is

A single-engine, **profile-driven** pair of master remediation/hardening scripts for CyberPatriot training images:

| File | OS / Profile | Stages |
|---|---|---|
| `cp_master.sh` | Debian 12, Mint 21 (auto-detect + `PROFILE` env override) | `audit`, `forensics`, `fix`, `verify` |
| `cp_master_win.ps1` | Windows 11 — CP19 Round 2 training image (`Win11_TR2`) | `audit`, `fix`, `verify`, `forensics` |

Design goals:

- **One engine per OS, profile = data.** All per-round targets (password policy numbers, file permissions, service names, expected users, Notepad++ target version, …) live in a profile block at the top of each script. A new training round = a new profile block, not a new script.
- **Four stages, separate concerns.**
  - `audit` — read-only check table (expected / actual / pass-fail per scored item). Safe to run any time.
  - `fix` — applies every remediation, idempotent, safe to re-run.
  - `verify` — re-audits after fixes; reports what still fails.
  - `forensics` — decodes the Forensics Question files (e.g., ROT13 → reverse-text pipeline) and prints the workflow to follow by hand.
- **Safety guards are hard-coded, not configurable.** No stage will ever:
  - stop/disable/kill the **CCS Client**,
  - change **chowe's** password,
  - remove **authorized users**,
  - change the **time zone**,
  - uninstall **Chrome** or **Notepad++** (penalty-guarded apps).

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

### Linux (Debian 12 / Mint 21 training images)

```bash
# stage = first positional arg (default: audit); profile auto-detected, overridable
./cp_master.sh audit
PROFILE=debian12 ./cp_master.sh fix
./cp_master.sh verify
./cp_master.sh forensics
```

Env overrides: `PROFILE` (auto | explicit), `AUTO_WRITE_ANSWERS` (0/1), `SUDO_PASS_FILE` (default `/tmp/.cp_sudo_pass`).

> **Do not run any of the above inside a competition image.** Run it on the training image to *learn the sequence and the exact values*, then do it by hand during the round.

## Scope per profile

- **`Win11_TR2`** — 32 scored items + 3 penalty checks from the CP19 Round 2 training image answer key, all mapped 1:1 to profile data and consumed by the stage functions (registry-backed policy items, password/lockout policy, service state, firewall, users/groups, Notepad++ version, Chrome presence, …).
- **Debian 12 / Mint 21** — CIS-baseline families (sshd, sysctl, PAM password controls incl. `pam_unix remember`, shadow/file permissions 640, ASLR, `ip_forward`, syncookies, grub.cfg, ufw, unattended-upgrades) with profile-specific targets.
- **Windows Server 2022 — deliberately excluded.** Selecting it raises a FATAL error guard: WS 2022 images are competition images and must not be scripted against (3009/3010.4). The profile is intentionally not implemented.

## Verification status (2026-11-24)

- `cp_master_win.ps1` — **full-file parse: OK (0 errors)** on Windows PowerShell 5.1 (`[Parser]::ParseFile`) after all fixes.
- Profile data cross-check — **32/32 scored items + 3 penalties** mapped to profile keys and consumed by stage functions.
- Forensics helpers — `Rot13` + `Reverse-Text` round-trip verified against the answer-key flow: file content `lnj ehbl ab ren hbL` → ROT13 → `yaw ruoy no era uoY` → reverse → `You are on your way`.
- Notepad++ version comparison — numeric `[Version]` compare verified: `8.9.10` is correctly judged **not older** than `8.9.8.1` (string comparison got this wrong).
- `cp_master.sh` — syntax-checked (`bash -n`); stage dispatch and profile auto-detect verified.

Known limitations:

- `fix` does not auto-install Chrome/Notepad++ (penalty-guarded); it surfaces a manual-update note for Notepad++ when below target (needs internet + installer).
- Version compare falls back to exact string match if a reported version isn't a valid `[Version]` (e.g., "8.6.8 build 4012").
- Runtime behavior on a live training image is the final proof — run `audit` → `fix` → `verify` on the training image before trusting the mapping.

## Reproducing a round by hand (the actual competition workflow)

1. **Audit first.** Read every scored requirement from the round's readme; confirm the current state of each item (the scripts' `audit` stage shows exactly which commands/registry keys to check).
2. **Fix in order of risk.** Password policy, users/groups, services, firewall, then file permissions — the `fix` stage's ordering is the suggested sequence.
3. **Verify.** Re-check every item after fixes; leave evidence (screenshots of each check).
4. **Forensics last.** Work the decode chain in a text editor (the `forensics` stage prints the chain and the expected workflow).

## Files

```
cp_master/
├── README.md            # this file
├── cp_master.sh         # Debian 12 + Mint 21 engine
└── cp_master_win.ps1    # Windows 11 TR2 engine
```

*Built as a learning aid for CyberPatriot training. Not affiliated with or endorsed by NICE. Keep private. Never use in scored rounds.*
