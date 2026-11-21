# CyberPatriot Season 19 — Round 2 Retrospective (Introductory)

**Team:** TX295-CyberPatriotTeam · ID `67GYR-CA7BA-5RMKG`
**Round:** Introductory Round & Round 2 (Season 19)
**Date:** 2026-11-14
**Scenario:** Arc Foundry & Aerospace (AFA) — newly acquired avionics lab
**Result:** Debian 12 = **87 / 100** · Windows Server 2022 = **65 / 100** · Windows 11 = **43 / 100** (CCS **195** · Cisco Quiz **10.00** · Cisco PT **5.71** · Adjust **−75.00**)

> Legend: ✅ scored · ❌ not scored · ⚠️ learned the hard way.
> Passwords are **not** restated here (see the per-image README in `Readmes/`) — only *which account* was affected.

---

## 1. The two images at a glance

| | Debian 12 (Linux) | Windows Server 2022 |
|---|---|---|
| Score | 87 / 100 (16 of 19 checks) | 65 / 100 |
| Default browser | Chromium (latest stable) | Google Chrome (latest stable) |
| Firewall | UFW only | Windows Defender Firewall + Action Center |
| Critical services | **sshd (SSH)** — keep enabled | **IIS (web)**, **SMB file share** — keep running |
| Must keep | LightDM, authorized users + homes, UTC, CCS Client | + Notepad++, WinSCP, 7-Zip installed & up-to-date |
| Special ask | — | Disable **IIS directory browsing**; **Handbook share**: admins write, everyone read, always available |

**Shared authorized roster (both images):**
- **Admins (7):** pparker (auto-login / "you"), tstark, ppotts, hhogan, nfury, mhill, pcoulson
- **Users (13):** bbanner, swilson, sstrange, slang, cdanvers, okoye, kbishop, ybelova, jfoster, nleeds, mjwatson, jtorres, pcarter
- **This round's targets:** remove unauthorized users **azola, brumlow**; fix the insecure admin password on **hhogan**.

---

## 2. Debian 12 — what we scored (16 / 19 = 87 pts)

| Check (dashboard wording) | Pts |
|---|---|
| Forensics Question 1 correct | 8 |
| Forensics Question 2 correct | 8 |
| Removed unauthorized user azola | 4 |
| Removed unauthorized user brumlow | 4 |
| Changed insecure password for user hhogan | 4 |
| A minimum password length is required | 6 |
| UFW protection enabled | 6 |
| FTP service disabled / removed | 6 |
| Install updates from important security updates | 5 |
| Sudo updated | 5 |
| Chromium updated | 5 |
| OpenSSH updated | 5 |
| Prohibited MP3 files removed | 5 |
| Prohibited software Ettercap removed | 5 |
| Prohibited software Freeciv removed | 5 |
| SSH does not permit empty passwords | 6 |
| **Total** | **87** |

## 3. Debian 12 — the 3 checks we missed (13 pts)

| Check | Confidence | Root cause | Fix for next time |
|---|---|---|---|
| **Account lockout policy (faillock)** | ❌ **confirmed** | `pam-auth-update` kept dying on a held debconf lock, so `pam_faillock.so` never got wired into the PAM stack | Insert the faillock lines **directly into `/etc/pam.d/common-auth`** (manual PAM edit) or clear the debconf lock first; **always hard-login-test after** |
| **Minimum password age** | ❌ likely | `login.defs` PASS_MIN_DAYS only affects **new** users; live accounts still had `chage` min = 0 | Run `chage -m 7 -M 90 -W 7 <user>` on **every live account** (the scorer reads the *effective* value, not the default) |
| **Third hardening check** | ⚠️ not pinned down | likely `/etc/shadow` permissions (should be 640) or an admin-group membership fix | `ls -l /etc/shadow` → `-rw-r-----`; confirm admin-group membership matches the roster |

## 4. Windows Server 2022 — 65 / 100 (35 pts missed)

We did **not capture the failing-checks list** for the Windows image (no scoring-report screenshot was saved). From the scenario, this image's check family is:
- Forensics questions (Desktop)
- Remove unauthorized users (azola, brumlow) + change **hhogan's** insecure password
- Enforce password policy (min length / complexity) on all live accounts
- **Disable IIS directory browsing** (SOC request) — IIS must keep running
- **Handbook share** (`C:\Shares\Handbook`, share name `Handbook`): **only admins may write**; **everyone may read**; must stay available
- Remove prohibited media + "hacking tools"
- Update the default browser (Chrome) + business software (Notepad++, WinSCP, 7-Zip)
- Enable Windows Action Center / keep Defender healthy; Windows Firewall
- **CCS Client:** Malwarebytes (and other AV) may flag it as malware — allow-list `ccsclient.exe` and restart if that happens

**Action item:** next Windows round, **screenshot the scoring report BEFORE suspending** so we have the exact failing checks and their point values.

---

## 5. Technical learnings — the gotchas that cost us

1. **`login.defs` ≠ live accounts.** Setting `PASS_MIN_DAYS` / `PASS_MAX_DAYS` only affects *future* accounts. The scorer reads the **effective `chage`** value on each existing account. Fix **both**: the default **and** `chage` per user.
2. **Faillock on Debian 12 is not a package.** `libpam-faillock` does not exist as a standalone dpkg package — the module ships in `libpam-modules`. Don't `apt install libpam-faillock`.
3. **`pam-auth-update` and the debconf lock.** A live `debconf` `frontend` can hold the lock; killing it *breaks* `pam-auth-update` (and the whole PAM regen). If it hangs, **don't fight it** — edit `/etc/pam.d/common-auth` by hand and verify with a hard login.
4. **PAM jump-order.** In `common-auth`, an `authsucc` / `[success=...]` jump label must sit **after** the `pam_permit` / `pam_unix` line it jumps over. A mis-placed `authsucc` *before* `pam_permit` routes success into `pam_deny` and **bricks login**.
5. **Never brick the VM.** Any PAM / password / auth change must be followed by a **real login test (GUI + SSH)** before you re-score or submit.
6. **The "insecure password" check is one specific account** (here: hhogan). Restore it to a policy-compliant value (≥12 chars, mixed classes). **Do not** mass-reset every admin — you'll break the auto-login account and lose access.
7. **Don't delete the CP client's own files.** `/opt/CyberPatriot/*.wav` are the client's UI sounds, not prohibited media. Only remove the *users'* non-work media (e.g. `/home/<user>/Music/*.mp3`).
8. **Do NOT touch:** authorized users or their homes, the auto-login account's password, the UTC timezone, the CCS Client, LightDM, sshd, IIS, or the SMB share.
9. **Stop scoring by SUSPENDING the VM** (not power-off) — the README says the Stop Scoring app can be blocked by security settings, and suspending is the sanctioned safe stop. Don't power it back on before delete.
10. **Tooling pitfalls we hit:**
    - `write_file` refuses to overwrite an existing file → use `patch` or a new filename.
    - SFTP can't write into root-owned dirs → use `sudo tee` (base64 payload) or a paramiko shell command.
    - `sed` on a **commented** config line (`#MaxAuthTries 6`) needs `s/^#?[[:space:]]*MaxAuthTries.*/.../` — the naive `s/^MaxAuthTries.*/` misses it.
    - `chage -l <user>` can report "not in /etc/passwd" for a user that **is** in `/etc/shadow` (NSS / split-record quirk) — verify via `getent passwd` / `/etc/shadow` directly.
    - A native Windows path ending in `\` inside bash quotes escapes the quote → use forward slashes.

---

## 6. The playbook (what next round should look like)

1. **Read the full README** (scenario, authorized roster, critical services, prohibited items) — before touching anything.
2. **Answer the Forensics Questions FIRST** — they're only scored on the Desktop, and modifying the box can destroy the answer.
3. **Baseline** the box: `sshd -T`, `ls -l /etc/shadow`, `chage -l <each user>`, `systemctl list-units --state=active`, `netstat -tlnp`, `locate *.mp3`, `crontab -l` (root **and** each user).
4. **Work least-brickable first:**
   - Remove unauthorized users (azola, brumlow) → `deluser --remove-home`.
   - Fix the one insecure admin password (hhogan) → strong, ≥12 chars.
   - Enforce password policy → `login.defs` **and** `chage` per live account **and** pwquality `minlen=12`.
   - Wire **faillock** (manual PAM edit, correct `authsucc` order) → **hard-login test**.
   - Hardening knobs → `X11Forwarding no`, `MaxAuthTries 3`, `LoginGraceTime 60`, `PermitRootLogin no` (sshd is critical: **reload**, don't break it).
   - Disable unneeded services (FTP / vsftpd) → keep sshd, LightDM, CCS Client.
   - Enable **UFW** (allow SSH in).
   - Remove prohibited media + tools (Ettercap, Freeciv, user MP3s) — **not** CP client files.
   - Update (apt) → Debian stable only; keep Chromium as default.
5. **Re-score frequently** (double-click the Scoring Report) and fix until green.
6. **Screenshot the scoring report**, then **SUSPEND** the VM.

---

## 7. Scripts & artifacts

- Hardening script (machine-agnostic): `2026_Scripts/Training Round 2/Linux/harden-debian12.sh`
- Prior iterations (same dir): `cap_hardening_2026.sh`, `Harden_v6.sh`, `Harden_v7.sh`
- Scenario READMEs + answer keys: `Readmes/` and `Readmes/Answer_Keys/`
- The per-run paramiko diagnostic/fix scripts lived in the ephemeral scratch dir → **recreate them** in `2026_Scripts/Round 2/` so the manual PAM-edit + `chage` + sshd steps are reproducible before the next round.

## 8. Action items (carry into the next round)

- [ ] Add the **manual faillock PAM edit** (correct `authsucc` order) to the hardening script — it's the check we *know* we missed.
- [ ] Add **`chage -m 7 -M 90 -W 7` for every live account** to the script (not just `login.defs`).
- [ ] Add **`chmod 640 /etc/shadow`** + admin-group membership verification to the script.
- [ ] **Windows:** build `harden-win2022.ps1` covering IIS directory-browsing off, Handbook share ACLs (admins write / everyone read), Chrome + Notepad++/WinSCP/7-Zip updates, Action Center, `ccsclient.exe` allow-list.
- [ ] **Screenshot the scoring report on BOTH images** before suspending, next time.
- [ ] Populate the currently-empty `2026_Scripts/Round 2/{Linux,Windows}` folders with reproducible tooling.
- [ ] **Windows 11 (43/100, 2 penalties — our weakest image):** capture the scoring-report failure breakdown before the images are deleted, then build `harden-win11.ps1` for the AFA R2 image (Chrome default, keep business apps, Action Center, roster/password targets per the live README).
- [ ] **Investigate the −75.00 team Adjust** (results email / national team) before Round 3 — reason not yet confirmed.

---

## 9. Official results — CAP dashboard (reviewed 2026-11-21)

Team **#19-3483** · TX · CAP · High School tier.

| Image (dashboard) | Submitted at | Found | Remaining | Pen | Score |
|---|---|---|---|---|---|
| Debian 12 (`cp19_intro_r2`) | 02:40:14 | 16 | 3 | 0 | **87** |
| Windows Server 2022 | 03:24:59 | 14 | 9 | 0 | **65** |
| Windows 11 (`cp19_intro_r2`) | 03:41:28 | 10 | 9 | **2** | **43** |

**Totals:** CCS Score **195** · Cisco Quiz **10.00** · Cisco PT **5.71** · **Adjust −75.00** (reason not yet confirmed — see action items).

- Submission order: Debian → WS 2022 → Win 11; timestamps are cumulative within the 03:41:28 round.
- **Windows 11 is the weakest image (43)** and the only one with penalties recorded (2). A per-check failure breakdown needs the Win11 scoring report — the images must be captured **before they're deleted** per the rules book.
- Debian's "3 remaining" checks match section 3 above (faillock, min password age, one unpinned check).

---

*Documented 2026-11-14 from the Season 19 Round 2 run; official dashboard results added 2026-11-21. Passwords intentionally omitted — see `Readmes/`.*
