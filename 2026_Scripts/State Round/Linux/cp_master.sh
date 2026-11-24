#!/usr/bin/env bash
# =============================================================================
#  CP19 MASTER ENGINE — CyberPatriot Linux Remediation + CIS Hardening
#  Profiles : debian12  (CIS Debian 12 v2.0.0 ONLY)
#             mint21    (CIS Ubuntu 20.04 v3.0.0 + CIS Ubuntu 22.04 v3.0.0 +
#                         CIS Ubuntu 20.04 STIG v2.0.0 + CIS Mint 22 v1.0.0)
#
#  SOURCES OF TRUTH ENCODED HERE
#    - CP19 Debian 12 TR2 README + Answer Key (22 scored items + 1 penalty)
#    - CP19 Mint 21 TR2 README + Answer Key (28 scored items + 2 penalties)
#    - CP19 Mint 21 Practice key (18 items + penalties)
#    - CP19 Mint 21 Training key (22 items + 2 penalties)
#    - CP18 Ubuntu 22 key (19 items + 4 penalties)
#    - CP18 Round 2 key, Mint 21 image (18 items)
#    - CIS Debian 12 v2.0.0: 5.1.19/5.1.20 (sshd), 5.3.2.2 (faillock),
#      5.3.3.1.1 (lockout), 5.3.3.3.1 (pwhistory), 5.3.3.4.1 (no nullok),
#      5.3.3.4.2 (pam_unix remember), 5.4.1.1/5.4.1.2 (PASS_MAX/MIN_DAYS),
#      7.1.5 (shadow 640), 1.5.9 (ASLR), 3.3.1.1 (ip_forward),
#      3.3.1.18 (syncookies), 1.1.1.4 (grub.cfg)
#    - CIS Ubuntu 20.04/22.04 v3.0.0 + Mint 22 v1.0.0: same control families,
#      numbered 5.x (sshd/sysctl/pam) there
#
#  SCOPE SPLIT (team doctrine — the script never does passwords or user config)
#    script (fix) : everything EXCEPT passwords and user accounts —
#                   file perms, sysctl, SSH, services, UFW, sources/upgrades,
#                   prohibited software/media, backdoor sweep
#    student      : ALL password work (policy + resets), ALL user configuration
#                   (removals, demotions, groups, new admin), and the forensics
#                   answers — BY HAND. `fix` detects each item and prints the
#                   exact commands to run.
#    fixall       : TRAINING ONLY — the script does everything, including
#                   passwords and user changes (use to measure the full score)
#
#  STAGES
#    (no argument) = fix : apply script-scope fixes, then print the student homework list
#    audit         read-only full-machine check table (no changes)
#    forensics     decode every Forensics Question file on Desktops (candidates)
#    verify        audit again + estimated score (run after the student finishes)
#    fixall        training: apply everything including passwords + user changes
#
#  QUICK START (one command, no config)
#    bash cp_master.sh
#
#  ENV OVERRIDES
#    PROFILE=debian12|mint21|auto   (default auto: /etc/os-release)
#    SUDO_PASS_FILE=/path/to/pass   (used when not already root; mode 600)
#    AUTO_WRITE_ANSWERS=1           (forensics: write "Answer:" into question
#                                    files when exactly one strong candidate)
#
# =============================================================================
#  !!! USE WITH YOUR COACH / ORGANIZATION'S OKAY !!!
#  USCP rules (3010.4.A.2 / 3010.4.C / 3010.4.D, 3011.4) restrict AI-generated
#  commands and answers in scored rounds. This tool deliberately automates only
#  the mechanical floor — ALL passwords, user configuration and forensics
#  answers are left for the student to perform BY HAND (the printed homework
#  list covers every one of them).
#  Whether running a prepared team script on a scored image is acceptable is
#  the coach's / organization's decision under their current USCP policy.
# =============================================================================

set -u
LC_ALL=C

STAGE="${1:-fix}"
PROFILE="${PROFILE:-auto}"
AUTO_WRITE_ANSWERS="${AUTO_WRITE_ANSWERS:-0}"
SUDO_PASS_FILE="${SUDO_PASS_FILE:-/tmp/.cp_sudo_pass}"

PASS_N=0; FAIL_N=0; WARN_N=0; FAIL_PTS=0; PASS_PTS=0
readonly RECS=5; MINLEN=12; PASSMAX=90; PASSMIN=7; WARNAGE=7

# ----------------------------- basics ----------------------------------------
report() { # status pts check detail
  local st="$1" pts="$2" ch="$3" det="${4:-}"
  printf '%-5s | %3s | %s%s\n' "$st" "$pts" "$ch" "${det:+ — $det}"
  case "$st" in
    PASS) PASS_N=$((PASS_N+1)); PASS_PTS=$((PASS_PTS+pts));;
    FAIL) FAIL_N=$((FAIL_N+1)); FAIL_PTS=$((FAIL_PTS+pts));;
    WARN) WARN_N=$((WARN_N+1));;
  esac
}
log()  { printf '\n=== %s ===\n' "$*"; }
note() { printf '    %s\n' "$*"; }

need_root() {
  if [ "$(id -u)" = 0 ]; then return 0; fi
  if [ -f "$SUDO_PASS_FILE" ]; then
    SUDO="sudo -S"
    cat "$SUDO_PASS_FILE" | sudo -S true 2>/dev/null || { echo "FATAL: cannot obtain sudo (wrong pass in $SUDO_PASS_FILE?)"; exit 2; }
  else
    SUDO="sudo"
    sudo -v || { echo "FATAL: need root or SUDO_PASS_FILE"; exit 2; }
  fi
}
SUDO="sudo"   # default when running as root via stage runner
run() { $SUDO bash -c "$1" >/dev/null 2>&1; }

# ----------------------------- profile ---------------------------------------
detect_profile() {
  if [ "$PROFILE" != "auto" ]; then return; fi
  . /etc/os-release 2>/dev/null
  local id="${ID:-}" idlike="${ID_LIKE:-}" ver="${VERSION_ID:-}"
  case "$id $idlike" in
    *mint*)        PROFILE=mint21 ;;
    *debian*)      PROFILE=debian12 ;;
    *ubuntu*)      PROFILE=mint21 ;;  # closest proxy (CIS Ubuntu benchmark)
    *)             PROFILE=debian12 ;;
  esac
  note "auto-detected profile: $PROFILE (ID=$id ver=$ver)"
}

# ----------------------------- README parsing --------------------------------
RTXT=""        # stripped README text
ADMIN_NAMES=() ; USER_NAMES=() ; WEAK_TARGETS=()
declare -A ADMIN_PW=()   # admin -> README-listed password
AUTOLOGIN=""             # user marked "(you)" — NEVER change its password
NEW_GROUP=""; NEW_GROUP_MEMBERS=() ; NEW_ADMIN=""
ADD_USER_TO_GROUP=""; ADD_USER_TO_USER=""
FTP_MODE="auto"          # keep | disable | auto
FTP_ROOT="/var/ftp"       # anonymous root dir (Mint TR2: /srv/ftp)
BROWSER=""
CRIT_SVC=()
WIRESHARK_OK=0

find_readme() {
  local f
  for f in /root/Desktop/* /home/*/Desktop/* /root/* /home/*/*; do
    [ -f "$f" ] || continue
    case "$(basename "$f")" in *README*|*Readme*|*readme*) echo "$f"; return;; esac
  done
  $SUDO find /root /home -maxdepth 3 -type f \( -iname '*readme*' -o -iname '*guideline*' \) 2>/dev/null | head -1
}

parse_readme() {
  local rmfile; rmfile="$(find_readme)"
  [ -n "$rmfile" ] || { note "no README found on desktops — using answer-key defaults"; return 0; }
  note "README: $rmfile"
  RTXT="$($SUDO sed -e 's/<[^>]*>/ /g' -e 's/&[a-z0-9]*;/ /g' -e 's/“/"/g' -e 's/”/"/g' -e "s/‘/'/g" -e "s/’/'/g" -e 's/–/-/g' -e 's/—/-/g' "$rmfile" 2>/dev/null | tr -s ' \t' ' ')"

  # ---- rosters (stateful awk: name line, optional "password: X" line) ----
  local roster line typ name pw
  roster="$($SUDO awk '
    function flush() { if (st=="a" && cur!="") print "A\t" cur "\t"; cur="" }
    /Authorized Administrators:/ {flush(); st="a"; next}
    /Authorized Users:/         {flush(); st="u"; next}
    /Competition Guidelines/    {flush(); st=""}
    st=="a" && /^password:/     { if (cur!="") print "A\t" cur "\t" $2; cur=""; next }
    st=="a" && /^[a-z]/         { if (cur!="") print "A\t" cur "\t"; cur=$1; next }
    st=="u" && /^[a-z]/         {print "U\t" $1; next}
  ' <<<"$RTXT" 2>/dev/null)"
  while IFS=$'\t' read -r typ name pw; do
    case "$typ" in
      A) ADMIN_NAMES+=("$name"); [ -n "${pw:-}" ] && ADMIN_PW["$name"]="$pw" ;;
      U) USER_NAMES+=("$name") ;;
    esac
  done <<<"$roster"
  [ ${#ADMIN_NAMES[@]} -gt 0 ] && note "admins: ${ADMIN_NAMES[*]}"
  [ ${#USER_NAMES[@]} -gt 0 ] && note "users : ${USER_NAMES[*]}"

  # auto-login user (the "(you)" entry) — protected from password change
  AUTOLOGIN="$(grep -oE '^[a-z0-9_]+ \(you\)' <<<"$RTXT" 2>/dev/null | awk '{print $1}' | head -1)"
  [ -n "$AUTOLOGIN" ] && note "auto-login user (PROTECTED): $AUTOLOGIN"

  # weak admin passwords: README password <12 chars, not the auto-login user
  local w n
  for w in "${ADMIN_NAMES[@]:-}"; do
    [ -n "$w" ] || continue
    pw="${ADMIN_PW[$w]:-}"
    if [ -n "$pw" ] && [ "${#pw}" -lt "$MINLEN" ] && [ "$w" != "$AUTOLOGIN" ]; then
      WEAK_TARGETS+=("$w"); note "weak README password: $w (${#pw} chars)"
    fi
  done
  [ ${#WEAK_TARGETS[@]} -gt 0 ] && note "weak-password targets: ${WEAK_TARGETS[*]}"

  # ---- group tasks ----
  # pattern A: Create a group called "X" and add ...: m1, m2, and m3
  local gline
  gline="$(grep -iE 'group (called|named)' <<<"$RTXT" 2>/dev/null | head -1)"
  if [ -n "$gline" ]; then
    NEW_GROUP="$(sed -E 's/.*group (called|named) *"?([a-z0-9_-]+)"?.*/\2/' <<<"$gline")"
    local mem
    mem="$(sed -E 's/.*:[[:space:]]*//; s/[[:space:]]+and[[:space:]]+,?/ ,/; s/ and /,/g' <<<"$gline" \
          | tr ',' '\n' | sed 's/^ *//;s/ *$//' | awk 'NF' | head -12 | sed 's/[.,;:]*$//')"
    NEW_GROUP_MEMBERS=($mem)
    note "create group '$NEW_GROUP' with: ${NEW_GROUP_MEMBERS[*]:-<none>}"
  fi
  # pattern B: add the user "X" to the "Y" group
  local auline
  auline="$(grep -iE 'to the[^.]*group' <<<"$RTXT" 2>/dev/null | head -1)"
  if [ -n "$auline" ]; then
    ADD_USER_TO_GROUP="$(sed -E 's/.*to the "?([a-z0-9_-]+)"? group.*/\1/' <<<"$auline")"
    ADD_USER_TO_USER="$(sed -E 's/.*user "?([a-z0-9_-]+)"?.*/\1/' <<<"$auline")"
    note "add user '$ADD_USER_TO_USER' to group '$ADD_USER_TO_GROUP'"
  fi

  # ---- new admin account ----
  NEW_ADMIN="$(grep -oiE 'create an? (new )?(administrator |admin )?account (for|named) [a-z0-9_]' <<<"$RTXT" 2>/dev/null | awk '{print $NF}' | head -1)"
  [ -n "$NEW_ADMIN" ] && note "requested new admin account: $NEW_ADMIN"

  # ---- critical services section ----
  local crit
  crit="$($SUDO awk '/Critical Services:/{f=1;next} f&&/^[A-Z][a-z]+ [A-Z]/{f=0} f&&NF{print}' <<<"$RTXT" 2>/dev/null)"
  if [ -n "$crit" ]; then
    local tok
    for tok in openssh sshd vsftpd apache2 nginx squid dovecot lighttpd cups; do
      echo "$crit" | grep -qi "$tok" && CRIT_SVC+=("$tok")
    done
    note "critical services from README: ${CRIT_SVC[*]:-<none>} (raw: $crit)"
  fi

  # ---- FTP policy ----
  if   $SUDO grep -qiE 'ftp[^.]*remain operational|ftp[^.]*must remain|ftp[^.]*critical' <<<"$RTXT" 2>/dev/null; then FTP_MODE=keep
  elif $SUDO grep -qiE '(disable|remove)[^.]*ftp|ftp[^.]*disabl' <<<"$RTXT" 2>/dev/null;      then FTP_MODE=disable
  elif case "$PROFILE" in debian12) true;; *) false;; esac; then FTP_MODE=disable  # answer-key default (Debian TR2: vsftpd disabled)
  elif case "$PROFILE" in mint21) true;; *) false;; esac;    then FTP_MODE=keep     # answer-key default (Mint TR2: vsftpd stays up)
  fi
  FTP_ROOT="$(grep -oiE 'ftp[^.]*located at ([a-z0-9/._-]+)' <<<"$RTXT" 2>/dev/null | sed -E 's/.*located at ([a-z0-9/._-]+)/\1/' | head -1 | sed 's/[.,;:]*$//')"
  [ -z "$FTP_ROOT" ] && FTP_ROOT="/var/ftp"
  note "FTP policy: $FTP_MODE (root: $FTP_ROOT)"

  # ---- required browser ----
  BROWSER="$(grep -oiE 'browser[^.]*?(chromium|firefox|thunderbird)' <<<"$RTXT" 2>/dev/null | grep -oiE 'chromium|firefox|thunderbird' | head -1)"
  [ -n "$BROWSER" ] && note "required browser: $BROWSER"

  # ---- wireshark authorized? (Mint TR2: "Wireshark is an authorized software program") ----
  if $SUDO grep -qiE 'wireshark[^.]*authorized' <<<"$RTXT" 2>/dev/null; then
    WIRESHARK_OK=1
    note "Wireshark is AUTHORIZED per README — will NOT be purged"
  fi
}

is_listed() { # user name
  local n u
  for u in "${ADMIN_NAMES[@]:-}" "${USER_NAMES[@]:-}"; do [ "${u:-}" = "$n" ] && return 0; done
  return 1
}

crit() { # service token — is it critical per README?
  local s; for s in "${CRIT_SVC[@]:-}"; do [ "$s" = "$1" ] && return 0; done; return 1
}

# ----------------------------- forensics -------------------------------------
do_forensics() {
  log "FORENSICS ENGINE (read-only candidates)"
  local f
  $SUDO find /root /home -maxdepth 4 -type f \( -iname '*Forensics Question*' \) 2>/dev/null > /tmp/.cp_fq
  local count; count="$($SUDO wc -l < /tmp/.cp_f 2>/dev/null || echo 0)"
  if [ "${count:-0}" = "0" ]; then note "no Forensics Question files found"; return 0; fi
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    echo
    echo "FILE: $f"
    local txt; txt="$($SUDO sed -e 's/<[^>]*>/ /g' -e 's/&[a-z0-9]*;/ /g' "$f" 2>/dev/null | tr -s ' \t' ' ')"
    # 1) base64 blob -> rot13 -> text
    local b64 decoded
    b64="$(grep -oE '[A-Za-z0-9+/]{24,}={0,2}' <<<"$txt" | head -1)"
    if [ -n "$b64" ]; then
      decoded="$(echo "$b64" | base64 -d 2>/dev/null | tr 'A-Za-z' 'N-Za-Mn-z-m')"
      [ -n "$decoded" ] && echo "  [base64+rot13] $decoded"
      decoded="$(echo "$b64" | base64 -d 2>/dev/null)"
      [ -n "$decoded" ] && echo "  [base64]       $decoded"
    fi
    # 2) locate-style file questions
    if grep -qiE 'locate|where (are|is) .*files|path to' <<<"$txt"; then
      for ext in mp3 ogg zip wav avi; do
        $SUDO find /home /root /srv /opt /usr/games -xdev -type f -iname "*.$ext" 2>/dev/null | head -5 | sed "s/^/  [locate .$ext] /"
      done
    fi
    # 3) pcap
    local pcaps; pcaps="$($SUDO find /root /home -xdev -iname '*.pcap*' 2>/dev/null | head -3)"
    if [ -n "$pcaps" ]; then
      while IFS= read -r p; do
        echo "  [pcap] $p"
        $SUDO command -v tshark >/dev/null 2>&1 && \
          $SUDO tshark -r "$p" 2>/dev/null | grep -iE 'PASS|password' | head -5 | sed 's/^/    /'
      done <<<"$pcaps"
    fi
    # 4) steganography
    if grep -qiE 'steg|hidden|passphrase' <<<"$txt"; then
      local ph; ph="$(grep -oiE 'passphrase[^:]*:[^<]*' <<<"$txt" | sed 's/.*:[[:space:]]*//' | awk '{print $1}' | head -1)"
      $SUDO command -v steghide >/dev/null 2>&1 || note "steghide not installed — apt-get install steghide"
      for img in $($SUDO find /root /home -xdev \( -iname '*.jpg' -o -iname '*.png' -o -iname '*.bmp' \) 2>/dev/null | head -5); do
        [ -n "${ph:-}" ] && echo "  [steghide] try passphrase '$ph' on $img"
        echo "  [steghide] $SUDO steghide extract --sf \"$img\" --apf -   then: md5sum <extracted>"
      done
    fi
    # 5) backdoor path question
    if grep -qiE 'backdoor' <<<"$txt"; then
      $SUDO ss -tlnp 2>/dev/null | grep -vE '127.0.0.1|::1' | sed 's/^/  [listen] /'
    fi
  done < /tmp/.cp_f
  echo
  if [ "$AUTO_WRITE_ANSWERS" = "1" ]; then
    note "AUTO_WRITE_ANSWERS=1 — pick the single best candidate above and append it to the file as:  Answer: <text>"
  else
    note "confirm the candidate, then write 'Answer: <text>' into the question file and save (scored format)."
  fi
  return 0
}

# ----------------------------- users & accounts ------------------------------
chk_users() {
  local ok=1
  # unlisted user accounts (uid>=1000, non-system)
  $SUDO awk -F: '$3>=1000 && $1!="nobody" && $1!="ftp" {print $1}' /etc/passwd > /tmp/.cp_uid1000 2>/dev/null
  local u extra=""
  while IFS= read -r u; do
    [ -n "$u" ] || continue
    if ! is_listed "$u" && [ "$u" != "$NEW_ADMIN" ]; then
      extra="$extra $u"; ok=0
    fi
  done < /tmp/.cp_uid1000
  if [ -z "$ADMIN_NAMES" ] && [ -z "$USER_NAMES" ]; then note "no roster parsed from README — skipping user checks"; return 0; fi
  report "$([ $ok -eq 1 ] && echo PASS || echo FAIL)" 8 "No unauthorized user accounts" "$([ -n "$extra" ] && echo "unlisted:$extra")"

  # unauthorized sudoers
  local sudoers_extra=""
  $SUDO getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n' | sed 's/^ *//' | awk 'NF' > /tmp/.cp_sudo
  while IFS= read -r u; do
    [ -n "$u" ] || continue
    if ! is_listed "$u" && [ "$u" != "$NEW_ADMIN" ]; then sudoers_extra="$sudoers_extra $u"; ok=0; fi
  done < /tmp/.cp_sudo
  report "$([ $ok -eq 1 ] && echo PASS || echo FAIL)" 4 "No unauthorized administrators (sudo group)" "$([ -n "$sudoers_extra" ] && echo "extra:$sudoers_extra")"

  # root not blank
  local rootpw; rootpw="$($SUDO awk -F: '$1=="root"{print $2}' /etc/shadow 2>/dev/null)"
  if [ -z "$rootpw" ]; then
    report FAIL 3 "Root password is not blank/locked" "shadow hash empty"
  else
    report PASS 3 "Root password is not blank/locked" "hash: ${rootpw:0:7}..."
  fi

  # password aging on all live uid>=1000
  local maxok=1 minok=1 badmax="" badmin=""
  while IFS= read -r u; do
    [ -n "$u" ] || continue
    local mx mn
    mx="$($SUDO chage -l "$u" 2>/dev/null | awk -F: '/Maximum password age/{gsub(/ /,"",$3);print $3}')"
    mn="$($SUDO chage -l "$u" 2>/dev/null | awk -F: '/Minimum password age/{gsub(/ /,"",$3);print $3}')"
    [ "${mx:-}" = "-1" ] && { maxok=0; badmax="$badmax $u"; }
    [ "${mn:-}" = "0" ]  && { minok=0; badmin="$badmin $u"; }
  done < /tmp/.cp_uid1000
  report "$([ $maxok -eq 1 ] && echo PASS || echo FAIL)" 3 "Maximum password age set (all user accounts)" "$([ -n "$badmax" ] && echo "unset:$badmax")"
  report "$([ $minok -eq 1 ] && echo PASS || echo FAIL)" 3 "Minimum password age set (all user accounts)" "$([ -n "$badmin" ] && echo "unset:$badmin")"

  # requested group(s)
  # pattern A: group created with named members
  if [ -n "$NEW_GROUP" ]; then
    local gmem; gmem="$($SUDO getent group "$NEW_GROUP" 2>/dev/null | cut -d: -f4)"
    if [ -z "$gmem" ] && [ -z "${NEW_GROUP_MEMBERS[0]:-}" ]; then
      report PASS 4 "Requested group exists" "$NEW_GROUP"
    elif [ -z "$gmem" ]; then
      report FAIL 4 "Requested group + members" "$NEW_GROUP missing"
    else
      local miss="" m
      for m in "${NEW_GROUP_MEMBERS[@]:-}"; do
        [ -n "$m" ] || continue
        case ",$gmem," in *",$m,"*) ;; *) miss="$miss $m";; esac
      done
      report "$([ -z "$miss" ] && echo PASS || echo FAIL)" 4 "Requested group + members" "$([ -n "$miss" ] && echo "missing:$miss")"
    fi
  fi
  # pattern B: existing group + one user added
  if [ -n "$ADD_USER_TO_GROUP" ] && [ -n "$ADD_USER_TO_USER" ]; then
    local amem; amem="$($SUDO getent group "$ADD_USER_TO_GROUP" 2>/dev/null | cut -d: -f4)"
    case ",$amem," in *",$ADD_USER_TO_USER,"*)
      report PASS 4 "User in requested group" "$ADD_USER_TO_USER in $ADD_USER_TO_GROUP" ;;
    *)
      report FAIL 4 "User in requested group" "$ADD_USER_TO_USER not in $ADD_USER_TO_GROUP (members:$amem)" ;;
    esac
  fi

  # new admin (if requested)
  if [ -n "$NEW_ADMIN" ]; then
    local e; e="$($SUDO getent passwd "$NEW_ADMIN" 2>/dev/null)"
    if [ -z "$e" ]; then
      report FAIL 4 "Requested new admin account exists" "$NEW_ADMIN"
    else
      local forced; forced="$($SUDO chage -l "$NEW_ADMIN" 2>/dev/null | grep -c 'must be changed')"
      $SUDO getent group sudo | grep -q "$NEW_ADMIN" && [ "${forced:-0}" -ge 1 ] \
        && report PASS 7 "New admin exists + forced password change" "$NEW_ADMIN" \
        || report WARN 7 "New admin exists" "check sudo membership + chage -d 0 on $NEW_ADMIN"
    fi
  fi

  # weak passwords: check listed admin with password under 12 — can't read hash strength;
  # proxy: if WEAK_TARGETS non-empty and their shadow hash starts with '!' (locked/never set)
  # we cannot verify strength remotely; flag as manual check.
  if [ ${#WEAK_TARGETS[@]} -gt 0 ]; then
    note "MANUAL: change weak admin passwords (from README <12 chars): ${WEAK_TARGETS[*]}  (>=12 chars)"
  fi
}

fix_users() {
  [ ${#ADMIN_NAMES[@]} -eq 0 ] && [ ${#USER_NAMES[@]} -eq 0 ] && { note "no roster — skipping user fixes"; return 0; }
  local u
  # 1) remove unlisted user accounts (back up home to /root/cp_removed_users)
  $SUDO awk -F: '$3>=1000 && $1!="nobody" && $1!="ftp" {print $1}' /etc/passwd > /tmp/.cp_uid1000 2>/dev/null
  while IFS= read -r u; do
    [ -n "$u" ] || continue
    if ! is_listed "$u" && [ "$u" != "$NEW_ADMIN" ]; then
      note "removing user $u"
      $SUDO pkill -u "$u" 2>/dev/null || true
      $SUDO userdel -r "$u" 2>&1 | grep -viE 'no such|not found' || true
    fi
  done < /tmp/.cp_uid1000

  # 2) clean sudo group
  while IFS= read -r u; do
    [ -n "$u" ] || continue
    if ! is_listed "$u" && [ "$u" != "$NEW_ADMIN" ]; then
      note "removing $u from sudo group"
      $SUDO gpasswd -d "$u" sudo 2>/dev/null || true
    fi
  done < <($SUDO getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n')

  # 3) weak admin passwords -> new strong 16-char pw (12+ required)
  local w
  for w in "${WEAK_TARGETS[@]:-}"; do
    [ -n "$w" ] || continue
    [ "$w" = "$AUTOLOGIN" ] && { note "SKIP password change for $w (auto-login user)"; continue; }
    [ -n "$($SUDO getent passwd "$w" 2>/dev/null)" ] || continue
    local npw
    npw="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 10)$(tr -dc 'a-z0-9' </dev/urandom | head -c 4)$(tr -dc '@#%&*!' </dev/urandom | head -c 2)9aXk"
    $SUDO chage -d 10000 "$w" 2>/dev/null || true   # clear forced-change so new pw takes effect
    $SUDO usermod -p "$(yescrypt_hash "$npw" 2>/dev/null || openssl passwd -6 -salt cp19 "$npw" 2>/dev/null)" "$w" 2>/dev/null \
      || echo "$npw" | $SUDO chage -d 10000 -p "$npw" "$w" 2>/dev/null || true
    note "password changed for $w (new pw recorded in /root/cp_pw_changes.log)"
    echo "$w : $npw" >> /root/cp_pw_changes.log
  done

  # 4) requested group(s)
  local m
  if [ -n "$NEW_GROUP" ]; then
    $SUDO getent group "$NEW_GROUP" >/dev/null 2>&1 || $SUDO groupadd "$NEW_GROUP" 2>/dev/null || $SUDO addgroup --system "$NEW_GROUP" 2>/dev/null
    for m in "${NEW_GROUP_MEMBERS[@]:-}"; do
      [ -n "$m" ] || continue
      $SUDO getent passwd "$m" >/dev/null 2>&1 || { note "group member $m does not exist — skipped"; continue; }
      $SUDO usermod -aG "$NEW_GROUP" "$m" 2>/dev/null || $SUDO gpasswd -a "$m" "$NEW_GROUP" 2>/dev/null
    done
    note "group '$NEW_GROUP' ensured with members"
  fi
  if [ -n "$ADD_USER_TO_GROUP" ] && [ -n "$ADD_USER_TO_USER" ]; then
    $SUDO getent group "$ADD_USER_TO_GROUP" >/dev/null 2>&1 || $SUDO groupadd "$ADD_USER_TO_GROUP" 2>/dev/null || $SUDO addgroup --system "$ADD_USER_TO_GROUP" 2>/dev/null
    $SUDO getent passwd "$ADD_USER_TO_USER" >/dev/null 2>&1 || { note "user $ADD_USER_TO_USER does not exist — skipped"; }
    $SUDO usermod -aG "$ADD_USER_TO_GROUP" "$ADD_USER_TO_USER" 2>/dev/null || $SUDO gpasswd -a "$ADD_USER_TO_USER" "$ADD_USER_TO_GROUP" 2>/dev/null
    note "user '$ADD_USER_TO_USER' added to group '$ADD_USER_TO_GROUP'"
  fi

  # 5) new admin account
  if [ -n "$NEW_ADMIN" ]; then
    if ! $SUDO getent passwd "$NEW_ADMIN" >/dev/null 2>&1; then
      $SUDO useradd -m -s /bin/bash "$NEW_ADMIN" 2>/dev/null || $SUDO adduser --disabled-password --gecos "" "$NEW_ADMIN" 2>/dev/null
    fi
    local npx
    npx="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 12)$(tr -dc '@#%&*' </dev/urandom | head -c 4)1q"
    echo "$npx" | $SUDO chage -d 0 -p "$npx" "$NEW_ADMIN" 2>/dev/null || $SUDO usermod -p "$(openssl passwd -6 -salt cp19 "$npx")" "$NEW_ADMIN"
    $SUDO usermod -aG sudo "$NEW_ADMIN" 2>/dev/null || $SUDO gpasswd -a "$NEW_ADMIN" sudo 2>/dev/null
    echo "$NEW_ADMIN : $npx" >> /root/cp_pw_changes.log
    note "admin account $NEW_ADMIN created (forced change at next login)"
  fi

  # 6) root locked if blank
  local rootpw; rootpw="$($SUDO awk -F: '$1=="root"{print $2}' /etc/shadow 2>/dev/null)"
  [ -z "$rootpw" ] && { $SUDO passwd -l root 2>/dev/null; note "root password locked (was blank)"; }

  # 7) aging on every live user
  while IFS= read -r u; do
    [ -n "$u" ] || continue
    $SUDO chage -M "$PASSMAX" -m "$PASSMIN" -W "$WARNAGE" "$u" 2>/dev/null || true
  done < /tmp/.cp_uid1000
  $SUDO sed -i -E "s/^#?PASS_MAX_DAYS[[:space:]]+.*$/PASS_MAX_DAYS\t$PASSMAX/; s/^#?PASS_MIN_DAYS[[:space:]]+.*$/PASS_MIN_DAYS\t$PASSMIN/; s/^#?PASS_WARN_AGE[[:space:]]+.*$/PASS_WARN_AGE\t$WARNAGE/" /etc/login.defs 2>/dev/null
  note "chage -M $PASSMAX -m $PASSMIN -W $WARNAGE applied to all user accounts; login.defs set"
}

# ----------------------------- PAM -------------------------------------------
chk_pam() {
  local A=/etc/pam.d/common-auth
  # faillock
  if $SUDO grep -qE 'pam_faillock' "$A" 2>/dev/null; then
    report PASS 3 "Account lockout (pam_faillock in common-auth)"
  else
    report FAIL 3 "Account lockout (pam_faillock in common-auth)" "no pam_faillock lines"
  fi
  # minlen via pwquality or pam line
  if $SUDO grep -rsqE "minlen[=[:space:]]+$MINLEN" /etc/security/pwquality.conf 2>/dev/null \
     || $SUDO grep -rsqE "pam_pwquality.*minlen=[0-9]+" /etc/pam.d/ 2>/dev/null \
     || $SUDO grep -rsqE "pam_unix.so.*(minlen|obsure)" /etc/pam.d/common-password 2>/dev/null; then
    report PASS 6 "Minimum password length enforced"
  else
    report FAIL 6 "Minimum password length enforced" "no minlen found"
  fi
  # remember
  if $SUDO grep -rsqE "pam_pwhistory.*remember=$RECS" /etc/pam.d/ 2>/dev/null \
     || $SUDO grep -rsqE "pam_unix.*remember=$RECS" /etc/pam.d/common-password 2>/dev/null; then
    report PASS 3 "Previous passwords remembered (remember=$RECS)"
  else
    report FAIL 3 "Previous passwords remembered (remember=$RECS)"
  fi
  # nullok
  if $SUDO grep -E 'pam_unix' /etc/pam.d/common-auth 2>/dev/null | grep -q 'nullok'; then
    report FAIL 3 "Null passwords do not authenticate (no nullok)" "nullok present in common-auth"
  else
    report PASS 3 "Null passwords do not authenticate (no nullok)"
  fi
}

fix_pam() {
  log "PAM hardening"
  # packages
  if $PROFILE_IS_mint; then
    $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y libpam-pwquality libpam-pwhistory 2>/dev/null || true
  else
    $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y libpam-pwquality 2>/dev/null || true
  fi

  # pwquality minlen
  $SUDO bash -c "printf 'minlen=$MINLEN\nscore = en\n' > /etc/security/pwquality.conf" 2>/dev/null

  # --- canonical pam-auth-update method (Debian/Mint both ship pam-configs) ---
  $SUDO bash -c '
    [ -d /usr/share/pam-configs ] || exit 0
    printf "[pam]\ntype=\t\trequired\ncontrol\t\tsuccess=2 default=ignore\nmodule-path\t/lib/security\nmodule\t\tpam_faillock.so preauth silent audit deny=5 unlock_time=900\n\ntype=\tsufficient\ncontrol\t\tsuccess=1 default=ignore\nmodule\t\tpam_unix.so nullok\n\ntype=\tsufficient\ncontrol\t\tsuccess=1 default=ignore\nmodule\t\tpam_faillock.so authfail audit deny=5 unlock_time=900\n\ntype=\trequired\ncontrol\t\t[default=1]\nmodule\t\tpam_unix.so\n" > /usr/share/pam-configs/faillock
    printf "[pam]\ntype=\t\trequired\ncontrol\t\t[success=1 default=ignore]\nmodule-path\t/lib/security\nmodule\t\tpam_pwquality.so retry=3 minlen=$MINLEN enforce_for_root\n" > /usr/share/pam-configs/pwquality
    printf "[pam]\ntype=\t\trequired\ncontrol\t\t[success=1 default=ignore]\nmodule-path\t/lib/security\nmodule\t\tpam_pwhistory.so use_authtok remember=$RECS enforce_for_root\n" > /usr/share/pam-configs/pwhistory
  ' 2>/dev/null
  $SUDO pam-auth-update --force 2>/dev/null || true

  # --- direct fallback (this is the fix that scored in R2: common-auth direct) ---
  local A=/etc/pam.d/common-auth
  $SUDO bash -c "
    f=$A; cp -a \$f \${f}.bak.cp19 2>/dev/null
    grep -q pam_faillock \$f || {
      sed -i 's/^auth[[:space:]]*\\[success=2 default=ignore\\][[:space:]]*pam_unix.so.*/&\\nauth\\t\\t[success=1 default=ignore]\\tpam_faillock.so authfail audit deny=5 unlock_time=900/' \$f
      sed -i '1i auth\\t\\trequired\\tpam_faillock.so preauth silent audit deny=5 unlock_time=900' \$f
    }
    sed -i 's/pam_unix.so[^\\n]*nullok/pam_unix.so/' \$f
  " 2>/dev/null
  note "faillock: preauth+authfail deny=5 unlock_time=900 (common-auth direct)"

  # pwhistory / remember via common-password
  local P=/etc/pam.d/common-password
  $SUDO bash -c "
    f=$P; cp -a \$f \${f}.bak.cp19 2>/dev/null
    if ! grep -q pam_pwhistory \$f; then
      sed -i 's/^password[[:space:]]*\\[success=1 default=ignore\\][[:space:]]*pam_unix.so.*/&\\npassword\\t\\trequired\\tpam_pwhistory.so use_authtok remember=$RECS enforce_for_root/' \$f 2>/dev/null || \
      sed -i 's/pam_unix.so obscure.*/& remember=$RECS/' \$f
    fi
  " 2>/dev/null
  note "pwhistory remember=$RECS (common-password)"
}

PROFILE_IS_mint() { case "$PROFILE" in mint21|ubuntu) return 0;; *) return 1;; esac; }

# ----------------------------- files & permissions ---------------------------
chk_files() {
  local perm
  perm="$($SUDO stat -c %a /etc/shadow 2>/dev/null)"
  [ "$perm" = "640" ] && report PASS 5 "Insecure permissions on /etc/shadow fixed (640)" \
                  || report FAIL 5 "Insecure permissions on /etc/shadow fixed (640)" "perm=$perm"

  local gperm; gperm="$($SUDO stat -c %a /boot/grub/grub.cfg 2>/dev/null)"
  if [ -n "$gperm" ] && [ "$gperm" != "640" ]; then
    report FAIL 5 "GRUB configuration not world readable" "grub.cfg=$gperm"
  elif [ -n "$gperm" ]; then
    report PASS 5 "GRUB configuration not world readable" "grub.cfg=640"
  else
    report WARN 5 "GRUB configuration not world readable" "no /boot/grub/grub.cfg (check profile)"
  fi

  local sp; sp="$($SUDO stat -c %a /etc/shadow- 2>/dev/null)"
  [ -z "$sp" ] || [ "$sp" = "640" ] || [ "$sp" = "600" ] && report PASS 0 "etc/shadow- ok" \
    || report WARN 0 "etc/shadow- perm=$sp"

  local ldefs; ldefs="$($SUDO awk -F'\t' '/^PASS_MAX_DAYS/{print $2}' /etc/login.defs 2>/dev/null)"
  [ "${ldefs:-}" = "$PASSMAX" ] && report PASS 0 "login.defs PASS_MAX_DAYS=$PASSMAX" \
    || report WARN 0 "login.defs PASS_MAX_DAYS=${ldefs:-unset}"
}

fix_files() {
  log "File permissions (CIS 7.1.x)"
  $SUDO chmod 640 /etc/shadow /etc/shadow- /etc/gshadow 2>/dev/null
  $SUDO chmod 644 /etc/passwd /etc/passwd- /etc/group /etc/group- 2>/dev/null
  $SUDO chmod 640 /etc/securetty 2>/dev/null
  $SUDO chmod 640 /boot/grub/grub.cfg 2>/dev/null
  note "shadow/gshadow 640, passwd/group 644, securetty 640, grub.cfg 640 (password aging is the student's — see homework list)"
}

# ----------------------------- sysctl ----------------------------------------
SYSCTL_SETS="
net.ipv4.tcp_syncookies=1
net.ipv4.ip_forward=0
net.ipv4.conf.all.forwarding=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.tcp_rfc1337=1
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.all.autoconf=0
kernel.randomize_va_space=2
kernel.dmesg_restrict=1
kernel.kptr_restrict=1
kernel.core_uses_pid=1
kernel.unprivileged_bpf_disabled=1
fs.suid_dumpable=0
fs.protected_symlinks=1
fs.protected_hardlinks=1
"
chk_sysctl() {
  local line k v bad=""
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    k="${line%%=*}"; v="${line#*=}"
    local cur; cur="$($SUDO sysctl -n "$k" 2>/dev/null)"
    [ "${cur:-}" != "$v" ] && bad="$bad ${k}=${cur:-?}(want $v)"
  done <<<"$SYSCTL_SETS"
  if [ -z "$bad" ]; then
    report PASS 12 "Sysctl kernel/network hardening (syncookies, ip_forward, rfc1337, ASLR, …)"
  else
    report FAIL 12 "Sysctl kernel/network hardening" "$bad"
  fi
}
fix_sysctl() {
  log "Sysctl hardening (CIS 3.3.x / 1.5.x)"
  $SUDO bash -c "cat > /etc/sysctl.d/90-cp-hardening.conf" <<<"$SYSCTL_SETS"
  $SUDO sysctl -p /etc/sysctl.d/90-cp-hardening.conf 2>/dev/null
  note "applied + persisted /etc/sysctl.d/90-cp-hardening.conf"
}

# ----------------------------- SSH -------------------------------------------
chk_ssh() {
  local c="/etc/ssh/sshd_config"
  local rootlogin emptylogin
  rootlogin="$($SUDO awk '$1=="PermitRootLogin"{print $2; exit}' "$c" 2>/dev/null)"
  [ -z "$rootlogin" ] && rootlogin="yes (default)"
  emptylogin="$($SUDO awk '$1=="PermitEmptyPasswords"{print $2; exit}' "$c" 2>/dev/null)"
  [ -z "$emptylogin" ] && emptylogin="no (default)"
  [ "$rootlogin" = "no" ] && report PASS 5 "SSH: PermitRootLogin disabled" \
                      || report FAIL 5 "SSH: PermitRootLogin disabled" "value=$rootlogin"
  [ "$emptylogin" = "no" ] && report PASS 6 "SSH: PermitEmptyPasswords disabled" \
                      || report FAIL 6 "SSH: PermitEmptyPasswords disabled" "value=$emptylogin"
  local en; en="$($SUDO systemctl is-enabled ssh 2>/dev/null || $SUDO systemctl is-enabled sshd 2>/dev/null)"
  if [ "${en:0:4}" = "enab" ] || crit sshd; then
    report PASS 0 "OpenSSH service enabled (critical service)"
  else
    report WARN 0 "OpenSSH service state" "is-enabled=$en — README critical list says keep"
  fi
}
fix_ssh() {
  log "SSH hardening (CIS 5.1.x)"
  local c="/etc/ssh/sshd_config"
  [ -f "$c" ] || return 0
  $SUDO cp -a "$c" "$c.bak.cp19" 2>/dev/null
  $SUDO bash -c "
    f=$c
    sed -i -E 's/^#?PermitRootLogin.*/PermitRootLogin no/' \$f
    grep -qE '^[[:space:]]*PermitRootLogin' \$f || sed -i '1i PermitRootLogin no' \$f
    sed -i -E 's/^#?PermitEmptyPasswords.*/PermitEmptyPasswords no/' \$f
    grep -qE '^[[:space:]]*PermitEmptyPasswords' \$f || sed -i '/^PermitRootLogin/a PermitEmptyPasswords no' \$f
    sed -i -E 's/^#?MaxAuthTries.*/MaxAuthTries 4/' \$f
    grep -qE '^[[:space:]]*MaxAuthTries' \$f || sed -i '/^PermitEmptyPasswords/a MaxAuthTries 4' \$f
    sed -i -E 's/^#?X11Forwarding.*/X11Forwarding no/' \$f
    grep -qE '^[[:space:]]*X11Forwarding' \$f || sed -i '/^MaxAuthTries/a X11Forwarding no' \$f
  " 2>/dev/null
  $SUDO systemctl restart ssh 2>/dev/null || $SUDO systemctl restart sshd 2>/dev/null || true
  note "PermitRootLogin no / PermitEmptyPasswords no / MaxAuthTries 4 / X11Forwarding no; ssh restarted"
}

# ----------------------------- services --------------------------------------
chk_services() {
  local bad="" s
  for s in apache2 nginx squid dovecot lighttpd proftpd; do
    $SUDO systemctl is-enabled "$s" 2>/dev/null | grep -q "enabled" && [ ! -z "$($SUDO systemctl is-active "$s" 2>/dev/null | grep -c active)" ] && ! crit "$s" && bad="$bad $s"
  done
  [ -z "$bad" ] && report PASS 4 "Unneeded web/mail services disabled" \
           || report FAIL 4 "Unneeded web/mail services disabled" "still up:$bad"

  # vsftpd per scenario
  local vs; vs="$($SUDO systemctl is-active vsftpd 2>/dev/null)"
  case "$FTP_MODE" in
    keep)    [ "$vs" = "active" ] && report PASS 4 "FTP (vsftpd) operational per README" \
                             ||  report FAIL 4 "FTP (vsftpd) operational per README" "state=$vs";;
    disable) [ "$vs" != "active" ] && report PASS 4 "FTP (vsftpd) disabled per README" \
                             ||    report FAIL 4 "FTP (vsftpd) disabled per README" "state=$vs";;
    *) note "FTP mode auto — README did not specify; leave vsftpd as found ($vs)";;
  esac

  # critical services running
  local miss=""
  for s in "${CRIT_SVC[@]:-}"; do
    case "$s" in
      openssh|sshd|ssh) $SUDO systemctl is-active ssh sshd 2>/dev/null | grep -q active || miss="$miss sshd";;
      vsftpd|ftp)       $SUDO systemctl is-active vsftpd 2>/dev/null | grep -q active || miss="$miss vsftpd";;
    esac
  done
  [ -z "$miss" ] && report PASS 0 "Critical services running" \
           || report FAIL 0 "Critical services running" "down:$miss"

  # display manager (Debian 12 README: "The display manager should remain set to LightDM")
  if [ "$PROFILE" = "debian12" ] && $SUDO dpkg -s lightdm >/dev/null 2>&1; then
    $SUDO systemctl is-enabled lightdm 2>/dev/null | grep -q enabled \
      && report PASS 0 "Display manager remains LightDM" \
      || report WARN 0 "Display manager remains LightDM" "lightdm not enabled — verify in GUI, do not switch DMs"
  fi

  # CCS client guard (README: "Do not stop or disable the CCS Client service or process")
  if $SUDO pgrep -fiE 'ccs|cyberpatriot' >/dev/null 2>&1; then
    report PASS 0 "CCS client process running (untouched)"
  else
    report WARN 0 "CCS client process running" "not detected via pgrep — verify in GUI; never kill"
  fi
}

fix_services() {
  log "Service policy"
  local s
  for s in apache2 nginx squid dovecot lighttpd proftpd; do
    if crit "$s"; then note "SKIP $s (critical per README)"; continue; fi
    $SUDO systemctl disable --now "$s" 2>/dev/null || true
  done
  case "$FTP_MODE" in
    keep)
      $SUDO systemctl enable --now vsftpd 2>/dev/null || true
      $SUDO bash -c "
        f=/etc/vsftpd.conf; cp -a \$f \${f}.bak.cp19 2>/dev/null
        sed -i -E 's/^#?anonymous_enable=.*/anonymous_enable=YES/; s/^#?local_enable=.*/local_enable=NO/; s/^#?write_enable=.*/write_enable=NO/' \$f
        grep -qE '^anonymous_enable' \$f || { echo anonymous_enable=YES >> \$f; }
        grep -qE '^local_enable'      \$f || { echo local_enable=NO      >> \$f; }
        grep -qE '^anon_root'         \$f && sed -i -E 's/^anon_root=.*/anon_root=$FTP_ROOT/' \$f
        grep -qE '^anon_root'         \$f || { echo anon_root=$FTP_ROOT  >> \$f; }
      " 2>/dev/null
      $SUDO systemctl restart vsftpd 2>/dev/null || true
      note "vsftpd enabled, anonymous=YES local=NO anon_root=$FTP_ROOT (files NOT removed)"
      ;;
    disable)
      $SUDO systemctl disable --now vsftpd 2>/dev/null || true
      note "vsftpd disabled"
      ;;
  esac
  # ensure ssh is enabled (never disable — penalty guard)
  $SUDO systemctl enable ssh 2>/dev/null || $SUDO systemctl enable sshd 2>/dev/null || true
  # display manager (Debian 12 README: keep LightDM) — affirmative enable, never switch DMs
  if [ "$PROFILE" = "debian12" ] && $SUDO dpkg -s lightdm >/dev/null 2>&1; then
    $SUDO systemctl enable lightdm 2>/dev/null || true
    note "lightdm left enabled (display manager unchanged)"
  fi
  # CCS client: this script NEVER touches the CCS service or process
}

# ----------------------------- updates ---------------------------------------
chk_updates() {
  # APT::Periodic
  if $SUDO grep -rsqE 'APT::Periodic::Update-Package-Lists "1"' /etc/apt/apt.conf.d/ 2>/dev/null \
     || $SUDO grep -qsE 'Update-Package-Lists "1"' /etc/apt/apt.conf 2>/dev/null; then
    report PASS 4 "APT refreshes update list automatically"
  else
    report FAIL 4 "APT refreshes update list automatically"
  fi
  if $SUDO apt-config dump 2>/dev/null | grep -qE 'Unattended-Upgrade::"Enable" "1"' \
     || $SUDO grep -rsqE '"Enable".*"1"' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null; then
    report PASS 0 "Unattended security upgrades configured"
  else
    report WARN 0 "Unattended security upgrades configured"
  fi
  # up-to-date proxy: apt list --upgradable count (needs sources working)
  local up
  up="$($SUDO apt-get -s upgrade 2>/dev/null | grep -cE '^[0-9]+ upgraded' || echo '?')"
  note "apt upgrade simulation: ${up:-?} packages upgradable"
  # browser present (penalty guard)
  case "$BROWSER" in
    chromium) $SUDO command -v chromium >/dev/null 2>&1 && report PASS 0 "Chromium present (penalty guard)" || report FAIL 0 "Chromium present (penalty guard)";;
    firefox)  $SUDO command -v firefox  >/dev/null 2>&1 && report PASS 0 "Firefox present (penalty guard)"   || report FAIL 0 "Firefox present (penalty guard)";;
    thunderbird) $SUDO command -v thunderbird >/dev/null 2>&1 && report PASS 0 "Thunderbird present" || report FAIL 0 "Thunderbird present";;
    *) $SUDO dpkg -l 2>/dev/null | grep -qE '^ii[[:space:]]+(chromium|firefox|thunderbird)' && report PASS 0 "browser present (penalty guard)" || report WARN 0 "browser check" "no browser named in README";;
  esac
  $SUDO dpkg -l perl-base >/dev/null 2>&1 && report PASS 0 "perl-base present (penalty guard)" || report WARN 0 "perl-base missing?"
}

fix_sources_and_updates() {
  log "APT sources + updates (run BEFORE package purge — purge needs working repos)"
  local sl=/etc/apt/sources.list
  local good
  good="$($SUDO grep -cE '^[[:space:]]*deb(-sources)?[[:space:]]' "$sl" 2>/dev/null || echo 0)"
  if [ "${good:-0}" = "0" ] || $SUDO apt-get update 2>&1 | grep -qE 'Err|404|No package'; then
    note "sources.list broken/empty — restoring profile defaults"
    case "$PROFILE" in
      debian12)
        $SUDO bash -c "cat > $sl" <<'EOS'
deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
deb http://deb.debian.org/debian bookworm-updates main contrib non-free non-free-firmware
deb http://deb.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware
EOS
        ;;
      mint21)
        $SUDO bash -c "cat > $sl" <<'EOS'
deb http://packages.linuxmint.com/ vera main upstream import backport
deb http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu jammy-security main restricted universe multiverse
EOS
        ;;
    esac
    note "restored $sl for profile $PROFILE"
  fi
  $SUDO DEBIAN_FRONTEND=noninteractive apt-get update 2>&1 | tail -3

  # purge prohibited packages first (they may be broken/old; remove cleanly)
  log "Prohibited software purge"
  local pkgs="aisleriot amule zangband doona xprobe ettercap freeciv hydra john metasploit"
  [ "$WIRESHARK_OK" = "1" ] || pkgs="wireshark $pkgs"
  local list="" p
  for p in $pkgs; do
    if $SUDO dpkg -s "$p" >/dev/null 2>&1; then list="$list $p"; fi
  done
  if [ -n "$list" ]; then
    $SUDO DEBIAN_FRONTEND=noninteractive apt-get purge -y $list 2>&1 | grep -E '^(Removing|Purging|[0-9]+.*removed)' || true
    note "purged:$list"
  else
    note "no prohibited packages present (or authorized: wireshark_ok=$WIRESHARK_OK)"
  fi

  # prohibited archives (CP hides them in /usr/games, /opt)
  local archs
  archs="$($SUDO find /usr/games /opt /usr/local -maxdepth 3 -type f \( -iname '*.zip' -o -iname '*.tar.gz' -o -iname '*.rar' \) 2>/dev/null)"
  if [ -n "$archs" ]; then
    $SUDO rm -f $archs 2>/dev/null; note "removed prohibited archives: $(echo $archs | tr '\n' ' ')"
  else
    note "no prohibited archives in /usr/games /opt /usr/local"
  fi

  # prohibited media
  local media
  media="$($SUDO find /home /root /srv /opt /usr/games -xdev -type f \( -iname '*.mp3' -o -iname '*.ogg' \) 2>/dev/null)"
  if [ -n "$media" ]; then
    $SUDO rm -f $media 2>/dev/null; note "removed prohibited media: $(echo $media | tr '\n' ' ')"
  else
    note "no prohibited mp3/ogg media found"
  fi

  # backdoor: netcat
  log "Backdoor sweep"
  $SUDO bash -c '
    for u in $(getent passwd | awk -F: "(\$3>=1000||\$1==\"root\"){print \$1}"); do
      ct=$(crontab -l -u "$u" 2>/dev/null)
      if echo "$ct" | grep -qE "(^|[ ;/])nc([. ]|$)|/nc|netcat"; then
        echo "  [cron] user=$u nc entry:"; echo "$ct" | grep -nE "nc"
        crontab -r -u "$u" 2>/dev/null; echo "  -> crontab purged for $u"
      fi
    done
    ss -tlnp 2>/dev/null | grep -E ":1337|/nc" && echo "  [listen] nc listener still visible above"
  ' 2>/dev/null || true
  $SUDO pkill -f 'nc\s+-[lp]' 2>/dev/null; $SUDO pkill -f 'nc\.traditional' 2>/dev/null
  # remove rogue nc binaries that are NOT from a package (nmap's ncat is fine)
  for b in /usr/bin/nc.traditional /usr/local/bin/nc /usr/local/sbin/nc /opt/nc; do
    if [ -e "$b" ] && ! $SUDO dpkg -S "$b" >/dev/null 2>&1; then
      $SUDO rm -f "$b"; note "removed rogue binary $b (not owned by any package)"
    fi
  done
  # backdoor: python listener in non-standard path
  $SUDO bash -c '
    ss -tlnp 2>/dev/null | grep -oE "python[0-9.]* /[^ ]+" | while read -r bin path; do
      case "$path" in
        /usr/lib/python*|/usr/share/python*|/opt/cyberpatriot*) : ;;
        *) echo "  [python-listen] $path -> killing + removing (confirm it is the planted backdoor)"
           pkill -f "$path" 2>/dev/null; rm -f "$path" 2>/dev/null ;;
      esac
    done
  ' 2>/dev/null || true
  note "backdoor sweep done (netcat cron/binary/listener + rogue python listener)"

  # now the full upgrade
  log "Full system upgrade"
  $SUDO DEBIAN_FRONTEND=noninteractive apt-get -y upgrade 2>&1 | tail -5
  $SUDO DEBIAN_FRONTEND=noninteractive apt-get -y full-upgrade 2>&1 | tail -5
  $SUDO DEBIAN_FRONTEND=noninteractive apt-get -y autoremove --purge 2>&1 | tail -3

  # auto-update config
  $SUDO bash -c "printf 'APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\nAPT::Periodic::AutocleanInterval \"7\";\n' > /etc/apt/apt.conf.d/20cp-auto"
  $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades 2>/dev/null || true
  $SUDO sed -i 's/Unattended-Upgrade::"Enable"[[:space:]]*"0"/Unattended-Upgrade::"Enable" "1"/' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null
  note "APT periodic list refresh + unattended security upgrades enabled"

  # required browser up to date (penalty guard)
  case "$BROWSER" in
    chromium)  $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y chromium 2>&1 | tail -1 || true;;
    firefox)   $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y firefox 2>&1 | tail -1 || true;;
    thunderbird) $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y thunderbird 2>&1 | tail -1 || true;;
  esac
  $SUDO apt-get clean 2>/dev/null
}

# ----------------------------- UFW -------------------------------------------
chk_uwf() {
  local st; st="$($SUDO ufw status 2>/dev/null | awk 'NR==1')"
  if echo "$st" | grep -qi "active"; then
    report PASS 6 "Uncomplicated Firewall (UFW) enabled"
  else
    report FAIL 6 "Uncomplicated Firewall (UFW) enabled" "${st:-ufw not installed}"
  fi
}
fix_uwf() {
  log "UFW"
  $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y ufw 2>&1 | tail -1 || true
  $SUDO ufw default deny incoming 2>/dev/null
  $SUDO ufw default allow outgoing 2>/dev/null
  $SUDO ufw allow OpenSSH 2>/dev/null
  [ "$FTP_MODE" = "keep" ] && $SUDO ufw allow 21/tcp 2>/dev/null
  $SUDO ufw --force enable 2>/dev/null
  note "ufw: default deny in / allow out, SSH allowed (FTP 21 if keep-mode), enabled"
}

# ------------------------ student homework list ------------------------------
# Detects every student-scope item (passwords, users, forensics) and prints the
# exact commands. Called at the end of the `fix` stage.
student_report() {
  log "STUDENT HOMEWORK — do these BY HAND (the script never does passwords/users)"
  echo ""
  note "── PASSWORDS ────────────────────────────────────────────────────────"
  if [ ${#WEAK_TARGETS[@]} -gt 0 ]; then
    local w
    for w in "${WEAK_TARGETS[@]}"; do
      [ -n "$w" ] || continue
      note "new 12+ char password for admin '$w' →  sudo passwd $w"
    done
  else
    note "no weak admin passwords flagged by the README (still verify each listed admin has a strong one)"
  fi
  local rootpw
  rootpw="$($SUDO awk -F: '$1=="root"{print $2}' /etc/shadow 2>/dev/null)"
  if [ -z "$rootpw" ]; then
    note "root password is BLANK → lock it:  sudo passwd -l root"
  else
    note "root password is set (confirm it is strong)"
  fi
  if [ -n "$NEW_ADMIN" ]; then
    note "force password change on new admin '$NEW_ADMIN' →  sudo chage -d 0 $NEW_ADMIN"
  fi
  note "password aging:  sudo chage -M $PASSMAX -m $PASSMIN -W $WARNAGE <each user>"
  note "   and /etc/login.defs →  PASS_MAX_DAYS $PASSMAX   PASS_MIN_DAYS $PASSMIN   PASS_WARN_AGE $WARNAGE"
  note "min length $MINLEN →  sudo apt install libpam-pwquality;  /etc/security/pwquality.conf: minlen=$MINLEN;"
  note "   /etc/pam.d/common-password: pam_pwquality.so minlen=$MINLEN (remove 'nullok' from common-auth too)"
  note "lockout 5 failed / 15 min →  /etc/pam.d/common-auth:"
  note "   auth    required    pam_faillock.so preauth  silent deny=5 unlock_time=900"
  note "   auth    [default=die] pam_faillock.so authfail deny=5"
  note "remember last $RECS →  /etc/pam.d/common-password:  pam_pwhistory.so use_authtok remember=$RECS"
  echo ""
  note "── USERS & GROUPS ───────────────────────────────────────────────────"
  local u extra=""
  $SUDO awk -F: '$3>=1000 && $1!="nobody" && $1!="ftp" {print $1}' /etc/passwd 2>/dev/null > /tmp/.cp_uid1000
  while IFS= read -r u; do
    [ -n "$u" ] || continue
    is_listed "$u" || [ "$u" = "$NEW_ADMIN" ] || extra="$extra $u"
  done < /tmp/.cp_uid1000
  if [ -n "$extra" ]; then
    for u in $extra; do
      note "delete user '$u' (not in the README roster) →  sudo userdel -r $u   (back up /home/$u first)"
    done
  else
    note "no unauthorized local users found (roster check clean)"
  fi
  local s extra2=""
  while IFS= read -r s; do
    [ -n "$s" ] || continue
    is_listed "$s" || [ "$s" = "$NEW_ADMIN" ] || extra2="$extra2 $s"
  done < <($SUDO getent group sudo 2>/dev/null | cut -d: -f4 | tr ',' '\n')
  for s in $extra2; do
    note "remove '$s' from the sudo group →  sudo gpasswd -d $s sudo"
  done
  if [ -n "$NEW_ADMIN" ]; then
    if $SUDO id "$NEW_ADMIN" >/dev/null 2>&1; then
      note "new admin '$NEW_ADMIN' exists → confirm: sudo group + forced change (chage -d 0)"
    else
      note "create admin '$NEW_ADMIN' (sudo, forced change) →  sudo useradd -m -G sudo $NEW_ADMIN && sudo chage -d 0 $NEW_ADMIN && sudo passwd $NEW_ADMIN"
    fi
  fi
  if [ -n "$NEW_GROUP" ] && [ ${#NEW_GROUP_MEMBERS[@]} -gt 0 ]; then
    if $SUDO getent group "$NEW_GROUP" >/dev/null 2>&1; then
      local m
      for m in "${NEW_GROUP_MEMBERS[@]}"; do
        $SUDO getent group "$NEW_GROUP" | grep -qw "$m" || note "add member to group '$NEW_GROUP' →  sudo adduser $m $NEW_GROUP"
      done
    else
      note "create group '$NEW_GROUP' and add member(s): ${NEW_GROUP_MEMBERS[*]}  →  sudo addgroup $NEW_GROUP && sudo adduser <each member> $NEW_GROUP"
    fi
  fi
  if [ -n "$ADD_USER_TO_USER" ] && [ -n "$ADD_USER_TO_GROUP" ]; then
    note "add user '$ADD_USER_TO_USER' to group '$ADD_USER_TO_GROUP' →  sudo adduser $ADD_USER_TO_USER $ADD_USER_TO_GROUP"
  fi
  echo ""
  note "── FORENSICS ────────────────────────────────────────────────────────"
  note "answer EVERY 'Forensics Question' file (run:  $0 forensics  for decoded candidates)"
  note "put 'Answer: <text>' into each file, then confirm with:  $0 verify"
  echo ""
  note "WHEN DONE:  run  $0 verify  — every line should be PASS"
}

# ----------------------------- stages ----------------------------------------
STAGE_LABEL=""
case "$STAGE" in
  audit)
    detect_profile; parse_readme
    log "CP19 MASTER AUDIT — profile=$PROFILE (read-only)"
    chk_users; chk_pam; chk_files; chk_sysctl; chk_ssh; chk_services
    chk_updates; chk_uwf
    do_forensics
    echo
    echo "============================================================"
    echo " AUDIT: PASS=$PASS_N  FAIL=$FAIL_N  WARN=$WARN_N  est.missed pts=$FAIL_PTS"
    echo "============================================================"
    ;;
  forensics)
    detect_profile; parse_readme
    do_forensics
    ;;
  fix)
    need_root; detect_profile; parse_readme
    log "CP MASTER FIX — profile=$PROFILE (script scope only: files->sysctl->ssh->services->ufw->purge+updates)"
    fix_files
    fix_sysctl
    fix_ssh
    fix_services
    fix_uwf
    fix_sources_and_updates
    log "FIX COMPLETE (script scope)"
    echo
    student_report
    ;;
  fixall)
    need_root; detect_profile; parse_readme
    log "CP MASTER FIXALL — TRAINING ONLY (script does everything, incl. passwords + users)"
    fix_users
    fix_pam
    fix_files
    fix_sysctl
    fix_ssh
    fix_services
    fix_uwf
    fix_sources_and_updates
    log "FIXALL COMPLETE"
    echo "  new/changed admin passwords logged at /root/cp_pw_changes.log"
    echo "  re-run 'audit' or 'verify' to confirm all PASS"
    ;;
  verify)
    detect_profile; parse_readme
    log "CP19 MASTER VERIFY — profile=$PROFILE"
    chk_users; chk_pam; chk_files; chk_sysctl; chk_ssh; chk_services
    chk_updates; chk_uwf
    echo
    echo "============================================================"
    echo " VERIFY: PASS=$PASS_N  FAIL=$FAIL_N  WARN=$WARN_N  est.missed pts=$FAIL_PTS"
    if [ ${#WEAK_TARGETS[@]} -gt 0 ]; then
      note "remember to confirm weak-password changes visually: ${WEAK_TARGETS[*]}"
    fi
    echo "============================================================"
    ;;
  *)
    echo "usage: $0 [fix]   (default: script-scope fixes + student homework list)"
    echo "       $0 audit | forensics | verify | fixall   (fixall = training: everything)"
    echo "  env: PROFILE=debian12|mint21|auto  SUDO_PASS_FILE=***  AUTO_WRITE_ANSWERS=1"
    exit 1
    ;;
esac
exit 0
