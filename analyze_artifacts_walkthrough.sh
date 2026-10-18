#!/usr/bin/env bash
#
# XP Cyber Range — "Analyzing Attack Artifacts" guided walkthrough
# DCWF Cyber Crime Investigator (task 649) / NICE T1207
#
# Runs in stages and stops between them so you can read the output and
# decide what matters. Inode numbers are image-specific, so this discovers
# them rather than hardcoding; reference values from the Oct-2022 CentOS
# image are noted in comments as a sanity check.
#
# The protocol comes from the in-challenge meeting notes, not from general
# best practice. For this challenge: image hash unchanged and left on the
# Desktop, evidence in ~/Desktop/evidence with no subdirectories, five files
# maximum, recovered data in a file named exactly 'recovered'.

set -uo pipefail

IMG="$HOME/Desktop/var.img"
EVIDENCE="$HOME/Desktop/evidence"
WORK="/tmp/artifacts-work"   # scratch, deliberately off the Desktop

pause()  { echo; read -r -p ">>> $1 [Enter] "; echo; }
banner() { echo; echo "========================================"; echo "  $1"; echo "========================================"; }

# ---------------------------------------------------------------------------
banner "STAGE 0: Preserve"
# ---------------------------------------------------------------------------

[[ -f "$IMG" ]] || { echo "No image at $IMG"; exit 1; }
mkdir -p "$WORK" "$EVIDENCE"

BASELINE=$(sha256sum "$IMG" | awk '{print $1}')
echo "Baseline SHA-256: $BASELINE"

# Immutable flag: even root can't write to or delete the file. A typo'd
# redirect fails instead of destroying evidence. Changes ctime, not content.
sudo chattr +i "$IMG" 2>/dev/null || echo "warn: chattr failed"
lsattr "$IMG"

pause "Image locked. Next: filesystem triage."

# ---------------------------------------------------------------------------
banner "STAGE 1: Filesystem metadata"
# ---------------------------------------------------------------------------

# Never mount. This image is "Unmounted Improperly" — a dirty ext4 journal.
# Mounting replays it, which writes to the image and breaks the hash.
# If you must mount: losetup -r, then mount -o ro,noload,noexec,nodev,nosuid
fsstat "$IMG" > "$WORK/fsstat.txt" 2>&1
head -20 "$WORK/fsstat.txt"

echo
echo "Compare Last Written against the final log entry. A large gap means"
echo "log data is missing — that's your cue for Stage 4."

pause "Building file listing."

# ---------------------------------------------------------------------------
banner "STAGE 2: Enumerate"
# ---------------------------------------------------------------------------

# -p prints full paths. Without it you get indentation and every path grep
# silently returns nothing — the single biggest time sink in this challenge.
fls -rp "$IMG" > "$WORK/all_files.txt" 2>/dev/null
echo "Entries: $(wc -l < "$WORK/all_files.txt")"

# Match "log/httpd/", not bare "httpd" — cache/httpd also exists (mod_proxy
# cache) and listing it by mistake shows one "proxy" entry, which looks like
# the logs were wiped.
if grep -q "log/httpd/" "$WORK/all_files.txt"; then
    LOGDIR="log/httpd"; ACC="access_log"; ERR="error_log"; AUTH="log/secure"
    echo "CentOS/RHEL host"
else
    LOGDIR="log/apache2"; ACC="access.log"; ERR="error.log"; AUTH="log/auth.log"
    echo "Debian/Ubuntu host"
fi

echo "WordPress files present: $(grep -c "www/html/wp-" "$WORK/all_files.txt")"

pause "Extracting logs."

# ---------------------------------------------------------------------------
banner "STAGE 3: Extract by inode"
# ---------------------------------------------------------------------------

# fls format: "r/r 9815:   log/httpd/access_log" — field 2 minus the colon.
# Deleted rows are "r/r * 9815:" so skip bare stars, and skip (realloc)
# where the inode now belongs to a different file and icat returns wrong data.
inode_of() {
    grep -E "[[:space:]]${1}\$" "$WORK/all_files.txt" \
        | grep -v "realloc" | grep -v " \* " \
        | head -1 | awk '{print $2}' | tr -d ':'
}

# icat streams data blocks straight from the image — no mount, no atime
# updates. Hash both copies independently; a mismatch means something
# modified the file in transit, and it also catches extracting the same
# inode twice under two names.
extract() {
    local inode dest a b
    inode=$(inode_of "$1"); dest="$2"
    [[ -z "$inode" ]] && { echo "SKIP $dest (not found)"; return 1; }

    icat "$IMG" "$inode" > "$EVIDENCE/$dest" 2>/dev/null
    a=$(icat "$IMG" "$inode" 2>/dev/null | sha256sum | awk '{print $1}')
    b=$(sha256sum "$EVIDENCE/$dest" | awk '{print $1}')

    [[ "$a" == "$b" ]] \
        && printf 'OK   %-12s inode %-6s %s lines\n' "$dest" "$inode" "$(wc -l < "$EVIDENCE/$dest")" \
        || { echo "FAIL $dest hash mismatch"; return 1; }
}

# Reference inodes: access_log 9815, error_log 9816, secure 9819
extract "${LOGDIR}/${ACC}" "access_log"
extract "${LOGDIR}/${ERR}" "error_log"
extract "$AUTH"            "secure"

# NOT collecting log/messages (inode 9818). It's kernel boot noise that ends
# before the attack; including it fails the protocol check.

echo; echo "access_log and error_log should differ in size:"; ls -l "$EVIDENCE"

pause "Reading the logs."

# ---------------------------------------------------------------------------
banner "STAGE 3b: What the logs show"
# ---------------------------------------------------------------------------

echo "--- Source IPs ---"
awk '{print $1}' "$EVIDENCE/access_log" | sort | uniq -c | sort -rn | head

echo; echo "--- Methods ---"
awk '{print $6}' "$EVIDENCE/access_log" | tr -d '"' | sort | uniq -c | sort -rn

echo; echo "--- POST response sizes ---"
# In an xmlrpc brute force every failed login returns an identically sized
# XML error. A different size is the attempt that behaved differently.
# Reference image: 403 bytes x27 plus a single 645 in the LIVE log. (The
# 4272 outlier lives in the deleted log, so it only shows up in Stage 4.)
grep POST "$EVIDENCE/access_log" | awk '{print $10}' | sort | uniq -c | sort -rn

echo; echo "--- Outliers (the interesting ones) ---"
grep POST "$EVIDENCE/access_log" | awk '{print $10}' \
    | sort | uniq -c | sort -n \
    | awk '$1 <= 2 {print "  " $2 " bytes, seen " $1 "x"}'

pause "Hunting for deleted data."

# ---------------------------------------------------------------------------
banner "STAGE 4: Recover (objective 2)"
# ---------------------------------------------------------------------------

# Clean route first: a deleted inode that still holds its block pointers
# recovers byte-for-byte with icat, which beats carving.
#   "* 0:"      metadata gone, unrecoverable
#   "(realloc)" inode reused, icat returns the wrong file
echo "--- Cleanly recoverable deleted entries ---"
fls -rpd "$IMG" 2>/dev/null | grep -v "realloc" | grep -v "\* 0:" | head -20
echo "(empty = nothing clean, fall through to carving)"

# blkls extracts only unallocated blocks, where deleted content survives
# until overwritten.
blkls "$IMG" > "$WORK/unalloc.dd" 2>/dev/null
echo; echo "Unallocated: $(du -h "$WORK/unalloc.dd" | cut -f1)"

# Every IP in the surviving log, source or referer. Anything in the carved
# data that isn't in this set belonged to entries someone deleted.
LIVE=$(grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$EVIDENCE/access_log" | sort -u)

echo; echo "--- Hosts in carved data but not in the live log ---"
# -w so a live 172.31.2.19 doesn't filter out a carved 172.31.2.195,
# -f reads the live list as separate patterns (a piped "a|b" string would
# be matched literally by -F and filter nothing)
strings "$WORK/unalloc.dd" \
    | grep -E '"(GET|POST|HEAD) |\[client ' \
    | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
    | sort | uniq -c | sort -rn \
    | awk '{printf "  %-18s %s hits\n", $2, $1}' \
    | grep -vwFf <(printf '%s\n' "$LIVE") || echo "  (none — all carved hosts appear in the live log)"

echo
echo "Pick the host above, then:"
echo "  strings $WORK/unalloc.dd | grep -wF <IP> > $EVIDENCE/recovered"
echo
echo "Filename must be exactly 'recovered'. On the reference image this gave"
echo "200 lines from 172.31.2.195, including probes for searchreplacedb2.php"
echo "and emergency.php plus a PHP fatal error from rss-functions.php."
echo
echo "Note for the writeup: this is a reconstruction, not a byte-exact"
echo "extraction — strings drops non-printable bytes and the original inode"
echo "is gone, so there's nothing to hash against."

pause "Final verification."

# ---------------------------------------------------------------------------
banner "STAGE 5: Verify"
# ---------------------------------------------------------------------------

sudo chattr -i "$IMG" 2>/dev/null

FINAL=$(sha256sum "$IMG" | awk '{print $1}')
echo "Baseline: $BASELINE"
echo "Final:    $FINAL"
[[ "$BASELINE" == "$FINAL" ]] && echo "MATCH — unaltered" || echo "MISMATCH — objective 1 will fail"

echo; echo "Evidence ($(ls -1 "$EVIDENCE" | wc -l) files, limit 5):"; ls -l "$EVIDENCE"
echo; echo "Expected final count is 4, once you write 'recovered' above."
echo "Scratch is in $WORK, off the Desktop. The Desktop should hold only"
echo "var.img and evidence/ when you submit."

cat <<'NOTES'

========================================
GOTCHAS
========================================

1. RELEVANCE BEATS COUNT. The protocol says "no more than five files". Five
   including /var/log/messages failed; four without it passed. messages was
   5,805 lines of boot noise ending before the attack. Collect evidence, not
   filler.

2. THE CHECKS LAG. State takes a minute or two to re-evaluate. Reading a
   stale red as "that didn't work" and undoing a change that HAD worked
   costs more time than anything else here. One change, wait, then read.

3. fls WITHOUT -p gives indentation, not paths. Path greps return nothing
   and it looks like the file doesn't exist.

4. (realloc) means the inode was reused — icat returns the current owner's
   data, not the deleted file.

5. CHECK FOR DUPLICATE EXTRACTIONS. Two logs with byte-identical sizes is
   the tell. `cmp a b` printing nothing means they're identical.

6. DON'T WORK AS ROOT. `sudo su` makes ~ expand to /root, so redirects land
   where you aren't looking and files come out root-owned. Everything here
   works unprivileged except chattr.

7. SCRATCH STAYS OUT OF evidence/. foremost and photorec can emit thousands
   of files. Carve elsewhere, copy in only the finding.

8. COLLECTION IS NOT ATTRIBUTION. The work role is "identify, collect, and
   seize". Timeline reconstruction belongs to the analyst downstream.

9. wtmp AND btmp ARE A DEAD END HERE. Worth five seconds to check, but this
   intrusion was entirely over HTTP — wtmp showed only local tty1 console
   logins. `last` may not even be installed, and the range has no working
   apt mirror. `strings wtmp` tells you what you need without installing.

10. /var/log/messages AND /var/log/secure END AT THE LAST BOOT, weeks before
   the filesystem's Last Written date. That gap is the signal to go carving;
   it is not by itself proof the logs were tampered with.

========================================
TOOLS (for the documentation tab)
========================================
The Sleuth Kit: fls, icat, fsstat, blkls
coreutils: sha256sum, strings, grep, awk, cmp, wc
e2fsprogs: chattr, lsattr
NOTES
