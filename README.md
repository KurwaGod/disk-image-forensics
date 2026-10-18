# disk image forensics - collecting evidence without breaking it

notes and scripts for pulling evidence out of a linux disk image in a way
that holds up. written after working the xp cyber range challenge
"analyzing attack artifacts", but the method is general - it works on any
ext2/3/4 image you need to collect from.

the short version: never mount the image, pull files out by inode, hash
everything twice, and collect what is actually evidence rather than whatever
fills the quota.

## why not just mount it

mounting is the obvious move and it is the one that will cost you.

most images taken off a live or crashed machine have a dirty journal.
`fsstat` will say `Unmounted Improperly`. when you mount an ext3/ext4
filesystem in that state the kernel **replays the journal**, and replaying
writes to the image. the hash changes. if anyone is comparing that hash
against the one taken at acquisition, you have just failed.

plain `-o ro` does not stop this. you need `noload` as well.

the better answer is to not mount at all. every sleuth kit tool below reads
the image directly and never writes to it.

if you truly have to mount:

```
sudo losetup -r -f --show var.img
sudo mount -o ro,noload,noexec,nodev,nosuid /dev/loop0 /mnt/point
```

## the method

### 1. hash it before you touch it

```
sha256sum var.img
```

this is the number everything else is measured against. write it down.

### 2. make it physically unwritable

```
sudo chattr +i var.img
lsattr var.img
```

the immutable flag means even root cannot write to, rename, or delete the
file. a mistyped redirect fails with "operation not permitted" instead of
silently destroying your evidence. it bumps ctime but changes zero bytes, so
the hash is unaffected.

clear it with `chattr -i` when you are done.

### 3. identify the filesystem

```
fsstat var.img | head -20
```

gives you the type, the volume id, and the last written / last mounted /
last checked timestamps. those belong in your notes.

compare `Last Written` against the timestamp on the final log entry you
find later. a big gap means log data is missing.

### 4. list the files without mounting

```
fls -rp var.img > all.txt
```

`-r` is recursive, `-p` prints full paths.

**use `-p`.** without it you get indentation instead of paths, every grep
for a path fragment silently returns nothing, and it looks like the files
do not exist. this wastes more time than anything else on this list.

### 5. pull files out by inode

```
icat var.img 9815 > access_log
```

`icat` streams the inode's data blocks straight out of the image. no mount,
no atime updates, no chance of the host filesystem touching anything.

### 6. verify every extraction

```
icat var.img 9815 | sha256sum
sha256sum access_log
```

two identical hashes is your proof the extraction was sound. this also
catches the easy mistake of extracting the same inode twice under two
different names, which leaves you with two identical files and a failed
check.

### 7. recover what was deleted

try the clean route first:

```
fls -rpd var.img | grep -v realloc | grep -v "\* 0:"
```

anything left is recoverable byte for byte with `icat`. the two you are
filtering out:

- `* 0:` - the metadata is gone, there is nothing to recover
- `(realloc)` - the inode now belongs to a different file, `icat` will hand
  you the wrong data

if that comes back empty, carve instead:

```
blkls var.img > unalloc.dd
strings unalloc.dd | grep -wF <ip> > recovered
```

`blkls` pulls only the unallocated blocks. deleted content lives there until
something overwrites it.

a useful trick for finding what was deleted: collect every ip in the
surviving log, then look for ips in the carved data that are **not** in that
set. those belonged to entries somebody removed.

note that carving with `strings` gives you a reconstruction, not a byte
exact copy - it drops non printable bytes, and the original inode is gone so
there is nothing to hash against. say so in your writeup.

### 8. verify the image again

```
sudo chattr -i var.img
sha256sum var.img
```

must match step 1.

## gotchas

things that cost real time:

**relevance beats count.** if you are told "no more than five files", that
is a ceiling, not a target. we submitted five including `/var/log/messages`
and the check stayed red. four files without it passed. `messages` was
thousands of lines of kernel boot noise that ended before the attack even
started. collect evidence, not filler.

**automated checks lag.** state can take a minute or two to re-evaluate.
reading a stale red as "that change did not work" and then undoing a change
that had actually worked is a great way to go in circles. make one change,
wait, then read.

**check for duplicate extractions.** two different logs with byte identical
sizes is the tell. `cmp a b` printing nothing means they are the same file.

**there can be more than one directory with the same name.** on centos there
is `/var/log/httpd` (the logs) and `/var/cache/httpd` (the mod_proxy cache).
listing the wrong one shows a single `proxy` entry and makes it look like
the logs were wiped.

**do not work as root.** `sudo su` makes `~` expand to `/root`, so your
redirects land somewhere you are not looking and your files come out root
owned. everything here works unprivileged except `chattr`.

**keep scratch files off the desktop.** carving tools can emit thousands of
files. carve somewhere else and copy in only the finding.

**binary logs need a tool, not `cat`.** `wtmp` and `btmp` hold login
records. `last -f wtmp` reads them, but `last` is not always installed and a
locked down range may have no working package mirror. `strings wtmp` gets
you the usernames, terminals and source ips without installing anything.

**collection is not attribution.** if the task says "identify, collect, and
seize", then reconstructing the full intrusion timeline is the next
analyst's job, not yours. it is easy to burn an hour building a narrative
nobody asked for.

## files

| file | what it is |
| --- | --- |
| `analyze_artifacts_walkthrough.sh` | guided version - runs in stages, stops between them so you read the output and make the calls yourself |
| `solver/` | automated version, see the note in there first |

both were tested end to end against a purpose built ext4 image.

## requirements

```
sudo apt install sleuthkit
```

everything else (`sha256sum`, `strings`, `grep`, `awk`, `chattr`) is already
on any linux box.

## license

mit - see [LICENSE](LICENSE).

these scripts run `sudo chattr` and operate on evidence files. the warranty
disclaimer is not decoration. read what they do before pointing them at
anything you care about.
