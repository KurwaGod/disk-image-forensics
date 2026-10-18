# disk image forensics

# analyzing artifacts guide 
made this because of how bad i am at digital forensics and to save
others the time i wasted 

notes from pulling evidence off a linux disk image without wrecking it.
written after an xp cyber range challenge, though none of it is tied to
that. works on any ext2/3/4 image.

chattr is your friend use it!!!

## don't mount it

mounting is the obvious move and it will cost you.

images taken off a crashed or live machine usually have a dirty journal.
`fsstat` will say `Unmounted Improperly`. mount an ext3/ext4 filesystem in
that state and the kernel replays the journal, which writes to the image and
changes the hash. `-o ro` on its own does not stop this. you also need
`noload`.

easier to skip mounting entirely. every sleuth kit tool below reads the
image without writing to it.

## the steps

hash it first. this is the number everything gets measured against.

```
sha256sum var.img
```

lock it so you can't fat-finger a redirect into it. even root can't write to
an immutable file. ctime changes, content doesn't, hash stays the same.

```
sudo chattr +i var.img
```

check what you're looking at. note the last written and last mounted times.

```
fsstat var.img | head -20
```

list the files. use `-p` or you get indentation instead of paths, and every
grep comes back empty for no obvious reason.

```
fls -rp var.img > all.txt
```

pull files out by inode. no mount, no atime changes, nothing touches the
image.

```
icat var.img 9815 > access_log
```

verify each one. two matching hashes is your proof the copy is clean.

```
icat var.img 9815 | sha256sum
sha256sum access_log
```

look for deleted files. skip `* 0:` entries (metadata gone) and `(realloc)`
ones (inode belongs to something else now, icat gives you the wrong file).

```
fls -rpd var.img | grep -v realloc | grep -v "\* 0:"
```

if nothing survives there, carve the free space instead.

```
blkls var.img > unalloc.dd
strings unalloc.dd | grep -wF <ip> > recovered
```

a decent way to spot what someone deleted: list every ip in the surviving
log, then look for ips in the carved data that aren't in it.

unlock and hash again. should match step one.

```
sudo chattr -i var.img
sha256sum var.img
```

## things that cost me time

i submitted five and the check stayed red. four passed. the fifth was
`/var/log/messages`, thousands of lines of boot noise from before the attack.

**automated checks lag.** give them a minute. i undid a change that had
actually worked because the old red was still showing.

**two logs the same size means you extracted the same inode twice.** `cmp a b`
printing nothing confirms it.

**same directory name in two places.** centos has `/var/log/httpd` and
`/var/cache/httpd`. the cache one holds a single `proxy` entry and makes it
look like the logs are gone.

**don't work as root.** `sudo su` makes `~` point at `/root`, so your
redirects land somewhere you aren't looking. only `chattr` needs sudo.

**wtmp and btmp are binary.** `last -f wtmp` reads them, but `last` isn't
always installed and locked-down ranges often have no package mirror.
`strings wtmp` gets you the usernames and ips anyway.

**read the task before building a timeline.** if it says collect evidence,
then working out who did what is somebody else's job. i burned an hour on a
story nobody asked for.

## files

`analyze_artifacts_walkthrough.sh` runs in stages and stops between them so
you read the output yourself.

`solver/` does the whole thing unattended. read the note in there first.

both tested against a purpose-built ext4 image.

## requirements

```
sudo apt install sleuthkit
```

noting the lab itself should have it pre-installed as mentioned in the lab desc

everything else ships with linux.

## NOTE: I solved the lab and had all of my work processed by an agent, where it them simplified it and turned it into a shell script(s) it also helped me build this repo and this readme. I am not a documentation writer, thank god. 

##

if either of the scripts are bugged make a pull request and ill check it 

## license

mit, see [LICENSE](LICENSE).

these scripts run `sudo chattr` and touch evidence files. read them before
pointing them at anything you care about.
