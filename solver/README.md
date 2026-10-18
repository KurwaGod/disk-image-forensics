# about this one

`solve_analyzing_artifacts.sh` runs the whole collection start to finish
with no prompts. it hashes and locks the image, finds the apache and auth
logs, extracts them by inode with hash verification, carves the deleted log
entries out of unallocated space, and leaves a finished evidence folder.

## read this before you use it

this was written against one specific disk image. the choices it makes -
which logs count as evidence, which to leave out, how many files to end up
with - are baked in from knowing that image's answers. point it at a
different image and it will confidently collect the wrong things.

it does not have judgement. deciding what is evidence was the actual hard
part of the exercise, and this script skips it.

if you are working a graded exercise, running this does not teach you
anything, and depending on your institution it may not be allowed. the
guided script in the parent directory walks the same ground and stops at
each decision so you make it yourself. use that one.

this is here because the mechanics are reusable - the hashing, the
immutable flag, the verified `icat` extraction loop, the carve-and-diff
trick for finding deleted hosts. lift those parts into your own tooling.

## usage

```
bash solve_analyzing_artifacts.sh
```

expects the image at `~/Desktop/var.img` and writes to `~/Desktop/evidence`.
change the paths at the top of the file.

scratch goes to `/tmp/artifacts-work` and is safe to delete.
