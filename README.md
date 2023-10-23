# wd-passport
Linux equivalent of the WD Passport utility for disk encryption

I wanted a linux standalone executable to unlock WD Passport drives so I wrote this in C
with no binary dependencies (other than libc and libbsd).
Files in the 'lib' directory are stripped down versions from the sg-utils and lsscsi programs.

This utility is only useful if you plan to use your WD Passport disk on both linux and windows.
The security of the drive encryption is not that great: 
see https://eprint.iacr.org/2015/1002.pdf
"On the (in)security of a Self-Encrypting Drive series"
linux provides much better disk encryption solutions.

If you still plan to use this make sure you set then change the password once otherwise
the factory key can still be used to decrypt your data.

One feature that is missing is locking the disk from software.
Once the disk is unlocked you cannot lock it back, only re-plugging the disk works.
Changing the encryption password or sending a SCSI reset command still leaves the disk unlocked.

For me this is a flaw because if the disk is on a remote machine the data remains available
once you have unlocked it.
