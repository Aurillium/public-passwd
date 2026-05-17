> [!WARNING]
> Only use this on systems you own or have authorisation to test. It is recommended to keep a root shell open if you won't be able to reboot the system in case of failure, as you may not be able to clear the page cache for `/etc/shadow` without root. 

# public-passwd
Use CVE-2026-46333 and CVE-2026-31431 to change any user's password without ever escalating to root.

## Usage
```sh
python passwd.py <username>
```
You can also run the command without arguments to see hashes currently in the shadow file.

## Screenshots
<img width="782" height="195" alt="image" src="https://github.com/user-attachments/assets/d8881378-4e3d-4cda-a00c-d99cc1a2f15c" />
<img width="842" height="394" alt="image" src="https://github.com/user-attachments/assets/24a5d99f-7139-483a-b837-cc5fda570381" />

## How does it work

CopyFail (CVE-2026-31431) and similar vulnerabilities allow for writing 4 bytes to any file on the OS that you can read from. This generally means that you can't modify files you can't read, like PAM rules or the shadow file. You can use CopyFail to escalate to root and change whatever file you like after that (there's plenty of PoCs for this including my own [RootRemover](https://github.com/Aurillium/RootRemover)), but what if we want to modify other files without escalating?

CopyFail only needs a file descriptor to work. Most PoCs open a file and use that FD, however we can get it from anywhere else. Enter CVE-2026-46333.

CVE-2026-46333 is capable of stealing a file descriptor to root-readable files from `chage` or `ssh-keysign`. Since we want `/etc/shadow` so we can modify passwords, we focus on `chage`. `pidfd_getfd` is used to steal the file descriptor for `/etc/shadow` because there is a point during its execution that the UID is set to the user who executed it (allowing `pidfd_getfd`), but having an SUID bit, it was able to open `/etc/shadow` as root before lowering to our user. 

This FD is in `O_RDONLY`, meaning read-only, however because we have CopyFail this doesn't matter, we can escalate to writing. We can just pass the FD along to CopyFail and use the exploit like any other readable file.

## Important Notes
- This does fail if your user is too close to the end of /etc/shadow.
- The user's existing salt is reused for the new password, if you're actually using this as a recovery tool (why?), you'll want to change the password again using `passwd`.
- The new password will be removed on reboot, again setting it with `passwd` once you actually have a known password fixes this.
- Only works on systems vulnerable to CVE-2026-46333 and CVE-2026-31431.
