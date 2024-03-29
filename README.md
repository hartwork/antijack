[![Build and on Linux](https://github.com/hartwork/antijack/actions/workflows/linux.yml/badge.svg)](https://github.com/hartwork/antijack/actions/workflows/linux.yml)
[![Enforce clang-format](https://github.com/hartwork/antijack/actions/workflows/clang-format.yml/badge.svg)](https://github.com/hartwork/antijack/actions/workflows/clang-format.yml)


# What is antijack?

**antijack** was inspired by [ttyjack](https://github.com/jwilk/ttyjack)
and is its counterpart in some sense, hence the name.

**antijack**'s mission is threefold:

- demo execution of a program in a way where it *cannot* inject
  commands via ioctls `TIOCSTI` and/or `TIOCLINUX`
  into the surrounding controlling terminal,
  e.g. try `antijack ttyjack echo nope`.
- generate and dump a seccomp syscall filter (a BPF program)
  that blocks ioctls `TIOCSTI` and `TIOCLINUX`
  into a file for use with
  e.g. [bubblewrap](https://github.com/containers/bubblewrap)
  a la `bwrap --seccomp 3 [..] 3< <(antijack --dump /dev/stdout)`.
- demo mitigation at syscall level for Linux leveraging
  [libseccomp](https://github.com/seccomp/libseccomp).
  **May not be enough!**, more on that below.

It should be noted that:

- Alternative options for mitigation include:
  - `setsid(2)` (or `setsid(1)`) with drawbacks or
  - use of a PTY.
- With security in mind, we need to ask
  "why should access to the controlling terminal be granted?"
  not "why should it be taken away?"
  Use of a PTY by default is a consequence of that.
  The fact that `TIOCLINUX` attacks came to awareness later than `TIOCSTI`
  indicates that when the next attack like these will be discovered,
  those who are blocking single ioctls will have to adjust while
  those using a PTY may already by protected.
- The defaults for `su` and `sudo` are known-vulnerable as of 2023-03-16.
  - For `su` it takes `--pty`.
  - For `sudo` it takes `Defaults use_pty` in `/etc/sudoers`.
- Both util-linux and GNU coreutils have reverted their
  use of [libseccomp](https://github.com/seccomp/libseccomp) for mitigation:
  - https://github.com/util-linux/util-linux/commit/23f75093264aae5d58d61016cb1a29d8ebdfa157
  - https://github.com/coreutils/coreutils/commit/f5d7c0842ef7adc2be6e85f9ef66b35ebbbd6a61
- The syscall filter is easy to mis-implement,
  e.g. see [CVE-2019-10063](https://nvd.nist.gov/vuln/detail/CVE-2019-10063)
  and/or
  [commit 5f6bd3aa6e6a15f644923afa66fb0068736e2b8d](https://github.com/hartwork/antijack/commit/5f6bd3aa6e6a15f644923afa66fb0068736e2b8d).


# Requirements

- C99 compiler
- Linux build and target host
- glibc ≥ 2.32
- GNU make
- [libseccomp](https://github.com/seccomp/libseccomp)


# How to compile

```
$ make
```


# Example output (on `x86_64`)

```
$ antijack --help
usage: antijack [-v|--verbose] [-o|--dump PATH.bpf] [--] [COMMAND [ARG ..]]
   or: antijack -h|--help

$ antijack -v -- ttyjack echo nope
[*] Initializing libseccomp...
[+]   Done.
[*] Adding rule block TIOCSTI ioctls...
[+]   Done.
[*] Adding rule block TIOCLINUX ioctls...
[+]   Done.
[*] Loading seccomp rules into the kernel...
#
# pseudo filter code start
#
# filter for arch x86_64 (3221225534)
if ($arch == 3221225534)
  # filter for syscall "ioctl" (16) [priority: 65532]
  if ($syscall == 16)
    if ($a1.hi32 & 0x00000000 == 0)
      if ($a1.lo32 & 0xffffffff == 21532)
        action KILL_PROCESS;
      if ($a1.lo32 & 0xffffffff == 21522)
        action KILL_PROCESS;
  # default action
  action ALLOW;
# invalid architecture action
action KILL;
#
# pseudo filter code end
#
[+]   Done.
[*] Releasing libseccomp...
[+]   Done.
[*] Running ttyjack...
Bad system call

$ antijack --dump filter.bpf

$ wc -c < filter.bpf
112
```


# Related CVEs (not mine)

- [CVE-2005-4890](https://nvd.nist.gov/vuln/detail/CVE-2005-4890) for `su` of util-linux and `sudo`
- [CVE-2006-7098](https://nvd.nist.gov/vuln/detail/CVE-2006-7098) for Apache
- [CVE-2007-1400](https://nvd.nist.gov/vuln/detail/CVE-2007-1400) for [plash](https://github.com/mseaborn/plash)
- [CVE-2011-1408](https://nvd.nist.gov/vuln/detail/CVE-2011-1408) for `ikiwiki-mass-rebuild` of ikiwiki
- [CVE-2013-6409](https://nvd.nist.gov/vuln/detail/CVE-2013-6409) for [adequate](https://packages.debian.org/sid/adequate)
- [CVE-2016-2568](https://nvd.nist.gov/vuln/detail/CVE-2016-2568) for `pkexec` of Polkit
- [CVE-2016-2779](https://nvd.nist.gov/vuln/detail/CVE-2016-2779) for `runuser` of util-linux
- [CVE-2016-2781](https://nvd.nist.gov/vuln/detail/CVE-2016-2781) for `chroot` of GNU Coreutils
- [CVE-2016-7545](https://nvd.nist.gov/vuln/detail/CVE-2016-7545) for `policycoreutils` of SELinux
- [CVE-2016-9016](https://nvd.nist.gov/vuln/detail/CVE-2016-9016) for Firejail
- [CVE-2016-10124](https://nvd.nist.gov/vuln/detail/CVE-2016-10124) for `lxc-attach` of LXC
- [CVE-2016-?????](https://debbugs.gnu.org/cgi/bugreport.cgi?bug=24541) for `runcon` of GNU Coreutils
- [CVE-2017-5226](https://nvd.nist.gov/vuln/detail/CVE-2017-5226) for bubblewrap (or Flatpak)
- [CVE-2019-7303](https://nvd.nist.gov/vuln/detail/CVE-2019-7303) for `snapd` of Snap
- [CVE-2019-10063](https://nvd.nist.gov/vuln/detail/CVE-2019-10063) for Flatpak
- [CVE-2019-11460](https://nvd.nist.gov/vuln/detail/CVE-2019-11460) for `gnome-desktop` of GNOME
- [CVE-2019-11461](https://nvd.nist.gov/vuln/detail/CVE-2019-11461) for Nautilus of GNOME
- [CVE-2020-13753](https://nvd.nist.gov/vuln/detail/CVE-2020-13753) for WebKitGTK
- [CVE-2021-?????](https://hackerone.com/reports/1283871) for Homebrew
- [CVE-2023-28100](https://nvd.nist.gov/vuln/detail/CVE-2023-28100) for Flatpak
- [CVE-2023-28339](https://nvd.nist.gov/vuln/detail/CVE-2023-28339) for OpenDoas
- [CVE-2023-?????](https://github.com/slicer69/doas/issues/110) for doas (except on OpenBSD >=6.2)
- [CVE-2023-46277](https://nvd.nist.gov/vuln/detail/CVE-2023-46277) for pleaser/please
- [CVE-2023-?????](https://github.com/illiliti/ssu/issues/13) for ssu
- [CVE-2023-?????](https://github.com/memorysafety/sudo-rs/issues/159) for sudo-rs

---
[Sebastian Pipping](https://github.com/hartwork), Berlin, 2023
