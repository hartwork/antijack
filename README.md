# What is antijack?

**antijack** was inspired by [ttyjack](https://github.com/jwilk/ttyjack)
and is its counterpart in some sense, hence the name.

**antijack**'s mission is threefold:

- allow execution of a program in a way where it *cannot* inject
  commands via ioctls `TIOCSTI` and/or `TIOCLINUX`
  into the surrounding controlling terminal,
  e.g. try `antijack ttyjack echo nope`.
- generate and dump a seccomp syscall filter (a BPF program)
  that blocks ioctls `TIOCSTI` and `TIOCLINUX`
  into a file for use with
  e.g. [bubblewrap](https://github.com/containers/bubblewrap)
  a la `bwrap --seccomp 3 [..] 3< <(antijack --dump /dev/stdout)`.
- demo mitigation at syscall level for Linux leveraging libseccomp.
  **May not be enough!**


# Requirements

- C99 compiler
- Linux build and target host
- glibc ≥ 2.32
- [libseccomp](https://github.com/seccomp/libseccomp)


# How to compile

```console
# make
```


# Related CVEs (not mine)

- [CVE-2005-4890](https://nvd.nist.gov/vuln/detail/CVE-2005-4890) for `su` of GNU coreutils and `sudo`
- [CVE-2016-2568](https://nvd.nist.gov/vuln/detail/CVE-2016-2568) for `pkexec` of Polkit
- [CVE-2016-2779](https://nvd.nist.gov/vuln/detail/CVE-2016-2779) for `runuser` of util-linux
- [CVE-2017-5226](https://nvd.nist.gov/vuln/detail/CVE-2017-5226) for bubblewrap/flatpak
