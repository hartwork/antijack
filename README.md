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
- demo mitigation at syscall level for Linux leveraging
  [libseccomp](https://github.com/seccomp/libseccomp).
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


# Example output (on `x86_64`)

```console
# antijack --help
usage: antijack [-v|--verbose] [-o|--dump PATH.bpf] [--] [COMMAND [ARG ..]]
   or: antijack -h|--help

# antijack -v -- ttyjack echo nope
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
    if ($a1.hi32 == 0)
      if ($a1.lo32 == 21532)
        action KILL_PROCESS;
      if ($a1.lo32 == 21522)
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

# antijack --dump filter.bpf

# wc -c filter.bpf
112 filter.bpf
```


# Related CVEs (not mine)

- [CVE-2005-4890](https://nvd.nist.gov/vuln/detail/CVE-2005-4890) for `su` of util-linux and `sudo`
- [CVE-2016-2568](https://nvd.nist.gov/vuln/detail/CVE-2016-2568) for `pkexec` of Polkit
- [CVE-2016-2779](https://nvd.nist.gov/vuln/detail/CVE-2016-2779) for `runuser` of util-linux
- [CVE-2017-5226](https://nvd.nist.gov/vuln/detail/CVE-2017-5226) for bubblewrap/flatpak
