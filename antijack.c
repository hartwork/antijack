// Copyright (c) 2023 Sebastian Pipping <sebastian@pipping.org>
// SPDX-License-Identifier: Apache-2.0

#define _GNU_SOURCE // strerrorname_np, strerrordesc_np

#include <errno.h>
#include <fcntl.h> // open
#include <getopt.h>
#include <stdarg.h> // va_start
#include <stdbool.h>
#include <stddef.h> // NULL
#include <stdio.h>
#include <stdlib.h> // free
#include <string.h>
#include <unistd.h> // close

#include <sys/ioctl.h>

#include <seccomp.h>

#define AJ_NORETURN __attribute__((__noreturn__))

static bool g_verbose = false;
static char *g_bpf_filename = NULL;
static bool g_pfc_dumped = false;

AJ_NORETURN
static void exit_with(int exit_code, const char *format, ...) {
  if (format != NULL) {
    const int errno_backup = errno;
    FILE *const file = stderr;
    va_list args;
    va_start(args, format);

    fprintf(file, "[-] ERROR: ");
    vfprintf(file, format, args);

    fprintf(file, ": %s (%s/%d).\n", strerrordesc_np(errno_backup),
            strerrorname_np(errno_backup), errno_backup);
  }

  free(g_bpf_filename);
  g_bpf_filename = NULL;
  exit(exit_code);
}

static void success(const char *message) {
  if (!g_verbose) {
    return;
  }
  fprintf(stdout, "[+] %s.\n", (message == NULL) ? "  Done" : message);
}

static void now(const char *format, ...) {
  if (!g_verbose) {
    return;
  }

  FILE *const file = stdout;
  va_list args;
  va_start(args, format);

  fprintf(file, "[*] ");
  vfprintf(file, format, args);
  fprintf(file, "...\n");
}

static void usage(FILE *file) {
  const char *const progname = "antijack";
  fprintf(
      file,
      "usage: %s [-v|--verbose] [-o|--dump PATH.bpf] [--] [COMMAND [ARG ..]]\n",
      progname);
  fprintf(file, "   or: %s -h|--help\n", progname);
}

static void dump_seccomp_pfc(scmp_filter_ctx ctx) {
  if (!g_verbose || g_pfc_dumped) {
    return;
  }

  seccomp_export_pfc(ctx, 1 /* stdout */);
  g_pfc_dumped = true;
}

int main(int argc, char *argv[]) {
  static struct option long_options[] = {{"help", no_argument, 0, 'h'},
                                         {"verbose", no_argument, 0, 'v'},
                                         {"dump", required_argument, 0, 'o'},
                                         {0, 0, 0, 0}};
  int option_index = 0;

  for (;;) {
    const int getopt_res =
        getopt_long(argc, argv, "hvo:", long_options, &option_index);
    if (getopt_res == -1) {
      break;
    }

    switch (getopt_res) {
    case 'h':
      usage(stdout);
      exit_with(0, NULL);
    case 'v':
      g_verbose = true;
      break;
    case 'o':
      free(g_bpf_filename);
      g_bpf_filename = strdup(optarg);
      break;
    default:
      usage(stderr);
      exit_with(1, NULL);
    }
  }

  const bool exec_upcoming = optind < argc;

  if (!exec_upcoming && g_bpf_filename == NULL) {
    usage(stderr);
    exit_with(1, NULL);
  }

  now("Initializing libseccomp");
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (ctx == NULL) {
    exit_with(2, "Could not initialize seccomp.");
  }
  success(NULL);

  now("Adding rule block TIOCSTI ioctls");
  const int res_tiocsti =
      seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(ioctl), 1,
                       SCMP_A1(SCMP_CMP_EQ, TIOCSTI));
  if (res_tiocsti != 0) {
    exit_with(3, "Could not add rule to ioctl TIOCSTI.");
  }
  success(NULL);

  now("Adding rule block TIOCLINUX ioctls");
  const int res_tioclinux =
      seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(ioctl), 1,
                       SCMP_A1(SCMP_CMP_EQ, TIOCLINUX));
  if (res_tioclinux != 0) {
    exit_with(4, "Could not add rule to block ioctl TIOCLINUX.");
  }
  success(NULL);

  if (g_bpf_filename != NULL) {
    now("Dumping seccomp filter BPF program into file \"%s\"", g_bpf_filename);
    dump_seccomp_pfc(ctx);
    const int fd = open(g_bpf_filename, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0) {
      exit_with(5, "Could not open file \"%s\" for writing with",
                g_bpf_filename);
    }

    const int export_bpf_res = seccomp_export_bpf(ctx, fd);
    if (export_bpf_res != 0) {
      exit_with(6, "Faild to export BPF program to file \"%s\"",
                g_bpf_filename);
    }

    for (;;) {
      const int close_res = close(fd);
      if (close_res == 0) {
        break;
      }
      if (close_res == EINTR) {
        continue;
      }

      exit_with(7, "Failed to close file \"%s\"", g_bpf_filename);
    }

    success(NULL);
  }

  if (exec_upcoming) {
    now("Loading seccomp rules into the kernel");
    dump_seccomp_pfc(ctx);
    const int res_load = seccomp_load(ctx);
    if (res_load != 0) {
      errno = -res_load;
      exit_with(8, "Could not load seccomp filter into the kernel.");
    }
    success(NULL);
  }

  now("Releasing libseccomp");
  seccomp_release(ctx);
  success(NULL);

  if (!exec_upcoming) {
    exit_with(0, NULL);
  }

  free(g_bpf_filename);
  g_bpf_filename = NULL;

  now("Running %s", argv[optind]);
  execvp(argv[optind], argv + optind); // may exit

  switch (errno) {
  case EACCES:
    exit_with(126, "%s", argv[optind]);
  case ENOENT:
    exit_with(127, "%s", argv[optind]);
  default:
    exit_with(9, "failed to run command \"%s\"", argv[optind]);
  }
}
