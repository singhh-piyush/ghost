/*
 * Ghost Seccomp-BPF Filter
 * Blocks dangerous syscalls that could bypass Tor or escape the sandbox
 *
 * Compile: gcc -o apply_seccomp apply_seccomp.c -lseccomp
 * Usage: ./apply_seccomp <command> [args...]
 */

#define _GNU_SOURCE
#include <errno.h>
#include <linux/netlink.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
    return 1;
  }

  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (!ctx) {
    perror("seccomp_init");
    return 1;
  }

  /* Block raw packet sockets (AF_PACKET) - prevents raw sniffing */
  if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1,
                       SCMP_A0(SCMP_CMP_EQ, AF_PACKET)) < 0) {
    perror("seccomp AF_PACKET");
  }

  /* Block netlink sockets (AF_NETLINK) - prevents network config manipulation
   */
  if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1,
                       SCMP_A0(SCMP_CMP_EQ, AF_NETLINK)) < 0) {
    perror("seccomp AF_NETLINK");
  }

  /* Block mount operations */
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(mount), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(umount2), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(pivot_root), 0);

  /* Block container escape vector */
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(open_by_handle_at), 0);

  /* Block kernel module loading */
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(init_module), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(finit_module), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(delete_module), 0);

  /* Block ptrace (anti-debugging/injection) */
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ptrace), 0);

  /* Block kexec (kernel replacement) */
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kexec_load), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kexec_file_load), 0);

  /* [FIX 2.4] Block execveat (bypass seccomp/binary wrappers) */
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(execveat), 0);

  /* [FIX 2.5] Block chroot (escape Landlock/filesystem restrictions) */
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(chroot), 0);

  /* Block perf_event_open (performance monitoring can leak info) */
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(perf_event_open), 0);

  /* Block process_vm_readv/writev (cross-process memory access) */
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(process_vm_readv), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(process_vm_writev),
                   0);

  /* Block userfaultfd (exploit vector) */
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(userfaultfd), 0);

  /* Block bpf (eBPF programs can bypass restrictions) */
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(bpf), 0);

  /* Block personality (can disable ASLR) - allow personality(0) for reading */
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(personality), 1,
                   SCMP_A0(SCMP_CMP_NE, 0));

  /* Block kcmp (information leak about kernel pointers) */
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kcmp), 0);

  /* Block add_key/request_key/keyctl (keyring manipulation) */
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(add_key), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(request_key), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(keyctl), 0);

  /* Block io_uring (new attack vector) */
#ifdef __NR_io_uring_setup
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(io_uring_setup), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(io_uring_enter), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(io_uring_register), 0);
#endif

  /* Block quotactl (can enumerate filesystem) */
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(quotactl), 0);

  /* Block swapon/swapoff */
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(swapon), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(swapoff), 0);

  /* Load the filter */
  if (seccomp_load(ctx) < 0) {
    perror("seccomp_load");
    seccomp_release(ctx);
    return 1;
  }

  seccomp_release(ctx);

  /* Execute the command */
  execvp(argv[1], &argv[1]);
  perror("execvp");
  return 1;
}
