/*
 * Ghost Landlock File Access Control
 * Restricts file access to whitelisted paths only (Linux 5.13+)
 *
 * Compile: gcc -o apply_landlock apply_landlock.c
 * Usage: ./apply_landlock <command> [args...]
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef landlock_create_ruleset
static inline int
landlock_create_ruleset(const struct landlock_ruleset_attr *attr, size_t size,
                        __u32 flags) {
  return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int landlock_add_rule(int ruleset_fd,
                                    enum landlock_rule_type rule_type,
                                    const void *rule_attr, __u32 flags) {
  return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr,
                 flags);
}
#endif

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(int ruleset_fd, __u32 flags) {
  return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

#define LANDLOCK_ACCESS_FS_READ                                                \
  (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR)

#define LANDLOCK_ACCESS_FS_WRITE                                               \
  (LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_FILE |            \
   LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_MAKE_CHAR |              \
   LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |                 \
   LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |               \
   LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM)

static int add_path_rule(int ruleset_fd, const char *path, __u64 access) {
  int fd = open(path, O_PATH | O_CLOEXEC);
  if (fd < 0) {
    /* Path doesn't exist, skip */
    return 0;
  }

  struct landlock_path_beneath_attr attr = {
      .allowed_access = access,
      .parent_fd = fd,
  };

  int ret = landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &attr, 0);
  close(fd);
  return ret;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
    return 1;
  }

  /* Check Landlock ABI version */
  int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
  if (abi < 0) {
    if (errno == ENOSYS || errno == EOPNOTSUPP) {
      fprintf(stderr, "[WARN] Landlock not supported, continuing without\n");
      execvp(argv[1], &argv[1]);
      perror("execvp");
      return 1;
    }
    perror("landlock ABI check");
    return 1;
  }

  struct landlock_ruleset_attr ruleset_attr = {
      .handled_access_fs = LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_WRITE |
                           LANDLOCK_ACCESS_FS_EXECUTE,
  };

  int ruleset_fd =
      landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
  if (ruleset_fd < 0) {
    perror("landlock_create_ruleset");
    return 1;
  }

  /* Whitelist paths (read+execute) */
  add_path_rule(ruleset_fd, "/usr",
                LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_EXECUTE);
  add_path_rule(ruleset_fd, "/lib",
                LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_EXECUTE);
  add_path_rule(ruleset_fd, "/lib64",
                LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_EXECUTE);
  add_path_rule(ruleset_fd, "/bin",
                LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_EXECUTE);
  add_path_rule(ruleset_fd, "/sbin",
                LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_EXECUTE);
  add_path_rule(ruleset_fd, "/etc", LANDLOCK_ACCESS_FS_READ);
  add_path_rule(ruleset_fd, "/proc", LANDLOCK_ACCESS_FS_READ);
  add_path_rule(ruleset_fd, "/sys", LANDLOCK_ACCESS_FS_READ);
  add_path_rule(ruleset_fd, "/dev",
                LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_WRITE);

  /* Whitelist paths (read+write) */
  add_path_rule(ruleset_fd, "/tmp",
                LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_WRITE);
  add_path_rule(ruleset_fd, "/run/ghost",
                LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_WRITE);

  /* Ghost Home only (from GHOST_HOME env) */
  const char *ghost_home = getenv("GHOST_HOME");
  if (ghost_home) {
    add_path_rule(ruleset_fd, ghost_home,
                  LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_WRITE);
  } else {
    // Fallback: only /tmp if no GHOST_HOME
    add_path_rule(ruleset_fd, "/tmp",
                  LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_WRITE);
  }

  /* Allow DNS resolution */
  add_path_rule(ruleset_fd, "/etc/resolv.conf", LANDLOCK_ACCESS_FS_READ);
  add_path_rule(ruleset_fd, "/etc/hosts", LANDLOCK_ACCESS_FS_READ);
  add_path_rule(ruleset_fd, "/etc/nsswitch.conf", LANDLOCK_ACCESS_FS_READ);

  /* Allow certificate verification */
  add_path_rule(ruleset_fd, "/etc/ssl", LANDLOCK_ACCESS_FS_READ);
  add_path_rule(ruleset_fd, "/usr/share/ca-certificates",
                LANDLOCK_ACCESS_FS_READ);

  /* Allow timezone data */
  add_path_rule(ruleset_fd, "/usr/share/zoneinfo", LANDLOCK_ACCESS_FS_READ);

  /* Allow Python/Perl libs (if installed) */
  add_path_rule(ruleset_fd, "/usr/lib/python3",
                LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_EXECUTE);
  add_path_rule(ruleset_fd, "/usr/lib/perl5",
                LANDLOCK_ACCESS_FS_READ | LANDLOCK_ACCESS_FS_EXECUTE);

  /* Allow locale data */
  add_path_rule(ruleset_fd, "/usr/share/locale", LANDLOCK_ACCESS_FS_READ);

  /* Allow terminfo (for terminal colors) */
  add_path_rule(ruleset_fd, "/usr/share/terminfo", LANDLOCK_ACCESS_FS_READ);
  add_path_rule(ruleset_fd, "/lib/terminfo", LANDLOCK_ACCESS_FS_READ);

  /* Enforce */
  if (landlock_restrict_self(ruleset_fd, 0) < 0) {
    perror("landlock_restrict_self");
    close(ruleset_fd);
    return 1;
  }
  close(ruleset_fd);

  execvp(argv[1], &argv[1]);
  perror("execvp");
  return 1;
}
