"""Turns an strace log into a Docker seccomp profile: allow exactly the
syscalls seen, deny everything else with EPERM.

    python3 generate.py verifier.trace > verifier.json
"""
import json, re, sys

# Needed by the container runtime around exec, or on paths the test workload
# cannot provoke (a signal arriving mid-syscall). Kept short and explained.
BASELINE = {
    # runc loads the filter before it execs the binary, then still has to
    # re-open its exec fifo through a verified /proc handle. A trace of the
    # verifier cannot see these; without them the container never starts
    # ("reopen exec fifo: get safe /proc/thread-self/fd handle"). Found by
    # starting the hardened container and adding one syscall at a time.
    "execve", "fstat", "fstatfs", "statx", "readlinkat", "getdents64",
    "exit", "exit_group",
    "rt_sigreturn",     # returning from any signal handler
    "restart_syscall",  # a syscall interrupted by a signal, resumed
    "futex",            # thread joins and locks, even if the trace missed one
}

names = set(BASELINE)
pattern = re.compile(r"^\d+\s+(?:<\.\.\. )?([a-z0-9_]+)[( ]")
for line in open(sys.argv[1]):
    m = pattern.match(line)
    if m and m.group(1) not in ("exited", "killed"):
        names.add(m.group(1))

json.dump({
    "defaultAction": "SCMP_ACT_ERRNO",
    "defaultErrnoRet": 1,
    "archMap": [
        {"architecture": "SCMP_ARCH_X86_64", "subArchitectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"]},
        {"architecture": "SCMP_ARCH_AARCH64", "subArchitectures": ["SCMP_ARCH_ARM"]},
    ],
    "syscalls": [
        {"names": sorted(names - {"clone3"}), "action": "SCMP_ACT_ALLOW"},
        # glibc tries clone3 first and falls back to clone only on ENOSYS, not
        # on the EPERM the default action returns. Same trick as Docker's own
        # default profile.
        {"names": ["clone3"], "action": "SCMP_ACT_ERRNO", "errnoRet": 38},
    ],
}, sys.stdout, indent=2)
sys.stdout.write("\n")
