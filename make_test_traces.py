# make_test_traces.py
import random
import os

# Seed for reproducibility
random.seed(42)

# Basic building blocks for syscall lines (cleaned format)
common_syscalls = [
    "openat /etc/passwd",
    "openat /var/log/syslog",
    "read fd=3 len=512",
    "write fd=1 len=128",
    "close fd=3",
    "fstat fd=3",
    "lseek fd=3 off=0 whence=SEEK_SET",
    "stat /usr/bin/python3",
    "getpid",
    "getuid",
    "sendto fd=4 len=64",
    "recvfrom fd=4 len=64",
    "accept fd=5",
    "socket AF_INET SOCK_STREAM",
    "bind 0.0.0.0:8080",
    "listen fd=6 backlog=5",
    "connect 127.0.0.1:80",
    "mmap addr=0x0 len=4096 prot=rw",
    "munmap addr=0x0 len=4096"
]

# Rare / suspicious syscalls or lines to inject
suspicious_snippets = [
    "ptrace PTRACE_TRACEME",
    "execve /bin/sh -c 'sh -i'",
    "execve /usr/bin/sudo",
    "socket AF_INET SOCK_STREAM",
    "connect 192.168.1.100:4444",
    "connect 10.0.0.200:8081",
    "sendto fd=4 len=4096",
    "write fd=1 len=2048",
    "openat /etc/shadow",
    "mprotect addr=0x7fff len=8192 prot=PROT_READ|PROT_EXEC",
    "ioctl fd=3 cmd=0x1234",
    "clone flags=CLONE_VM|CLONE_FS|CLONE_FILES",
    "accept fd=9",
]

def make_normal_trace(path, lines=200):
    """Write a normal-looking trace file."""
    with open(path, "w", encoding="utf-8") as f:
        for i in range(lines):
            # Mostly common syscalls; occasional slightly less-common ones
            if random.random() < 0.03:
                # insert a less common but still benign line
                line = random.choice([
                    "stat /usr/lib/libc.so.6",
                    "futex wait pid=1234",
                    "gettimeofday",
                    "clock_gettime CLOCK_MONOTONIC",
                ])
            else:
                line = random.choice(common_syscalls)
            f.write(line + "\n")

def make_suspicious_trace(path, total_lines=250, anomaly_fraction=0.08):
    """
    Write a trace with injected anomalies.
    anomaly_fraction = fraction of lines that are suspicious.
    """
    normal_portion = int(total_lines * (1.0 - anomaly_fraction))
    with open(path, "w", encoding="utf-8") as f:
        # Start with normal-looking header portion
        for i in range(normal_portion):
            # keep a healthy mix of common syscalls
            f.write(random.choice(common_syscalls) + "\n")

        # Inject clusters of suspicious events
        # 1) A short burst with execve + shell
        f.write("execve /bin/sh -c 'sh -i'\n")
        f.write("ptrace PTRACE_TRACEME\n")
        f.write("openat /etc/shadow\n")

        # 2) A suspicious network phase
        for i in range(6):
            f.write(random.choice([
                "socket AF_INET SOCK_STREAM",
                "connect 192.168.1.100:4444",
                "sendto fd=4 len=2048",
                "recvfrom fd=4 len=128",
            ]) + "\n")

        # 3) Some strange memory / protection changes
        f.write("mprotect addr=0x7fff len=8192 prot=PROT_READ|PROT_EXEC\n")
        f.write("mmap addr=0x0 len=65536 prot=PROT_READ|PROT_WRITE\n")

        # 4) Sprinkle additional rare syscalls to reach total_lines
        remaining = total_lines - normal_portion - 3 - 6 - 2
        for i in range(max(0, remaining)):
            if random.random() < 0.33:
                f.write(random.choice(suspicious_snippets) + "\n")
            else:
                f.write(random.choice(common_syscalls) + "\n")

def main():
    out_dir = "."
    normal_path = os.path.join(out_dir, "normal_test.trace")
    suspicious_path = os.path.join(out_dir, "suspicious_test.trace")

    print("Creating test files in current directory:")
    print(" -", normal_path)
    print(" -", suspicious_path)

    make_normal_trace(normal_path, lines=220)
    make_suspicious_trace(suspicious_path, total_lines=260, anomaly_fraction=0.12)

    print("Done. Files written.")
    print("\nQuick usage example:")
    print("python rag_anomaly_detector.py --program chrome --trace suspicious_test.trace")
    print("python rag_anomaly_detector.py --program chrome --trace normal_test.trace")

if __name__ == '__main__':
    main()
