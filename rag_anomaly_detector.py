import argparse
import json
import math
import os
import re
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from dotenv import load_dotenv
from openai import OpenAI

# Load environment variables
load_dotenv()

EMBED_MODEL = "text-embedding-3-small"
CHAT_MODEL = "gpt-5-mini"

BASELINE_FILES = {
    "chrome": "cleaned_chrome.trace",
    "firefox": "cleaned_firefox.trace",
}
INDEX_PATH = "syscalls_index.json"  # embeddings + behavior-window text per program
STATS_PATH = "baseline_stats.json"  # behavior profiles per program
PROFILE_VERSION = 2

# Heuristics for anomaly flag (tune as needed)
ANOMALY_SCORE_THRESHOLD = 0.35
FEATURE_JS_REFERENCE = 0.20
RISK_EVENT_RATE_REFERENCE = 0.05
EXPECTED_CALL_MIN_PROB = 0.01
EXPECTED_CALL_MIN_COUNT = 2
SEQUENCE_N = 3
TOP_N_SUSPECT_LINES = 20
TOP_N_ABSENT_CALLS = 10
RETRIEVAL_K = 5
BEHAVIOR_WINDOW_SIZE = 12
BEHAVIOR_WINDOW_STRIDE = 6

FEATURE_WEIGHTS = {
    "syscalls": 0.22,
    "arg_patterns": 0.20,
    "arg_categories": 0.15,
    "path_categories": 0.12,
    "network": 0.12,
    "memory": 0.07,
    "errors": 0.05,
    "sequences": 0.07,
}

NETWORK_SYSCALLS = {
    "socket",
    "connect",
    "bind",
    "listen",
    "accept",
    "accept4",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "shutdown",
}
FILE_SYSCALLS = {
    "access",
    "faccessat",
    "faccessat2",
    "fstat",
    "lstat",
    "newfstatat",
    "open",
    "openat",
    "openat2",
    "readlink",
    "stat",
    "statx",
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "chmod",
    "fchmod",
    "chown",
    "fchown",
}
PROCESS_SYSCALLS = {
    "clone",
    "clone3",
    "execve",
    "execveat",
    "fork",
    "kill",
    "ptrace",
    "setgid",
    "setuid",
    "tgkill",
    "tkill",
    "vfork",
}
MEMORY_SYSCALLS = {"brk", "mmap", "mprotect", "munmap", "mremap"}
KERNEL_MODULE_SYSCALLS = {
    "delete_module",
    "finit_module",
    "init_module",
    "insmod",
}
MOUNT_SYSCALLS = {"mount", "umount", "umount2"}

SENSITIVE_PATHS = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/root/.ssh",
    "/home/your-user",
    "/proc/self/mem",
}
SHELL_OR_PRIVILEGED_EXEC = {
    "/bin/bash",
    "/bin/dash",
    "/bin/sh",
    "/usr/bin/bash",
    "/usr/bin/nc",
    "/usr/bin/netcat",
    "/usr/bin/python",
    "/usr/bin/python3",
    "/usr/bin/sudo",
}
SUSPICIOUS_PORTS = {4444, 1337, 31337, 8081, 5555}
CRITICAL_RISK_INDICATORS = {
    "risk:credential_or_secret_file",
    "risk:kernel_module_operation",
    "risk:mount_operation",
    "risk:ptrace_operation",
    "risk:shell_or_privileged_exec",
    "risk:writable_executable_memory",
}

_client: Optional[OpenAI] = None


@dataclass
class SyscallEvent:
    raw: str
    name: str
    args: List[str]
    ret: Optional[str] = None
    errno: Optional[str] = None
    duration: Optional[float] = None


# ----------- Utilities -----------


def get_openai_client() -> OpenAI:
    """Create the OpenAI client lazily so offline tests can import this module."""
    global _client
    if _client is None:
        _client = OpenAI()
    return _client


def read_trace_lines(path: str) -> List[str]:
    """Read non-empty trace lines."""
    out = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if s:
                out.append(s)
    return out


def strip_strace_prefix(line: str) -> str:
    """Remove optional 'pid timestamp' prefixes from raw strace output."""
    parts = line.split(maxsplit=2)
    if len(parts) == 3 and parts[0].isdigit() and re.fullmatch(r"\d+(?:\.\d+)?", parts[1]):
        return parts[2]
    return line


def split_args(arg_text: str) -> List[str]:
    """Split syscall arguments on top-level commas while respecting quotes/brackets."""
    if not arg_text:
        return []

    args = []
    buf = []
    depth = 0
    in_quote = False
    escape = False
    for ch in arg_text:
        if in_quote:
            buf.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_quote = False
            continue

        if ch == '"':
            in_quote = True
            buf.append(ch)
        elif ch in "([{":
            depth += 1
            buf.append(ch)
        elif ch in ")]}":
            depth = max(0, depth - 1)
            buf.append(ch)
        elif ch == "," and depth == 0:
            arg = "".join(buf).strip()
            if arg:
                args.append(arg)
            buf = []
        else:
            buf.append(ch)

    arg = "".join(buf).strip()
    if arg:
        args.append(arg)
    return args


def parse_syscall_event(line: str) -> Optional[SyscallEvent]:
    """Parse raw strace-style or simplified test-trace lines into structured events."""
    raw = line.strip()
    if not raw:
        return None

    body = strip_strace_prefix(raw)

    duration = None
    duration_match = re.search(r"\s<([0-9]*\.?[0-9]+)>$", body)
    if duration_match:
        duration = float(duration_match.group(1))
        body = body[: duration_match.start()].strip()

    ret = None
    errno = None
    if " = " in body:
        body, result = body.rsplit(" = ", 1)
        result = result.strip()
        ret_match = re.match(r"(?P<ret>-?(?:0x[0-9a-fA-F]+|\d+|\?))(?P<rest>.*)", result)
        if ret_match:
            ret = ret_match.group("ret")
            rest = ret_match.group("rest")
            errno_match = re.search(r"\b([A-Z][A-Z0-9_]+)\b", rest)
            if ret == "-1" and errno_match:
                errno = errno_match.group(1)

    body = body.strip()
    if body.startswith("---"):
        signal_match = re.match(r"---\s+([A-Z0-9_]+)", body)
        name = f"signal:{signal_match.group(1)}" if signal_match else "signal"
        return SyscallEvent(raw=raw, name=name, args=[], ret=ret, errno=errno, duration=duration)

    resumed_match = re.match(r"<\.\.\.\s+([A-Za-z_][A-Za-z0-9_]*)\s+resumed>(.*)", body)
    if resumed_match:
        name = resumed_match.group(1)
        args = split_args(resumed_match.group(2).strip(" )"))
        return SyscallEvent(raw=raw, name=name, args=args, ret=ret, errno=errno, duration=duration)

    if "(" in body:
        name_text, arg_text = body.split("(", 1)
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name_text):
            if arg_text.endswith(")"):
                arg_text = arg_text[:-1]
            args = split_args(arg_text)
            return SyscallEvent(raw=raw, name=name_text, args=args, ret=ret, errno=errno, duration=duration)

    simple_match = re.match(r"(?P<name>[A-Za-z_][A-Za-z0-9_:.+-]*)(?:\s+(?P<args>.*))?$", body)
    if simple_match:
        name = simple_match.group("name")
        arg_text = simple_match.group("args") or ""
        args = split_args(arg_text) if "," in arg_text else arg_text.split()
        return SyscallEvent(raw=raw, name=name, args=args, ret=ret, errno=errno, duration=duration)

    return None


def parse_trace_events(lines: List[str]) -> List[SyscallEvent]:
    return [event for line in lines if (event := parse_syscall_event(line)) is not None]


def syscall_name(line: str) -> str:
    """Return the parsed syscall name for backwards compatibility with older code."""
    event = parse_syscall_event(line)
    return event.name if event else ""


def normalize(counter: Counter) -> Dict[str, float]:
    total = sum(counter.values())
    if total == 0:
        return {}
    return {k: v / total for k, v in counter.items()}


def js_divergence(p: Dict[str, float], q: Dict[str, float]) -> float:
    """Jensen-Shannon divergence (base 2)."""
    keys = set(p) | set(q)
    if not keys:
        return 0.0
    m = {k: 0.5 * (p.get(k, 0.0) + q.get(k, 0.0)) for k in keys}

    def kl(a: Dict[str, float], b: Dict[str, float]) -> float:
        s = 0.0
        for k in keys:
            av, bv = a.get(k, 0.0), b.get(k, 0.0)
            if av > 0 and bv > 0:
                s += av * math.log(av / bv, 2)
        return s

    return 0.5 * kl(p, m) + 0.5 * kl(q, m)


def cosine(a: List[float], b: List[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def summarize_drift(baseline_probs: Dict[str, float], obs_probs: Dict[str, float]) -> Tuple[float, float]:
    """Return (JS divergence, unseen-rate)."""
    js = js_divergence(baseline_probs, obs_probs)
    unseen = sum(v for k, v in obs_probs.items() if k not in baseline_probs)
    return js, unseen


# ----------- Feature extraction -----------


def extract_paths(text: str) -> List[str]:
    quoted = re.findall(r'"((?:\\.|[^"\\])*)"', text)
    tokens = re.findall(r"(?<!\S)(/[^\s,\)'\"]+)", text)
    paths = []
    for item in quoted + tokens:
        cleaned = item.replace("\\n", "").rstrip(".,);]")
        if cleaned.startswith("/"):
            paths.append(cleaned)
    return list(dict.fromkeys(paths))


def classify_path(path: str) -> str:
    if path in SENSITIVE_PATHS or path.startswith("/root/.ssh") or path.endswith("/.ssh/id_rsa"):
        return "credential_or_secret_file"
    if path.startswith("/proc/") and (path.endswith("/mem") or "/mem" in path):
        return "process_memory"
    if path.startswith("/etc/"):
        return "etc_config"
    if path.startswith("/var/log/"):
        return "log_file"
    if path.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
        return "temporary_or_shared_memory"
    if path.startswith(("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/")):
        return "system_binary"
    if path.startswith(("/lib/", "/usr/lib/", "/lib64/", "/usr/local/lib/")):
        return "library"
    if path.startswith("/home/"):
        return "user_home"
    return "other_path"


def extract_network_targets(text: str) -> List[str]:
    targets = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b", text)
    return list(dict.fromkeys(targets))


def classify_network_target(target: str, syscall: str) -> str:
    host, _, port_text = target.partition(":")
    port = int(port_text) if port_text.isdigit() else None
    if host == "0.0.0.0":
        scope = "any_address_bind"
    elif host.startswith("127."):
        scope = "loopback"
    elif host.startswith("10.") or host.startswith("192.168.") or re.match(r"172\.(1[6-9]|2\d|3[01])\.", host):
        scope = "private_network"
    else:
        scope = "public_network"

    if port in SUSPICIOUS_PORTS:
        return f"{scope}:suspicious_port"
    if syscall in {"bind", "listen"} and host == "0.0.0.0":
        return f"{scope}:listening_service"
    return scope


def extract_lengths(text: str) -> List[int]:
    values = []
    for match in re.finditer(r"\b(?:len|count|size|st_size)=?\s*(\d+)\b", text):
        values.append(int(match.group(1)))
    return values


def length_bucket(value: int) -> str:
    if value <= 128:
        return "small"
    if value <= 1024:
        return "medium"
    if value <= 8192:
        return "large"
    return "very_large"


def normalize_number(value: int) -> str:
    if value < 0:
        return "num:negative"
    if value <= 2:
        return f"num:{value}"
    if value <= 16:
        return "num:small"
    if value <= 1024:
        return "num:medium"
    if value <= 65536:
        return "num:large"
    return "num:huge"


def normalize_arg(arg: str) -> str:
    arg = arg.strip()
    stripped = arg.strip('"')
    paths = extract_paths(arg)
    if paths:
        return f"path:{classify_path(paths[0])}"

    network_targets = extract_network_targets(arg)
    if network_targets:
        return f"network:{classify_network_target(network_targets[0], '')}"

    if re.fullmatch(r"0x[0-9a-fA-F]+", stripped):
        return "ptr"
    if re.fullmatch(r"-?\d+", stripped):
        return normalize_number(int(stripped))
    if any(flag in stripped for flag in ("O_", "PROT_", "MAP_", "CLONE_", "PTRACE_", "SIG", "ARCH_")):
        tokens = re.findall(r"[A-Z][A-Z0-9_]+", stripped)
        return "|".join(tokens[:4]) if tokens else "flags"
    if stripped.startswith("fd="):
        return "fd"
    if len(stripped) > 40:
        return "blob"
    return stripped.lower()[:40] if stripped else "empty"


def duration_bucket(duration: Optional[float]) -> Optional[str]:
    if duration is None:
        return None
    if duration < 0.0001:
        return "duration:fast"
    if duration < 0.001:
        return "duration:normal"
    if duration < 0.01:
        return "duration:slow"
    return "duration:very_slow"


def event_categories(event: SyscallEvent) -> Tuple[List[str], List[str]]:
    categories = []
    risk = []
    raw_upper = event.raw.upper()
    raw_lower = event.raw.lower()

    if event.name in FILE_SYSCALLS:
        categories.append("class:file")
    if event.name in NETWORK_SYSCALLS:
        categories.append("class:network")
    if event.name in PROCESS_SYSCALLS:
        categories.append("class:process")
    if event.name in MEMORY_SYSCALLS:
        categories.append("class:memory")

    for path in extract_paths(event.raw):
        path_class = classify_path(path)
        categories.append(f"path:{path_class}")
        if path_class in {"credential_or_secret_file", "process_memory"}:
            risk.append("risk:credential_or_secret_file")
        if event.name in {"execve", "execveat"} and path in SHELL_OR_PRIVILEGED_EXEC:
            risk.append("risk:shell_or_privileged_exec")

    for target in extract_network_targets(event.raw):
        network_class = classify_network_target(target, event.name)
        categories.append(f"network:{network_class}")
        if "suspicious_port" in network_class:
            risk.append("risk:suspicious_network_target")
        if event.name in {"bind", "listen"} and "any_address_bind" in network_class:
            risk.append("risk:listening_on_all_interfaces")

    if "PROT_EXEC" in raw_upper:
        categories.append("memory:executable")
    if "PROT_WRITE" in raw_upper:
        categories.append("memory:writable")
    if "PROT_EXEC" in raw_upper and "PROT_WRITE" in raw_upper:
        categories.append("memory:writable_executable")
        risk.append("risk:writable_executable_memory")
    if "PROT_READ|PROT_EXEC" in raw_upper:
        categories.append("memory:read_executable")
    if "prot=rw" in raw_lower:
        categories.append("memory:read_write")

    for length in extract_lengths(event.raw):
        bucket = length_bucket(length)
        categories.append(f"length:{bucket}")
        if event.name in {"sendto", "sendmsg", "write"} and length >= 2048:
            risk.append("risk:large_output_transfer")

    if event.errno:
        categories.append(f"errno:{event.errno}")
        risk.append("risk:syscall_error")
    elif event.ret == "-1":
        risk.append("risk:syscall_error")

    if event.name == "ptrace":
        risk.append("risk:ptrace_operation")
    if event.name in MOUNT_SYSCALLS:
        risk.append("risk:mount_operation")
    if event.name in KERNEL_MODULE_SYSCALLS or raw_lower.startswith("insmod "):
        risk.append("risk:kernel_module_operation")

    return list(dict.fromkeys(categories)), list(dict.fromkeys(risk))


def normalized_call_pattern(event: SyscallEvent) -> str:
    args = [normalize_arg(arg) for arg in event.args[:5]]
    if not args:
        return f"{event.name}()"
    return f"{event.name}({', '.join(args)})"


def event_summary(event: SyscallEvent) -> str:
    categories, risk = event_categories(event)
    pieces = [f"call={event.name}", f"pattern={normalized_call_pattern(event)}"]
    if categories:
        pieces.append("categories=" + ",".join(categories[:6]))
    if risk:
        pieces.append("risk=" + ",".join(risk))
    if event.errno:
        pieces.append(f"errno={event.errno}")
    if event.ret is not None:
        pieces.append(f"ret={event.ret}")
    pieces.append("raw=" + event.raw[:160])
    return "; ".join(pieces)


def feature_block(counter: Counter) -> Dict[str, object]:
    return {
        "freqs": dict(counter),
        "probs": normalize(counter),
        "total": sum(counter.values()),
    }


def build_behavior_profile(lines: List[str]) -> Dict[str, object]:
    events = parse_trace_events(lines)
    counters = {
        "syscalls": Counter(),
        "arg_patterns": Counter(),
        "arg_categories": Counter(),
        "path_categories": Counter(),
        "network": Counter(),
        "memory": Counter(),
        "errors": Counter(),
        "risk_indicators": Counter(),
        "duration": Counter(),
        "sequences": Counter(),
    }

    names = []
    for event in events:
        names.append(event.name)
        counters["syscalls"][event.name] += 1
        counters["arg_patterns"][normalized_call_pattern(event)] += 1

        categories, risk = event_categories(event)
        for category in categories:
            counters["arg_categories"][f"{event.name}|{category}"] += 1
            if category.startswith("path:"):
                counters["path_categories"][f"{event.name}|{category}"] += 1
            elif category.startswith("network:"):
                counters["network"][f"{event.name}|{category}"] += 1
            elif category.startswith("memory:"):
                counters["memory"][f"{event.name}|{category}"] += 1
            elif category.startswith("errno:"):
                counters["errors"][f"{event.name}|{category}"] += 1

        for indicator in risk:
            counters["risk_indicators"][indicator] += 1

        if event.errno:
            counters["errors"][f"{event.name}|errno:{event.errno}"] += 1
        elif event.ret == "-1":
            counters["errors"][f"{event.name}|return:-1"] += 1

        bucket = duration_bucket(event.duration)
        if bucket:
            counters["duration"][f"{event.name}|{bucket}"] += 1

    for i in range(0, max(0, len(names) - SEQUENCE_N + 1)):
        counters["sequences"][" -> ".join(names[i : i + SEQUENCE_N])] += 1

    syscall_total = sum(counters["syscalls"].values()) or 1
    expected_calls = {}
    for name, count in counters["syscalls"].items():
        prob = count / syscall_total
        if count >= EXPECTED_CALL_MIN_COUNT and prob >= EXPECTED_CALL_MIN_PROB:
            expected_calls[name] = {"count": count, "prob": prob}

    features = {name: feature_block(counter) for name, counter in counters.items()}
    return {
        "profile_version": PROFILE_VERSION,
        "total_lines": len(lines),
        "total_events": len(events),
        "freqs": features["syscalls"]["freqs"],  # compatibility with older outputs
        "probs": features["syscalls"]["probs"],
        "features": features,
        "expected_calls": expected_calls,
    }


def build_behavior_windows(events: List[SyscallEvent]) -> List[str]:
    if not events:
        return []

    windows = []
    if len(events) <= BEHAVIOR_WINDOW_SIZE:
        ranges = [(0, len(events))]
    else:
        ranges = [
            (i, min(i + BEHAVIOR_WINDOW_SIZE, len(events)))
            for i in range(0, len(events), BEHAVIOR_WINDOW_STRIDE)
        ]

    for start, end in ranges:
        window = events[start:end]
        calls = Counter(event.name for event in window)
        categories = Counter()
        risks = Counter()
        examples = []
        for event in window:
            event_cats, event_risks = event_categories(event)
            categories.update(event_cats)
            risks.update(event_risks)
            if len(examples) < 3:
                examples.append(event.raw[:100])

        text = (
            f"window {start}-{end}: "
            f"calls={format_counter(calls, 6)}; "
            f"categories={format_counter(categories, 6)}; "
            f"risk={format_counter(risks, 5)}; "
            f"examples={' | '.join(examples)}"
        )
        windows.append(text)

    return list(dict.fromkeys(windows))


# ----------- Baseline / index handling -----------


def stats_current() -> bool:
    if not os.path.exists(STATS_PATH):
        return False
    try:
        with open(STATS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return False
    if data.get("_profile_version") != PROFILE_VERSION:
        return False
    return all(prog in data and "features" in data[prog] for prog in BASELINE_FILES)


def index_current() -> bool:
    if not os.path.exists(INDEX_PATH):
        return False
    try:
        with open(INDEX_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return False
    if data.get("_profile_version") != PROFILE_VERSION:
        return False
    programs = data.get("programs", {})
    return all(prog in programs for prog in BASELINE_FILES)


def embed_texts(texts: List[str]) -> List[Dict[str, object]]:
    """Embed text chunks; fall back to text-only entries if the API is unavailable."""
    rows = [{"text": text, "embedding": []} for text in texts]
    if not texts:
        return rows

    try:
        embeddings = []
        batch_size = 256
        client = get_openai_client()
        for i in range(0, len(texts), batch_size):
            batch = texts[i : i + batch_size]
            res = client.embeddings.create(model=EMBED_MODEL, input=batch)
            for rec in res.data:
                embeddings.append(rec.embedding)
        return [{"text": text, "embedding": embedding} for text, embedding in zip(texts, embeddings)]
    except Exception as exc:
        print(f"Warning: embedding API unavailable; using lexical retrieval only. Details: {exc}")
        return rows


def ensure_baseline_exists(force: bool = False, build_index: bool = True) -> None:
    """Build baseline behavior stats and optional RAG index from BASELINE_FILES."""
    need_stats = force or not stats_current()
    need_index = build_index and (force or not index_current())

    if not need_stats and not need_index:
        return

    program_lines = {}
    for prog, file in BASELINE_FILES.items():
        if not os.path.exists(file):
            raise FileNotFoundError(
                f"Baseline file for '{prog}' not found: {file}. "
                f"Place cleaned or raw traces in the working directory."
            )
        program_lines[prog] = read_trace_lines(file)

    if need_stats:
        stats_out = {"_profile_version": PROFILE_VERSION}
        for prog, lines in program_lines.items():
            stats_out[prog] = build_behavior_profile(lines)
        with open(STATS_PATH, "w", encoding="utf-8") as f:
            json.dump(stats_out, f, indent=2)

    if need_index:
        index_out = {"_profile_version": PROFILE_VERSION, "programs": {}}
        for prog, lines in program_lines.items():
            events = parse_trace_events(lines)
            window_texts = build_behavior_windows(events)
            if not window_texts:
                window_texts = lines
            index_out["programs"][prog] = embed_texts(window_texts)

        with open(INDEX_PATH, "w", encoding="utf-8") as f:
            json.dump(index_out, f)


def load_stats() -> Dict[str, dict]:
    with open(STATS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def load_index() -> Dict[str, List[dict]]:
    with open(INDEX_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    if data.get("_profile_version") == PROFILE_VERSION:
        return data.get("programs", {})
    return data


# ----------- Scoring / retrieval -----------


def feature_metrics(base_profile: Dict[str, object], obs_profile: Dict[str, object]) -> Dict[str, Dict[str, float]]:
    metrics = {}
    base_features = base_profile.get("features", {})
    obs_features = obs_profile.get("features", {})
    for name in FEATURE_WEIGHTS:
        base_probs = base_features.get(name, {}).get("probs", {})
        obs_probs = obs_features.get(name, {}).get("probs", {})
        js, unseen = summarize_drift(base_probs, obs_probs)
        score = min(1.0, (js / FEATURE_JS_REFERENCE) * 0.70 + unseen * 0.30)
        metrics[name] = {"js": js, "unseen_rate": unseen, "score": score}
    return metrics


def absent_expected_calls(base_profile: Dict[str, object], obs_profile: Dict[str, object]) -> Tuple[List[Dict[str, float]], float]:
    expected = base_profile.get("expected_calls", {})
    obs_calls = set(obs_profile.get("features", {}).get("syscalls", {}).get("freqs", {}))
    total_expected_prob = sum(info["prob"] for info in expected.values()) or 1.0
    missing = []
    missing_prob = 0.0
    for call, info in expected.items():
        if call not in obs_calls:
            missing.append({"call": call, "baseline_count": info["count"], "baseline_prob": info["prob"]})
            missing_prob += info["prob"]
    missing.sort(key=lambda item: item["baseline_prob"], reverse=True)
    return missing[:TOP_N_ABSENT_CALLS], min(1.0, missing_prob / total_expected_prob)


def compare_profiles(base_profile: Dict[str, object], obs_profile: Dict[str, object]) -> Dict[str, object]:
    metrics = feature_metrics(base_profile, obs_profile)
    feature_score = sum(FEATURE_WEIGHTS[name] * metrics[name]["score"] for name in FEATURE_WEIGHTS)
    missing_calls, absent_score = absent_expected_calls(base_profile, obs_profile)

    risk_freqs = obs_profile.get("features", {}).get("risk_indicators", {}).get("freqs", {})
    risk_total = sum(risk_freqs.values())
    obs_total = obs_profile.get("total_events", 0) or 1
    risk_rate = risk_total / obs_total
    critical_risks = sorted(set(risk_freqs) & CRITICAL_RISK_INDICATORS)
    risk_score = min(1.0, risk_rate / RISK_EVENT_RATE_REFERENCE)
    if critical_risks:
        risk_score = max(risk_score, 0.85)

    anomaly_score = min(1.0, 0.68 * feature_score + 0.17 * absent_score + 0.15 * risk_score)
    high_confidence_features = {"syscalls", "arg_patterns", "arg_categories", "path_categories", "network", "memory", "errors"}
    high_drift = any(
        metrics[name]["js"] >= 0.30 and metrics[name]["unseen_rate"] >= 0.20
        for name in high_confidence_features
    )
    heuristic_anomaly = anomaly_score >= ANOMALY_SCORE_THRESHOLD or high_drift or bool(critical_risks)

    return {
        "anomaly_score": anomaly_score,
        "heuristic_anomaly": heuristic_anomaly,
        "feature_score": feature_score,
        "absent_score": absent_score,
        "risk_score": risk_score,
        "risk_rate": risk_rate,
        "risk_indicators": risk_freqs,
        "critical_risks": critical_risks,
        "absent_calls": missing_calls,
        "feature_metrics": metrics,
    }


def event_suspicion_score(
    event: SyscallEvent,
    base_profile: Dict[str, object],
    obs_profile: Dict[str, object],
) -> Tuple[float, List[str]]:
    base_features = base_profile.get("features", {})
    obs_features = obs_profile.get("features", {})
    base_sys_probs = base_features.get("syscalls", {}).get("probs", {})
    obs_sys_probs = obs_features.get("syscalls", {}).get("probs", {})
    base_arg_patterns = base_features.get("arg_patterns", {}).get("freqs", {})
    base_arg_categories = base_features.get("arg_categories", {}).get("freqs", {})

    score = 0.0
    reasons = []
    base_prob = base_sys_probs.get(event.name, 0.0)
    obs_prob = obs_sys_probs.get(event.name, 0.0)
    if event.name not in base_sys_probs:
        score += 2.5
        reasons.append("unseen syscall")
    else:
        score += max(0.0, 1.0 - base_prob)
        if base_prob > 0 and obs_prob >= max(base_prob * 3, base_prob + 0.05):
            score += 1.0
            reasons.append("frequency spike")

    pattern = normalized_call_pattern(event)
    if pattern not in base_arg_patterns:
        score += 1.2
        reasons.append("unseen parameter pattern")

    categories, risks = event_categories(event)
    for category in categories:
        key = f"{event.name}|{category}"
        if key not in base_arg_categories:
            if category.startswith(("path:", "network:", "memory:", "errno:")):
                score += 0.7
                reasons.append(f"unseen {category}")

    if risks:
        score += 2.0 + 0.5 * len(risks)
        reasons.extend(risks)

    if event.errno:
        score += 0.5
        reasons.append(f"errno {event.errno}")

    return score, list(dict.fromkeys(reasons))


def find_suspect_events(
    base_profile: Dict[str, object],
    obs_profile: Dict[str, object],
    events: List[SyscallEvent],
    top_n: int,
) -> List[Dict[str, object]]:
    scored = []
    for event in events:
        score, reasons = event_suspicion_score(event, base_profile, obs_profile)
        if score > 0:
            scored.append((score, event, reasons))

    scored.sort(reverse=True, key=lambda item: item[0])
    out = []
    seen = set()
    for score, event, reasons in scored:
        key = event_summary(event)
        if key in seen:
            continue
        seen.add(key)
        out.append({"score": score, "line": event.raw, "summary": key, "reasons": reasons})
        if len(out) >= top_n:
            break
    return out


def token_set(text: str) -> set:
    return set(re.findall(r"[A-Za-z0-9_./:-]+", text.lower()))


def lexical_neighbors(texts: List[str], queries: List[str], k: int) -> Dict[str, List[str]]:
    out = {}
    text_tokens = [(text, token_set(text)) for text in texts]
    for query in queries:
        q_tokens = token_set(query)
        scored = []
        for text, t_tokens in text_tokens:
            union = q_tokens | t_tokens
            sim = len(q_tokens & t_tokens) / len(union) if union else 0.0
            scored.append((sim, text))
        scored.sort(reverse=True, key=lambda item: item[0])
        out[query] = [text for _, text in scored[:k]]
    return out


def retrieve_neighbors(index: List[dict], queries: List[str], k: int) -> Dict[str, List[str]]:
    """Return top-k similar baseline behavior windows for each query summary."""
    if not queries:
        return {}

    texts = [r["text"] for r in index]
    vecs = [r.get("embedding", []) for r in index]
    if not texts or not any(vecs):
        return lexical_neighbors(texts, queries, k)

    try:
        res = get_openai_client().embeddings.create(model=EMBED_MODEL, input=queries)
        qvecs = [d.embedding for d in res.data]
    except Exception as exc:
        print(f"Warning: query embedding unavailable; using lexical retrieval. Details: {exc}")
        return lexical_neighbors(texts, queries, k)

    out = {}
    for qline, qv in zip(queries, qvecs):
        sims = [(cosine(qv, v), t) for t, v in zip(texts, vecs) if v]
        sims.sort(reverse=True, key=lambda x: x[0])
        out[qline] = [t for _, t in sims[:k]]
    return out


def format_counter(counter: Counter, limit: int = 5) -> str:
    if not counter:
        return "none"
    return ", ".join(f"{key}:{value}" for key, value in counter.most_common(limit))


def top_feature_lines(comparison: Dict[str, object], limit: int = 5) -> List[str]:
    metrics = comparison["feature_metrics"]
    ordered = sorted(metrics.items(), key=lambda item: item[1]["score"], reverse=True)
    return [
        f"{name}: js={values['js']:.3f}, unseen={values['unseen_rate']:.3f}, score={values['score']:.3f}"
        for name, values in ordered[:limit]
    ]


def heuristic_reason(comparison: Dict[str, object]) -> str:
    top_metric = top_feature_lines(comparison, 1)[0]
    risk_indicators = comparison.get("risk_indicators", {})
    absent_calls = comparison.get("absent_calls", [])
    parts = [f"behavior score={comparison['anomaly_score']:.3f}", f"top drift={top_metric}"]
    if risk_indicators:
        parts.append("risk=" + format_counter(Counter(risk_indicators), 3))
    if absent_calls:
        parts.append("missing expected calls=" + ", ".join(item["call"] for item in absent_calls[:3]))
    return "; ".join(parts)


def llm_decide(
    program: str,
    comparison: Dict[str, object],
    obs_total: int,
    suspects: List[Dict[str, object]],
    suspect_to_neighbors: Dict[str, List[str]],
    skip_llm: bool = False,
) -> Tuple[bool, str]:
    """Ask GPT to explain the deterministic detector verdict."""
    heuristic_anomaly = bool(comparison["heuristic_anomaly"])
    fallback_reason = heuristic_reason(comparison)
    if skip_llm:
        return heuristic_anomaly, fallback_reason

    suspect_blocks = []
    for item in suspects:
        neighs = suspect_to_neighbors.get(item["summary"], [])
        block = (
            f"- score: {item['score']:.2f}\n"
            f"  reasons: {', '.join(item['reasons']) or 'none'}\n"
            f"  line: {item['line']}\n"
            f"  summary: {item['summary']}\n"
            f"  similar_baseline: {' | '.join(neighs) if neighs else '(none)'}"
        )
        suspect_blocks.append(block)
    suspect_text = "\n".join(suspect_blocks) if suspect_blocks else "(none)"

    absent_text = "\n".join(
        f"- {item['call']} baseline_prob={item['baseline_prob']:.3f}"
        for item in comparison["absent_calls"]
    ) or "(none)"
    feature_text = "\n".join("- " + line for line in top_feature_lines(comparison, 8))
    risk_text = format_counter(Counter(comparison["risk_indicators"]), 8)

    system = (
        "You are a security assistant. Explain whether a system-call trace deviates "
        "from a known program baseline. Treat the deterministic behavior score as "
        "the primary verdict, and use syscall parameters, frequency, missing calls, "
        "return/error behavior, sequences, and retrieved baseline windows in the explanation."
    )

    user = f"""
Program: {program}
Observed parsed events: {obs_total}
Deterministic anomaly score: {comparison['anomaly_score']:.3f}
Deterministic verdict: {"ANOMALY" if heuristic_anomaly else "NORMAL"}
Feature score: {comparison['feature_score']:.3f}
Absent-call score: {comparison['absent_score']:.3f}
Risk score: {comparison['risk_score']:.3f}
Risk event rate: {comparison['risk_rate']:.3f}
Risk indicators: {risk_text}

Feature drift:
{feature_text}

Expected baseline calls absent from observed trace:
{absent_text}

Top suspect events and nearest baseline behavior windows:
{suspect_text}

Respond strictly in this JSON shape:
{{"anomaly": true|false, "reason": "one-sentence justification"}}
"""

    try:
        resp = get_openai_client().chat.completions.create(
            model=CHAT_MODEL,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        content = resp.choices[0].message.content.strip()
        parsed = json.loads(content)
        if isinstance(parsed, dict) and "reason" in parsed:
            llm_anomaly = bool(parsed.get("anomaly", heuristic_anomaly))
            reason = str(parsed["reason"])
            if llm_anomaly != heuristic_anomaly:
                reason = f"{reason} Deterministic score retained verdict: {fallback_reason}."
            return heuristic_anomaly, reason
    except Exception as exc:
        return heuristic_anomaly, f"{fallback_reason}; LLM explanation unavailable: {exc}"

    return heuristic_anomaly, fallback_reason


# ------------- Main flow -------------


def known_programs(stats: Dict[str, dict]) -> List[str]:
    return [key for key in stats if not key.startswith("_")]


def analyze(program: str, trace_path: str, rebuild_index: bool = False, skip_llm: bool = False) -> None:
    ensure_baseline_exists(force=rebuild_index, build_index=not skip_llm)

    stats = load_stats()
    index = load_index() if not skip_llm and os.path.exists(INDEX_PATH) else {}

    if program not in stats:
        raise ValueError(
            f"Unknown program '{program}'. Known: {known_programs(stats)}. "
            f"If this is new, add a baseline file to BASELINE_FILES and rebuild."
        )
    if not skip_llm and program not in index:
        raise ValueError(
            f"No RAG index for '{program}'. Known: {list(index.keys())}. "
            f"Run with --rebuild-index or use --skip-llm for heuristic-only analysis."
        )

    lines = read_trace_lines(trace_path)
    events = parse_trace_events(lines)
    obs_profile = build_behavior_profile(lines)
    base_profile = stats[program]

    comparison = compare_profiles(base_profile, obs_profile)
    suspects = find_suspect_events(base_profile, obs_profile, events, TOP_N_SUSPECT_LINES)

    neighbors = {}
    if not skip_llm:
        queries = [item["summary"] for item in suspects]
        neighbors = retrieve_neighbors(index[program], queries, RETRIEVAL_K)

    is_anom, reason = llm_decide(program, comparison, len(events), suspects, neighbors, skip_llm)

    verdict = "ANOMALY: YES" if is_anom else "ANOMALY: NO"
    syscall_metrics = comparison["feature_metrics"]["syscalls"]
    arg_metrics = comparison["feature_metrics"]["arg_patterns"]
    sequence_metrics = comparison["feature_metrics"]["sequences"]

    print("=" * 72)
    print(verdict)
    print(f"Reason: {reason}")
    print("-" * 72)
    print(
        "Stats -> "
        f"Score: {comparison['anomaly_score']:.3f} | "
        f"Syscall JS: {syscall_metrics['js']:.3f} | "
        f"Syscall unseen: {syscall_metrics['unseen_rate']:.3f} | "
        f"Arg-pattern JS: {arg_metrics['js']:.3f} | "
        f"Sequence JS: {sequence_metrics['js']:.3f} | "
        f"Risk rate: {comparison['risk_rate']:.3f} | "
        f"Events: {len(events)}"
    )
    print("Top drift signals:")
    for line in top_feature_lines(comparison, 5):
        print(f"  - {line}")
    if comparison["risk_indicators"]:
        print(f"Risk indicators: {format_counter(Counter(comparison['risk_indicators']), 8)}")
    if comparison["absent_calls"]:
        absent = ", ".join(item["call"] for item in comparison["absent_calls"][:TOP_N_ABSENT_CALLS])
        print(f"Absent expected calls: {absent}")
    print(f"Program baseline: {program}")
    print("=" * 72)


def main() -> None:
    parser = argparse.ArgumentParser(description="RAG Anomaly Detector for syscall traces.")
    parser.add_argument("--program", required=True, help="Program name (e.g., chrome, firefox)")
    parser.add_argument("--trace", required=True, help="Path to the trace file to analyze.")
    parser.add_argument(
        "--rebuild-index",
        action="store_true",
        help="Rebuild baseline behavior stats and embedding index from baseline files.",
    )
    parser.add_argument(
        "--skip-llm",
        action="store_true",
        help="Use deterministic behavior scoring only; skip RAG retrieval and GPT explanation.",
    )
    args = parser.parse_args()

    analyze(args.program.lower(), args.trace, args.rebuild_index, args.skip_llm)


if __name__ == "__main__":
    main()
