#!/usr/bin/env python3
"""Generate deploy/docker/sensor-seccomp.json, the Sensor container's
distributed seccomp allow-list (layer (a) of the Sensor's containment).

This takes moby/profiles' Docker default profile — a much larger allow-list
suited to an arbitrary container — and mechanically removes everything the
Sensor's observer and parser processes have no legitimate use for, per a
fixed exclusion list. It never hand-edits the upstream file: every change
this script makes is one of a small number of named transformations, each
checked afterward, so the diff from "what Docker ships" to "what the Sensor
ships" is auditable and re-derivable from this script alone.

Usage:
    python3 scripts/gen_sensor_seccomp_profile.py [--input FILE] [--check-only]

Without --input, fetches the upstream profile from GitHub. --input reads a
local copy instead (e.g. scripts/testdata/moby-seccomp-default.json, a
frozen fixture this script's own test regenerates against), for
reproducibility without depending on network access. --check-only runs the
same fetch/transform/verify pipeline and diffs the result against the
checked-in output instead of writing it, for CI or a pre-commit check.

Output:
    deploy/docker/sensor-seccomp.json       the generated profile
    deploy/docker/sensor-seccomp.provenance.json
        the exact source URL (or --input path) and the SHA-256 of the
        input bytes this run consumed, plus this script's own path — never
        embedded in the profile itself, so nothing here risks confusing
        Docker's own seccomp JSON loader with an unrecognized field.
"""

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

UPSTREAM_URL = "https://raw.githubusercontent.com/moby/profiles/main/seccomp/default.json"

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_PROFILE = REPO_ROOT / "deploy" / "docker" / "sensor-seccomp.json"
OUTPUT_PROVENANCE = REPO_ROOT / "deploy" / "docker" / "sensor-seccomp.provenance.json"

# Architectures the Sensor's file capability, seccomp, and Landlock support
# targets (design decision: x86_64 and aarch64 only).
ARCH_KEEP = {"SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"}

# Names removed unconditionally, wherever they appear in the upstream
# profile's syscalls entries. socketpair is handled separately (constrained
# by argument, not removed outright); ioctl is removed with no replacement
# (an empty allow-list, per the design decision to allow no ioctl at all).
EXCLUDE_NAMES = frozenset(
    [
        # Other processes' connections, memory, and fds.
        "ptrace",
        "process_vm_readv",
        "process_vm_writev",
        "pidfd_getfd",
        "kcmp",
        "process_madvise",
        # File handles: open_by_handle_at bypasses openat's own flag checks
        # once CAP_DAC_READ_SEARCH is granted (which the observer holds).
        "open_by_handle_at",
        "name_to_handle_at",
        # Communication endpoints. sendmsg/recvmsg stay (fd-passing IPC).
        "socket",
        "connect",
        "bind",
        "listen",
        "accept",
        "accept4",
        "sendto",
        "recvfrom",
        "sendmmsg",
        "recvmmsg",
        "shutdown",
        "getsockopt",
        "setsockopt",
        "getsockname",
        "getpeername",
        # Multiplexed syscalls and compat ABIs — archMap below removes the
        # 32-bit/compat architectures these exist for in the first place.
        "socketcall",
        "ipc",
        # perf_event_open: eBPF here only ever uses bpf_link, never perf
        # events (bpf itself, gated on CAP_BPF upstream, stays).
        "perf_event_open",
        # Asynchronous I/O this Sensor never uses. (io_uring_* syscalls are
        # verified absent from the upstream profile already; see
        # _verify_io_uring_absent.)
        "ioctl",
        # Filesystem mutation: rename/link/symlink/unlink/mkdir/mknod
        # families, rmdir, chmod/chown families, path-based truncate
        # (ftruncate/ftruncate64 are NOT excluded: the observer legitimately
        # calls ftruncate on its already-open evidence fd to keep the file's
        # length in sync with each rewrite, and that is an fd operation, not
        # a new path resolution), utime family, setxattr/removexattr
        # families.
        "rename",
        "renameat",
        "renameat2",
        "link",
        "linkat",
        "symlink",
        "symlinkat",
        "unlink",
        "unlinkat",
        "mkdir",
        "mkdirat",
        "rmdir",
        "mknod",
        "mknodat",
        "chmod",
        "fchmod",
        "fchmodat",
        "fchmodat2",
        "chown",
        "chown32",
        "fchown",
        "fchown32",
        "fchownat",
        "lchown",
        "lchown32",
        "truncate",
        "truncate64",
        "utime",
        "utimes",
        "utimensat",
        "utimensat_time64",
        "futimesat",
        "setxattr",
        "setxattrat",
        "fsetxattr",
        "lsetxattr",
        "removexattr",
        "removexattrat",
        "fremovexattr",
        "lremovexattr",
    ]
)

# Names whose presence anywhere in the upstream profile this script has
# never seen and does not know how to handle; if a future upstream update
# adds one, generation must fail loudly rather than ship a profile that
# silently allows an io_uring-based bypass of the socket/file restrictions
# above.
IO_URING_NAMES = frozenset(["io_uring_setup", "io_uring_enter", "io_uring_register"])

# socketpair's replacement entry: allow only
# socketpair(AF_UNIX, SOCK_SEQPACKET | <any of CLOEXEC/NONBLOCK>, 0).
# AF_UNIX=1, SOCK_SEQPACKET=5 (both stable, architecture-independent Linux
# UAPI values). The mask 0xf is SOCK_TYPE_MASK: the low 4 bits of the type
# argument carry the socket type, the upper bits carry SOCK_CLOEXEC/
# SOCK_NONBLOCK, which are allowed regardless (observer creates it with
# SOCK_CLOEXEC per the design's startup order).
#
# For SCMP_CMP_MASKED_EQ, the condition this whole toolchain (Docker's own
# JSON loader -> libcontainer's configs.Arg -> libseccomp-golang's
# MakeCondition -> libseccomp's own seccomp_rule_add) ends up building is
# (argument & value) == valueTwo, i.e. "value" carries the mask and
# "valueTwo" carries the value to compare against after masking — not the
# other way around. Confirmed against libseccomp's own db.c
# (chain[arg_num].mask = arg_data.datum_a; .datum = arg_data.datum_b for
# SCMP_CMP_MASKED_EQ) and cross-checked against this exact upstream
# profile's own existing use of the operator (the "clone" syscall rules,
# which pass only "value" — no "valueTwo" — to mean "(flags & value) == 0",
# i.e. value is unambiguously the mask there). So: value=SOCK_TYPE_MASK
# (the mask), valueTwo=SOCK_SEQPACKET (what the masked type must equal).
AF_UNIX = 1
SOCK_SEQPACKET = 5
SOCK_TYPE_MASK = 0xF

SOCKETPAIR_ENTRY = {
    "names": ["socketpair"],
    "action": "SCMP_ACT_ALLOW",
    "args": [
        {"index": 0, "value": AF_UNIX, "op": "SCMP_CMP_EQ"},
        {
            "index": 1,
            "value": SOCK_TYPE_MASK,
            "valueTwo": SOCK_SEQPACKET,
            "op": "SCMP_CMP_MASKED_EQ",
        },
    ],
}


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=30) as resp:
        return resp.read()


def transform(raw: bytes) -> dict:
    profile = json.loads(raw)

    all_names_before = set()
    for entry in profile["syscalls"]:
        all_names_before.update(entry["names"])
    _verify_io_uring_absent(all_names_before)

    profile["archMap"] = _filtered_arch_map(profile["archMap"])

    new_syscalls = []
    saw_socketpair = False
    for entry in profile["syscalls"]:
        names = entry["names"]
        if "socketpair" in names:
            saw_socketpair = True
            names = [n for n in names if n != "socketpair"]
        names = [n for n in names if n not in EXCLUDE_NAMES]
        if not names:
            continue
        entry = dict(entry)
        entry["names"] = names
        new_syscalls.append(entry)
    if not saw_socketpair:
        raise SystemExit(
            "gen_sensor_seccomp_profile: upstream profile no longer lists "
            "socketpair; the replacement entry below would silently add a "
            "new allowance instead of narrowing an existing one. Update "
            "this script's assumptions before proceeding."
        )
    new_syscalls.append(dict(SOCKETPAIR_ENTRY))
    profile["syscalls"] = new_syscalls

    _verify(profile)
    return profile


def _filtered_arch_map(arch_map: list) -> list:
    kept = []
    for entry in arch_map:
        if entry.get("architecture") not in ARCH_KEEP:
            continue
        entry = dict(entry)
        entry.pop("subArchitectures", None)
        kept.append(entry)
    got = {e["architecture"] for e in kept}
    if got != ARCH_KEEP:
        raise SystemExit(
            f"gen_sensor_seccomp_profile: expected archMap to contain exactly "
            f"{sorted(ARCH_KEEP)}, got {sorted(got)}"
        )
    return kept


def _verify_io_uring_absent(all_names: set) -> None:
    present = all_names & IO_URING_NAMES
    if present:
        raise SystemExit(
            "gen_sensor_seccomp_profile: upstream profile now allows "
            f"{sorted(present)}; this script assumed io_uring is absent "
            "(the design's non-fatal-if-true assumption) and needs an "
            "explicit exclusion added, not silent inheritance."
        )


def _verify(profile: dict) -> None:
    all_names = set()
    for entry in profile["syscalls"]:
        all_names.update(entry["names"])

    excluded_present = all_names & EXCLUDE_NAMES
    if excluded_present:
        raise SystemExit(
            f"gen_sensor_seccomp_profile: excluded syscalls still present: {sorted(excluded_present)}"
        )
    if "socketcall" in all_names or "ipc" in all_names:
        raise SystemExit("gen_sensor_seccomp_profile: multiplexed syscall(s) still present")
    _verify_io_uring_absent(all_names)

    arches = {e["architecture"] for e in profile["archMap"]}
    if arches != ARCH_KEEP:
        raise SystemExit(f"gen_sensor_seccomp_profile: archMap mismatch: {sorted(arches)}")
    for e in profile["archMap"]:
        if "subArchitectures" in e:
            raise SystemExit(
                f"gen_sensor_seccomp_profile: {e['architecture']} still has subArchitectures"
            )

    socketpair_entries = [e for e in profile["syscalls"] if "socketpair" in e["names"]]
    if len(socketpair_entries) != 1:
        raise SystemExit(
            f"gen_sensor_seccomp_profile: expected exactly one socketpair entry, found {len(socketpair_entries)}"
        )
    if socketpair_entries[0] != SOCKETPAIR_ENTRY:
        raise SystemExit("gen_sensor_seccomp_profile: socketpair entry does not match the expected argument condition")

    if "ioctl" in all_names:
        raise SystemExit("gen_sensor_seccomp_profile: ioctl still present (allow-list must be empty)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", type=Path, help="local upstream profile JSON, instead of fetching")
    ap.add_argument("--check-only", action="store_true", help="verify the checked-in output matches; do not write")
    args = ap.parse_args()

    if args.input:
        raw = args.input.read_bytes()
        source = str(args.input)
    else:
        raw = fetch(UPSTREAM_URL)
        source = UPSTREAM_URL

    digest = hashlib.sha256(raw).hexdigest()
    profile = transform(raw)
    profile_json = json.dumps(profile, indent=2, sort_keys=False) + "\n"

    provenance = {
        "source": source,
        "source_sha256": digest,
        "generator": "scripts/gen_sensor_seccomp_profile.py",
    }
    provenance_json = json.dumps(provenance, indent=2, sort_keys=True) + "\n"

    if args.check_only:
        current = OUTPUT_PROFILE.read_text() if OUTPUT_PROFILE.exists() else ""
        if current != profile_json:
            sys.stderr.write(
                f"{OUTPUT_PROFILE} is out of date with the current input; "
                "run without --check-only to regenerate.\n"
            )
            return 1
        print(f"OK: {OUTPUT_PROFILE} matches (source sha256 {digest})")
        return 0

    OUTPUT_PROFILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PROFILE.write_text(profile_json)
    OUTPUT_PROVENANCE.write_text(provenance_json)
    print(f"wrote {OUTPUT_PROFILE}")
    print(f"wrote {OUTPUT_PROVENANCE} (source sha256 {digest})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
