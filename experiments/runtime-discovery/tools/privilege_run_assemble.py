#!/usr/bin/env python3
"""Assembles one privilege-run.sh condition's privilege-<condition>.json and .md from the
per-operation result/errno/denial/proc-state files that script's own bash already wrote
under out/privilege/<condition>/. An operation's own exit code is the supervised CHILD's,
kept apart from the supervisor's own exit status, which reports something else entirely
(whether the supervision worked) and is 0 even when the child it supervised failed. Not meant to be run on its own: privilege-run.sh invokes
it as its last step, passing the condition, the run-as user, the private working directory
and the output directory through KLP_* environment variables.

Usage (as privilege-run.sh's own last step; not meant to be invoked otherwise):
  KLP_CONDITION=... KLP_RUN_AS=... KLP_PRIVDIR=... KLP_OUT=... python3 experiments/runtime-discovery/tools/privilege_run_assemble.py
"""
import json
import os

OPERATIONS = [
    ('bpf_program_load', 'BPF program load'),
    ('tracepoint_attach', 'Tracepoint attach'),
    ('buffer_create_and_read', 'Buffer creation and reading'),
    ('cgroup_id_map', 'cgroup-id map creation'),
]

LOG_EXCERPT_MAX_CHARS = 4000


def read_text(path):
    if not path or not os.path.exists(path):
        return None
    with open(path, encoding='utf-8', errors='replace') as f:
        return f.read().strip()


def read_line(path, default=None):
    v = read_text(path)
    return v if v is not None else default


def read_supervise_record(d):
    path = os.path.join(d, 'supervise.json')
    if not os.path.exists(path):
        return None
    try:
        return json.load(open(path))
    except (OSError, ValueError):
        return None


def operation_record(ops_dir, name):
    d = os.path.join(ops_dir, name)
    result = read_line(os.path.join(d, 'result.txt'), 'unreached')
    condition = read_line(os.path.join(d, 'condition.txt'))
    rec = {'result': result, 'condition_established': condition == 'established' if condition is not None else None,
           'condition_detail': condition}
    if result == 'unreached':
        rec['reason'] = read_line(os.path.join(d, 'reason.txt'), 'unknown')
        return rec
    # The operation's own exit code is the CHILD's, as supervise recorded it - "unknown"
    # when no exit was ever observed, which is not the same fact as an exit code of 0 and is
    # never rendered as one. The SUPERVISOR's own exit status is a separate field: it says
    # whether the supervision worked, and is 0 even for a child that failed.
    exit_code = read_line(os.path.join(d, 'exit_code.txt'))
    if exit_code is not None and exit_code.lstrip('-').isdigit():
        rec['exit_code'] = int(exit_code)
    else:
        rec['exit_code'] = 'not_measured: no exit was recorded for the child'
    exit_signal = read_line(os.path.join(d, 'exit_signal.txt'))
    if exit_signal not in (None, '-'):
        rec['exit_signal'] = exit_signal
    child_status = read_line(os.path.join(d, 'child_status.txt'))
    if child_status is not None:
        rec['child_status'] = child_status
    supervisor_exit = read_line(os.path.join(d, 'supervisor_exit_code.txt'))
    rec['supervisor_exit_code'] = int(supervisor_exit) if supervisor_exit is not None and supervisor_exit.lstrip('-').isdigit() else None
    stage = read_line(os.path.join(d, 'stage.txt'))
    if stage is not None:
        rec['stage'] = stage
    note = read_line(os.path.join(d, 'note.txt'))
    if note is not None:
        rec['note'] = note
    if result == 'failure':
        rec['errno'] = read_line(os.path.join(d, 'errno.txt'), 'unknown')
        rec['denying_layer'] = read_line(os.path.join(d, 'denial.txt'), 'unknown')
    # CapEff/attr/current/limits come from supervise's own record - the actually exec'd
    # child's real /proc state, captured by supervise itself before this script ever runs -
    # rather than from a separate bash-side /proc read of a possibly different process.
    sup = read_supervise_record(d)
    if sup is not None:
        rec['cap_eff'] = sup.get('cap_eff') or 'not_measured: not captured'
        rec['attr_current'] = sup.get('attr_current') or 'not_measured: not captured'
        rec['limits'] = sup.get('limits') or 'not_measured: not captured'
        rec['real_uid'] = sup.get('real_uid')
        rec['effective_uid'] = sup.get('effective_uid')
        rec['actual_exe'] = sup.get('actual_exe')
        rec['cgroup_method'] = sup.get('cgroup_method')
    else:
        rec['cap_eff'] = 'not_measured: no supervise record'
        rec['attr_current'] = 'not_measured: no supervise record'
        rec['limits'] = 'not_measured: no supervise record'
    log = read_text(os.path.join(d, 'log.txt'))
    if log is not None:
        rec['log_excerpt'] = log[-LOG_EXCERPT_MAX_CHARS:]
    return rec


def main():
    condition = os.environ['KLP_CONDITION']
    run_as = os.environ['KLP_RUN_AS']
    privdir = os.environ['KLP_PRIVDIR']
    out_dir = os.environ['KLP_OUT']
    facts = os.path.join(privdir, 'facts')
    ops = os.path.join(privdir, 'ops')

    record = {
        'condition': condition,
        'run_as': run_as,
        'run_as_uid': os.environ.get('KLP_RUN_AS_UID', ''),
        'capabilities_requested': read_line(os.path.join(facts, 'capabilities_requested.txt'), ''),
        'binaries': {
            'system_bpftrace_sha256': read_line(os.path.join(facts, 'system_bpftrace_sha256.txt')),
            'private_bpftrace_sha256': read_line(os.path.join(facts, 'private_bpftrace_sha256.txt')),
            'private_runtime_events_sha256': read_line(os.path.join(facts, 'private_runtime_events_sha256.txt')),
        },
        'sysctls': {
            'kernel.unprivileged_bpf_disabled': read_line(os.path.join(facts, 'sysctl.kernel.unprivileged_bpf_disabled.txt')),
            'kernel.perf_event_paranoid': read_line(os.path.join(facts, 'sysctl.kernel.perf_event_paranoid.txt')),
            'kernel.yama.ptrace_scope': read_line(os.path.join(facts, 'sysctl.kernel.yama.ptrace_scope.txt')),
        },
        'lockdown': read_line(os.path.join(facts, 'lockdown.txt')),
        'operations': {name: operation_record(ops, name) for name, _ in OPERATIONS},
    }

    json.dump(record, open(os.path.join(out_dir, f'privilege-{condition}.json'), 'w'), indent=1, sort_keys=True)

    lines = [f'# Privilege condition: {condition}\n',
             f'Run as: `{run_as}` (uid {record["run_as_uid"] or "?"})  \n'
             f'Capabilities requested: `{record["capabilities_requested"] or "(none)"}`\n',
             '## Sysctls and lockdown\n',
             '| sysctl | value |', '| --- | --- |']
    for k, v in record['sysctls'].items():
        lines.append(f'| `{k}` | {v} |')
    lines.append(f'| `/sys/kernel/security/lockdown` | {record["lockdown"]} |')
    lines.append('\n## Binary identity (sha256)\n')
    lines.append('| binary | sha256 |'); lines.append('| --- | --- |')
    for k, v in record['binaries'].items():
        lines.append(f'| {k} | `{v}` |')
    lines.append('\n## Operations\n')
    lines.append('| operation | condition established | result | stage | errno | denying layer | child exit | supervisor exit |')
    lines.append('| --- | --- | --- | --- | --- | --- | --- | --- |')
    for name, label in OPERATIONS:
        rec = record['operations'][name]
        cond = 'yes' if rec.get('condition_established') else ('no' if rec.get('condition_established') is False else '-')
        child = rec.get('exit_code', '-')
        if rec.get('exit_signal'):
            child = f"{child} ({rec['exit_signal']})"
        lines.append(f"| {label} | {cond} | {rec['result']} | {rec.get('stage', '-')} | {rec.get('errno', '-')} | {rec.get('denying_layer', '-')} | {child} | {rec.get('supervisor_exit_code', '-')} |")
    for name, label in OPERATIONS:
        rec = record['operations'][name]
        if rec['result'] == 'unreached':
            lines.append(f"\n### {label}\n\nUnreached: {rec.get('reason')}\n")
            continue
        lines.append(f"\n### {label}\n")
        if rec.get('condition_established') is False:
            lines.append(f"- **Condition not established**: {rec.get('condition_detail')}")
        lines.append(f"- Actual exe: `{rec.get('actual_exe')}`  (real uid {rec.get('real_uid')}, effective uid {rec.get('effective_uid')})")
        lines.append(f"- CapEff: `{rec.get('cap_eff')}`")
        lines.append(f"- LSM attr/current: `{rec.get('attr_current')}`")
        lines.append(f"- cgroup start method: `{rec.get('cgroup_method')}`")
        if rec.get('note'):
            lines.append(f"- Note: {rec['note']}")
        lines.append(f"- Child exit: `{rec.get('exit_code')}`"
                     + (f" (signal `{rec['exit_signal']}`)" if rec.get('exit_signal') else '')
                     + f", supervise status `{rec.get('child_status')}`; supervisor's own exit `{rec.get('supervisor_exit_code')}`")

    open(os.path.join(out_dir, f'privilege-{condition}.md'), 'w').write('\n'.join(lines) + '\n')
    print(f'wrote {out_dir}/privilege-{condition}.json and .md')


if __name__ == '__main__':
    main()
