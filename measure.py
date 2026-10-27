"""Memory counters only: no browsing data, files, addresses or credentials."""
from pathlib import Path


def read(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def snapshot():
    total = 0
    if Path('/proc').exists():
        for entry in Path('/proc').iterdir():
            if entry.name.isdigit():
                for line in (read(entry / 'status') or '').splitlines():
                    if line.startswith('VmRSS:'):
                        total += int(line.split()[1]) * 1024
    return {'cgroup_current_bytes': read('/sys/fs/cgroup/memory.current'),
            'cgroup_peak_bytes': read('/sys/fs/cgroup/memory.peak'),
            'cgroup_limit_bytes': read('/sys/fs/cgroup/memory.max'),
            'cgroup_cpu_limit': read('/sys/fs/cgroup/cpu.max'),
            'cgroup_memory_events': read('/sys/fs/cgroup/memory.events'),
            'sum_process_rss_bytes': total}
