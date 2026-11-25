#!/usr/bin/env python3
"""Measure running Debian/KVM guests, their VDE attachments, and the regional quorum."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from region import NODES, OPERATOR, ROOT, etcdctl, run, ssh

LAB = ROOT / "bin/ocean-lab"
PROFILES = ROOT / "lab/profiles"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def meminfo(path):
    return {parts[0].rstrip(":"): int(parts[1])
            for line in path.read_text().splitlines() if len(parts := line.split()) == 3 and parts[2] == "kB"}


def qemu_processes(state):
    processes = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            line = (entry / "cmdline").read_bytes().split(b"\0")
            command = [value.decode() for value in line if value]
            if not command or "qemu-system-x86_64" not in command[0] or "-qmp" not in command:
                continue
            socket = command[command.index("-qmp")+1].removeprefix("unix:").split(",server=", 1)[0]
            monitor = Path(socket)
            if monitor.parent.parent != state / "nodes":
                continue
            processes[monitor.parent.name] = (int(entry.name), command)
        except (OSError, ValueError, IndexError, UnicodeError):
            continue
    return processes


def inspect_guest(state, guest, process):
    name = guest["name"]
    pid, command = process
    identifiers = {"-accel": "kvm", "-m": str(guest["resources"]["memoryMiB"]), "-smp": str(guest["resources"]["vcpus"])}
    require(all(option in command and command[command.index(option)+1] == value for option, value in identifiers.items()),
            f"{name} QEMU did not use the declared KVM resource profile")
    require(os.getuid() != 0 and Path(f"/proc/{pid}").stat().st_uid == os.getuid() and
            os.getpriority(os.PRIO_PROCESS, pid) == 10, f"{name} did not run rootlessly at nice +10")
    network = [command[index+1] for index, value in enumerate(command[:-1]) if value == "-netdev"]
    for index, interface in enumerate(guest["interfaces"]):
        socket = state / "networks" / interface["segment"] / "data"
        require(any(value.startswith(f"vde,id=net{index},sock=") and str(socket) in value for value in network) and
                any("mac="+interface["mac"] in device for device in command),
                f"{name} did not attach {interface['name']} to its planned VDE segment")
    inside = json.loads(ssh(state, name, """python3 - <<'PY'
import json,os,subprocess
total=next(int(row.split()[1]) for row in open('/proc/meminfo') if row.startswith('MemTotal:'))
links=json.loads(subprocess.check_output(['ip','-j','link']))
print(json.dumps({'cpus':os.cpu_count(),'memoryKiB':total,'links':{row['ifname']:row.get('address') for row in links}}))
PY"""))
    memory_mib = guest["resources"]["memoryMiB"]
    require(inside["cpus"] == guest["resources"]["vcpus"] and memory_mib*0.75 <= inside["memoryKiB"]/1024 <= memory_mib,
            f"{name} did not expose the configured CPU and memory to Debian")
    for interface in guest["interfaces"]:
        require(inside["links"].get(interface["name"]) == interface["mac"], f"{name} did not bind its planned guest interface")
    rss = next(int(line.split()[1]) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if line.startswith("VmRSS:"))
    return {"node": name, "roles": guest["roles"], "qemuPID": pid, "nice": 10, "accelerator": "kvm",
            "allocatedRAMMiB": memory_mib, "guestMemoryKiB": inside["memoryKiB"], "guestVCPUs": inside["cpus"],
            "qemuResidentKiB": rss, "attachments": guest["interfaces"]}


def verify(state, profile, disk_budget_gib=64):
    planned = json.loads(run([LAB, "plan", "-profile", PROFILES / f"{profile}.yaml"]))["guests"]
    live = json.loads(run([LAB, "status", "-state", state]))
    observed = {item["guest"]["name"]: item for item in live}
    processes = qemu_processes(state)
    for guest in planned:
        name = guest["name"]
        row = observed.get(name)
        require(row and row["running"] and row["guest"] == guest and name in processes,
                f"{name} is absent or differs from the declared lab topology")
    with ThreadPoolExecutor(max_workers=4) as pool:
        guests = list(pool.map(lambda guest: inspect_guest(state, guest, processes[guest["name"]]), planned))
    health = json.loads(ssh(state, OPERATOR, etcdctl("endpoint health --cluster -w json")))
    members = json.loads(ssh(state, OPERATOR, etcdctl("member list -w json")))["members"]
    voters = sorted(member["name"] for member in members if not member.get("isLearner"))
    require(voters == sorted(NODES) and len(health) == 3 and all(endpoint["health"] for endpoint in health),
            "the three declared voters do not form a healthy management quorum")
    if disk_budget_gib <= 0:
        raise RuntimeError("the lab disk budget must be positive")
    allocated_disk = sum(file.lstat().st_blocks * 512 for file in state.rglob("*") if file.is_file() and not file.is_symlink())
    require(allocated_disk <= disk_budget_gib << 30, "the measured lab disk use exceeded the declared budget")
    host = meminfo(Path("/proc/meminfo"))
    limit = host["MemTotal"]//1024 - 2048
    allocation = sum(item["allocatedRAMMiB"] for item in guests)
    require(allocation <= limit, "the planned guest allocation exceeds the host memory budget")
    if profile == "scale-16":
        require(host["MemAvailable"] >= 2048 * 1024, "the scale lab left less than 2 GiB of host memory headroom")
    node_allocations = {(item["allocatedRAMMiB"], item["guestVCPUs"]) for item in guests if "-node-" in item["node"]}
    if profile == "storage-ha":
        require(len(node_allocations) >= 2, "the mixed topology must exercise different CPU and memory profiles")
    return {"profile": profile, "guests": guests, "quorumVoters": voters, "allocatedRAMMiB": allocation,
            "hostMemoryBudgetMiB": limit, "hostAvailableMemoryKiB": host["MemAvailable"],
            "sumQEMUResidentKiB": sum(item["qemuResidentKiB"] for item in guests),
            "diskAllocatedBytes": allocated_disk, "diskBudgetBytes": disk_budget_gib << 30,
            "diskAvailableBytes": os.statvfs(state).f_bavail*os.statvfs(state).f_frsize}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--profile", required=True, choices=("single-farm-3", "storage-ha", "scale-16"))
    parser.add_argument("--disk-budget-gib", type=int, default=64)
    args = parser.parse_args()
    state = args.state.resolve()
    result = verify(state, args.profile, args.disk_budget_gib)
    out = state / "evidence"
    out.mkdir(mode=0o700, exist_ok=True)
    name = {"single-farm-3": "small-topology.json", "storage-ha": "mixed-topology.json", "scale-16": "scale-topology.json"}[args.profile]
    (out / name).write_text(json.dumps(result, indent=2)+"\n")
    print(f"Measured {len(result['guests'])} KVM guests with the declared profiles and a healthy three-voter quorum.")


if __name__ == "__main__":
    main()
