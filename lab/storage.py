#!/usr/bin/env python3
"""Bootstrap the dedicated three-host Debian Ceph storage cluster in the KVM lab."""

import argparse
import json
import os
import shlex
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import UUID, uuid4

sys.dont_write_bytecode = True
from region import eventually, ssh, upload

NODES = {f"farm-1-node-{index:02d}": f"10.231.1.{index + 10}" for index in (7, 8, 9)}
FIRST = next(iter(NODES))
POOL = "ocean"
DEVICE = "/dev/disk/by-id/virtio-ocean-storage"
FILES = "/var/lib/ocean-ceph"
KEYS = ("admin.key", "mon.key", "osd-bootstrap.key")
INSTALL = ("sudo apt-get update -qq && sudo env DEBIAN_FRONTEND=noninteractive apt-get install "
           "-y -qq --no-install-recommends ceph-mon ceph-osd ceph-volume ceph-mgr lvm2 gdisk && sudo apt-get clean")


def private_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def boot_material(state):
    directory = state / "storage-pki"
    directory.mkdir(mode=0o700, exist_ok=True)
    fsid_path = directory / "cluster-id"
    if not fsid_path.exists():
        private_file(fsid_path, str(uuid4()).encode())
    fsid = str(UUID(fsid_path.read_text()))
    ssh(state, FIRST, f"""set -eu
sudo install -d -m 0750 -o ceph -g ceph {FILES}
if ! sudo test -s {FILES}/admin.key; then
    sudo ceph-authtool --create-keyring {FILES}/admin.key --gen-key -n client.admin \\
        --cap mon 'allow *' --cap osd 'allow *' --cap mds 'allow *' --cap mgr 'allow *'
fi
if ! sudo test -s {FILES}/osd-bootstrap.key; then
    sudo ceph-authtool --create-keyring {FILES}/osd-bootstrap.key --gen-key -n client.bootstrap-osd --cap mon 'profile bootstrap-osd'
fi
if ! sudo test -s {FILES}/mon.key; then
    sudo ceph-authtool --create-keyring {FILES}/mon.key --gen-key -n mon. --cap mon 'allow *'
fi
sudo ceph-authtool {FILES}/mon.key --import-keyring {FILES}/admin.key
sudo ceph-authtool {FILES}/mon.key --import-keyring {FILES}/osd-bootstrap.key
sudo chmod 0600 {FILES}/admin.key {FILES}/mon.key {FILES}/osd-bootstrap.key
sudo chown ceph:ceph {FILES}/admin.key {FILES}/mon.key {FILES}/osd-bootstrap.key
if ! sudo test -s {FILES}/monmap; then
    sudo monmaptool --create --clobber --fsid {fsid} {FILES}/monmap.pending
    {'; '.join(f"sudo monmaptool --addv {name} '[v2:{ip}:3300]' {FILES}/monmap.pending" for name, ip in NODES.items())}
    sudo chown ceph:ceph {FILES}/monmap.pending
    sudo mv {FILES}/monmap.pending {FILES}/monmap
fi
""")
    material = {}
    for name in (*KEYS, "monmap"):
        path = directory / name
        data = ssh(state, FIRST, f"sudo cat {FILES}/{name}")
        if not path.exists():
            private_file(path, data)
        elif path.read_bytes() != data:
            raise RuntimeError(f"the existing cluster setup differs from {name}")
        material[name] = data
    addresses = ",".join(f"[v2:{address}:3300]" for address in NODES.values())
    machines = json.loads((state / "state.json").read_text())["machines"]
    storage_ram = min(machine["guest"]["resources"]["memoryMiB"] for machine in machines
                      if machine["guest"]["name"] in NODES)
    memory_target = min(1024, storage_ram // 2) << 20
    material["ceph.conf"] = f"""[global]
fsid = {fsid}
mon initial members = {','.join(NODES)}
mon host = {addresses}
public network = 10.231.1.0/24
cluster network = 10.231.1.0/24
ms bind msgr1 = false
ms cluster mode = secure
ms service mode = secure
ms client mode = secure
auth cluster required = cephx
auth service required = cephx
auth client required = cephx
osd pool default size = 3
osd pool default min size = 2
osd crush chooseleaf type = 1
osd memory target = {memory_target}
mon clock drift allowed = 0.1
mon warn on pool no redundancy = true
""".encode()
    return fsid, material


def prepare_monitor(state, node, material):
    upload(state, node, material, FILES, owner="ceph")
    ssh(state, node, f"""set -eu
sudo install -D -m 0644 {FILES}/ceph.conf /etc/ceph/ceph.conf
sudo install -D -o ceph -g ceph -m 0600 {FILES}/admin.key /etc/ceph/ceph.client.admin.keyring
sudo install -D -o ceph -g ceph -m 0600 {FILES}/osd-bootstrap.key /var/lib/ceph/bootstrap-osd/ceph.keyring
sudo install -d -o ceph -g ceph /var/lib/ceph/mon/ceph-{node}
if ! sudo test -e /var/lib/ceph/mon/ceph-{node}/store.db/CURRENT; then
    sudo -u ceph ceph-mon --mkfs -i {node} --monmap {FILES}/monmap --keyring {FILES}/mon.key
fi
sudo systemctl reset-failed ceph-mon@{node}.service || true
sudo systemctl enable --now ceph-mon@{node}.service
""")


def command(state, args, node=FIRST):
    return ssh(state, node, shlex.join(["sudo", *args]))


def quorum(state):
    report = json.loads(command(state, ["ceph", "--connect-timeout", "5", "--format", "json", "quorum_status"]))
    if set(report["quorum_names"]) != set(NODES):
        raise RuntimeError("the three dedicated monitors have not formed a quorum")
    return report["quorum_names"]


def prepare_manager(state, node):
    ssh(state, node, f"""set -eu
path=/var/lib/ceph/mgr/ceph-{node}
sudo install -d -m 0750 -o ceph -g ceph "$path"
if ! sudo test -s "$path/keyring"; then
    sudo ceph auth get-or-create mgr.{node} mon 'profile mgr' osd 'allow *' mds 'allow *' -o "$path/keyring"
    sudo chown ceph:ceph "$path/keyring"
    sudo chmod 0600 "$path/keyring"
fi
sudo systemctl enable --now ceph-mgr@{node}.service
""")


def prepare_osd(state, node, fsid):
    script = f"""set -eu
disk=$(readlink -f {DEVICE})
test -b "$disk"
test "$(lsblk -dnro SERIAL "$disk")" = ocean-storage
test "$(lsblk -rno TYPE "$disk")" = disk
test "$(sudo blockdev --getsize64 "$disk")" -eq 8589934592
label=$(sudo ceph-volume raw list "$disk" --format json)
if test "$label" = '{{}}'; then
    test -z "$(sudo wipefs -n --noheadings "$disk")"
    sudo ceph-volume raw prepare --bluestore --data "$disk"
    label=$(sudo ceph-volume raw list "$disk" --format json)
fi
osd=$(printf '%s' "$label" | python3 -c 'import json,sys; data=list(json.load(sys.stdin).values()); assert len(data)==1 and data[0]["ceph_fsid"]==sys.argv[1]; print(data[0]["osd_id"])' {fsid})
sudo install -d "/etc/systemd/system/ceph-osd@$osd.service.d"
printf '%s\\n' '[Service]' 'ExecStartPre=/usr/sbin/ceph-volume raw activate --device {DEVICE} --no-systemd --no-tmpfs' | sudo tee "/etc/systemd/system/ceph-osd@$osd.service.d/ocean.conf" >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable --now "ceph-osd@$osd.service"
printf 'OSD %s on %s\\n' "$osd" "$disk"
"""
    result = ssh(state, node, script).decode().splitlines()
    return result[-1]


def pool_ready(state):
    report = json.loads(command(state, ["ceph", "--connect-timeout", "5", "-s", "-f", "json"]))
    osds = report["osdmap"]
    if any(osds[key] != 3 for key in ("num_osds", "num_up_osds", "num_in_osds")):
        raise RuntimeError("Ceph has fewer than three active data disks")
    for item in report["pgmap"].get("pgs_by_state", []):
        if item["state_name"] != "active+clean":
            raise RuntimeError("placement groups have not reached three clean replicas")
    if not report["pgmap"]["num_pgs"]:
        raise RuntimeError("Ceph has no active placement groups")
    return report


def prepare(state, install):
    with ThreadPoolExecutor(max_workers=3) as pool:
        for node in NODES:
            eventually(lambda: ssh(state, node, f"test -b {DEVICE}"), 60)
        if install:
            list(pool.map(lambda node: ssh(state, node, INSTALL), NODES))
        fsid, material = boot_material(state)
        list(pool.map(lambda node: prepare_monitor(state, node, material), NODES))
        peers = eventually(lambda: quorum(state), 80)
        list(pool.map(lambda node: prepare_manager(state, node), NODES))
        osds = list(pool.map(lambda node: prepare_osd(state, node, fsid), NODES))
    pools = json.loads(command(state, ["ceph", "osd", "pool", "ls", "-f", "json"]))
    if POOL not in pools:
        command(state, ["ceph", "osd", "pool", "create", POOL, "16"])
    command(state, ["rbd", "pool", "init", POOL])
    status = eventually(lambda: pool_ready(state), 110)
    replication = {}
    for prop in ("size", "min_size", "crush_rule"):
        replication.update(json.loads(command(state, ["ceph", "osd", "pool", "get", POOL, prop, "-f", "json"])))
    if replication.get("size") != 3 or replication.get("min_size") != 2 or replication.get("crush_rule") != "replicated_rule":
        raise RuntimeError("the storage pool does not have the required replication policy")
    rule = json.loads(command(state, ["ceph", "osd", "crush", "rule", "dump", "replicated_rule", "-f", "json"]))
    if not any(step.get("type") == "host" for step in rule["steps"]):
        raise RuntimeError("the Ceph replication rule does not distribute replicas across hosts")
    evidence = state / "evidence"
    evidence.mkdir(mode=0o700, exist_ok=True)
    (evidence / "ceph-cluster.json").write_text(json.dumps({"fsid": fsid, "monitorQuorum": peers, "osds": osds,
                                                            "replication": replication, "failureDomain": "host",
                                                            "placementGroups": status["pgmap"]["num_pgs"]}, indent=2) + "\n")
    print("Three Ceph monitors and three replicated OSDs are available on separate KVM guests.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--packages-installed", action="store_true", help="use packages already installed on the dedicated storage guests")
    args = parser.parse_args()
    prepare(args.state.resolve(), not args.packages_installed)


if __name__ == "__main__":
    main()
