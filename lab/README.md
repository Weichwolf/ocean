# Rootless ocean development lab

Use a Debian host with access to `/dev/kvm`, a Debian generic AMD64 QCOW2 cloud image, QEMU, cloud-image-utils, VDE, and OpenSSH. The launcher runs QEMU with hardware acceleration and adjusts its niceness by +10. Node disks use QCOW2 overlays over the supplied image. The launcher keeps the image path and SHA-256 digest in the local state and checks them when the lab starts again.

## Start and inspect guests

```sh
make build
OCEAN_LAB_STATE=$(mktemp -d /tmp/ocean-lab.XXXXXX)
OCEAN_LAB_IMAGE="$HOME/.cache/ocean/images/debian-13-generic-amd64.qcow2"

./bin/ocean-lab plan -profile lab/profiles/single-farm-3.yaml
./bin/ocean-lab up -state "$OCEAN_LAB_STATE" -profile lab/profiles/single-farm-3.yaml -image "$OCEAN_LAB_IMAGE"
./bin/ocean-lab status -state "$OCEAN_LAB_STATE"
./bin/ocean-lab ssh -state "$OCEAN_LAB_STATE" farm-1-node-01 -- 'cloud-init status --wait'
```

`status` reports the QEMU process state. Use the guest's cloud-init status for boot readiness. The launcher generates an SSH key for the lab and supplies it through a private NoCloud seed. SSH forwarding is bound to the host loopback address. Use `down` to stop QEMU and the VDE switches while retaining the state and guest disks.

```sh
./bin/ocean-lab down -state "$OCEAN_LAB_STATE"
```

## Profiles and networking

The `single-farm-3` and `scale-16` profiles use the same addresses and hardware identities for the first three nodes. Run `up` with the larger profile in the same state directory to add nodes. The `geo-4x3` and `geo-4x4` profiles work the same way for four farms. Three nodes per farm carry the control-plane role and two carry the gateway role. Each farm also has separate operator and customer clients.

Every farm has its own VDE management, workload, and customer segments. The four-farm profiles add two separate VDE segments for the WAN gateway paths. The operator client attaches to management, and the customer client attaches to the customer segment. The client bootstrap interfaces provide only loopback SSH access. Ocean nodes also have bootstrap egress for package and image downloads. Guests with a management interface resolve their farm's `arm.farm-N.ocean.test` and `id.farm-N.ocean.test` names to `10.231.N.10` using data in the NoCloud seed. This address is reserved for the management virtual IP.

Copy a profile to customize node sizing. Overrides use the guest name printed by `plan`. Start a separate lab directory to adopt changes to an existing guest's declared sizing or interfaces.

```yaml
farms: 1
nodesPerFarm: 3
defaults:
  memoryMiB: 1024
  vcpus: 1
overrides:
  farm-1-node-03:
    memoryMiB: 2048
    vcpus: 2
```

The launcher checks requested memory for new guests against host `MemAvailable` and retains the memory headroom specified by `-reserve-mib`. The default is 2048 MiB. Record measured host headroom, CPU allocation, and disk use for acceptance runs. The lab provisions the guests, addresses, and network segments used by the protocol. Product readiness, quorum, join, and workload results come from the corresponding acceptance checks on a deployed ocean build.
