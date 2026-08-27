"""OCEAN – CPU/GPU-Benchmark. Skaliert die Bevölkerung und misst Tick-Durchsatz."""

import argparse
import copy
import json
import os
import time

import torch

from init_gpu import init_world
from tick_gpu import tick
from world import CONFIG_PATH

SCRATCH = os.path.join(os.path.dirname(__file__), ".bench_config.json")


def sync(device):
    if device.type == "mps":
        torch.mps.synchronize()
    elif device.type == "cuda":
        torch.cuda.synchronize()


def scaled_config(factor):
    with open(CONFIG_PATH) as f:
        cfg = json.load(f)
    total = 0
    for s in cfg["settlements"]:
        s["pop"] = int(s["pop"] * factor)
        s["capacity"] = int(s["capacity"] * factor)
        s["food"] = int(s["food"] * factor)
        total += s["pop"]
    cfg["meta"]["max_npcs"] = total + 200
    with open(SCRATCH, "w") as f:
        json.dump(cfg, f)
    return SCRATCH, total


def measure(world, device, ticks, warmup):
    w = copy.deepcopy(world).to(device)
    for _ in range(warmup):
        tick(w)
    sync(device)
    t0 = time.perf_counter()
    for _ in range(ticks):
        tick(w)
    sync(device)
    return (time.perf_counter() - t0) / ticks


def launch_overhead(device, n=2000):
    """Kosten eines Kernel-Starts, isoliert von der Rechenlast."""
    x = torch.ones(64, device=device)
    for _ in range(50):
        x = x * 1.0001
    sync(device)
    t0 = time.perf_counter()
    for _ in range(n):
        x = x * 1.0001
    sync(device)
    return (time.perf_counter() - t0) / n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scales", default="1,2,4,8")
    ap.add_argument("--ticks", type=int, default=30)
    ap.add_argument("--warmup", type=int, default=5)
    args = ap.parse_args()

    devices = [torch.device("cpu")]
    if torch.backends.mps.is_available():
        devices.append(torch.device("mps"))
    if torch.cuda.is_available():
        devices.append(torch.device("cuda"))

    print(f"torch {torch.__version__}  threads={torch.get_num_threads()}")
    print(f"\n{'':22s}" + "".join(f"{d.type:>12}" for d in devices))
    print(f"  {'Kernel-Start':<20s}"
          + "".join(f"{launch_overhead(d) * 1e6:9.1f} µs" for d in devices))
    for label, fn in [("nonzero → Host", lambda x: x.nonzero()),
                      ("float(x.sum())", lambda x: float(x.sum()))]:
        row = []
        for d in devices:
            x = (torch.rand(4096, device=d) < 0.01).float()
            for _ in range(20):
                fn(x)
            sync(d)
            t0 = time.perf_counter()
            for _ in range(300):
                fn(x)
            sync(d)
            row.append((time.perf_counter() - t0) / 300 * 1e6)
        print(f"  {label:<20s}" + "".join(f"{v:9.1f} µs" for v in row))

    header = f"\n{'NPCs':>7} {'D':>4} {'Zustand':>11}" + \
        "".join(f"{str(d.type):>12}" for d in devices) + f"{'Faktor':>10}"
    print(header)
    print("-" * len(header))

    for factor in [float(x) for x in args.scales.split(",")]:
        path, total = scaled_config(factor)
        world = init_world(config_path=path)
        d_npc = world.layout.D_NPC
        mem = (world.npc.numel() * 4 + world.assign.numel() * 4
               + world.bond_idx.numel() * 8 + world.bond_val.numel() * 4) / 1e6
        times = []
        for d in devices:
            try:
                times.append(measure(world, d, args.ticks, args.warmup))
            except RuntimeError as e:
                print(f"  {total} NPCs auf {d}: {e}")
                times.append(float("nan"))
        cpu_t, best_gpu = times[0], min(times[1:]) if len(times) > 1 else None
        ratio = f"{cpu_t / best_gpu:9.2f}x" if best_gpu else "        –"
        print(f"{total:7d} {d_npc:4d} {mem:9.1f}MB"
              + "".join(f"{t * 1000:9.1f}ms" for t in times) + ratio)

    if os.path.exists(SCRATCH):
        os.remove(SCRATCH)


if __name__ == "__main__":
    main()
