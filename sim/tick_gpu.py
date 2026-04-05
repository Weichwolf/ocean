"""
OCEAN – Generischer NPC/World Simulator. GPU-Tick.
"""

import torch
import numpy as np
import json
import time
import sys
import os

from world import (
    DEVICE, POILayout, WorldState,
    load_config, assign_roles, compute_social_embedding,
    compute_affinity_matrix,
)
from init_gpu import init_world, print_world_summary


def tick(world: WorldState) -> dict:
    """Ein Wochen-Tick. Config-getrieben."""
    L = world.layout
    S = world.sim
    dev = world.npc.device
    N = world.npc.shape[0]
    n_poi = world.poi.shape[0]
    alive = world.alive_mask
    si = world.season_idx

    summary = {"tick": world.tick + 1, "births": 0, "deaths": 0,
               "migrations": 0, "dead_names": [], "born_names": []}

    food_mult = S.season_food[si].to(dev)
    uv = S.season_uv[si].to(dev)
    disease_mult = S.season_disease[si].to(dev)

    # ── 1. RESSOURCEN ──────────────────────────────────
    pop_per_poi = (world.assign * alive.float().unsqueeze(1)).sum(dim=0)
    food_supply = world.poi[:, POILayout.FOOD] * food_mult * (0.85 + torch.rand(n_poi, device=dev) * 0.30)
    food_demand = pop_per_poi * 14000
    surplus_days = (food_supply - food_demand) / (pop_per_poi.clamp(min=1) * 2000)

    npc_surplus = world.assign @ surplus_days
    cal_col = L.col("calories")
    world.npc[:, cal_col] = (world.npc[:, cal_col] + npc_surplus).clamp(0, 30)

    # ── 2. GESUNDHEIT ──────────────────────────────────
    hp_col = L.col("health")
    age_col = L.col("age")
    hp = world.npc[:, hp_col]
    cal = world.npc[:, cal_col]
    age = world.npc[:, age_col]

    # C-trait für Unfälle (zweiter Trait in der Liste)
    c_col = L.col("c") if "c" in L.columns else L.trait_start() + 1
    c_trait = world.npc[:, c_col]

    shelter = world.assign @ world.poi[:, POILayout.SHELTER]

    recovery = (cal > S.hunger_threshold).float() * S.recovery_rate * (1 - uv * 0.3)
    uv_damage = uv * (1 - shelter) * S.uv_damage_factor

    hunger_damage = torch.where(
        cal <= 0, torch.tensor(S.hunger_zero, device=dev),
        torch.where(cal < S.hunger_threshold, torch.tensor(S.hunger_low, device=dev),
                    torch.tensor(0.0, device=dev)))

    disease_prob = (S.disease_base * disease_mult).expand(N)
    sick = torch.bernoulli(disease_prob * alive.float())
    disease_damage = sick * (0.1 + torch.rand(N, device=dev) * 0.2)
    summary["illnesses"] = int(sick.sum().item())
    # Log illness events (batch)
    sick_ids = sick.nonzero(as_tuple=True)[0]
    if len(sick_ids) > 0:
        sick_pois = world.assign[sick_ids].argmax(dim=1)
        world.log_events_batch(world.tick + 1, 3, sick_ids, sick_pois)

    accident_prob = S.accident_base * (1 - c_trait * 0.4)
    accidents = torch.bernoulli(accident_prob * alive.float())
    accident_damage = accidents * (0.1 + torch.rand(N, device=dev) * 0.3)
    acc_ids = accidents.nonzero(as_tuple=True)[0]
    if len(acc_ids) > 0:
        acc_pois = world.assign[acc_ids].argmax(dim=1)
        world.log_events_batch(world.tick + 1, 4, acc_ids, acc_pois)

    age_decay = torch.where(age > S.age_decay_start,
                            S.age_decay_rate * (1 + (age - S.age_decay_start) / 20),
                            torch.tensor(0.0, device=dev))

    infant_shield = torch.where(age < S.infant_shield_age,
                                torch.tensor(S.infant_shield_factor, device=dev),
                                torch.tensor(1.0, device=dev))

    delta = (recovery
             - (uv_damage + disease_damage + accident_damage) * infant_shield
             - hunger_damage - age_decay)
    world.npc[:, hp_col] = (hp + delta * alive.float()).clamp(0, 1)

    # ── 3. TOD ─────────────────────────────────────────
    death_prob = torch.where(
        world.npc[:, hp_col] <= 0, torch.tensor(1.0, device=dev),
        torch.where(age > 75, 0.02 * (age - 75),
        torch.where((age > 60) & (world.npc[:, hp_col] < 0.3),
                    torch.tensor(0.01, device=dev),
                    torch.tensor(0.0, device=dev))))
    deaths = torch.bernoulli(death_prob * alive.float())
    dead_indices = deaths.nonzero(as_tuple=True)[0]

    for idx in dead_indices.tolist():
        world.npc[idx, L.col("alive")] = 0
        pi = int((world.assign[idx] > 0).nonzero(as_tuple=True)[0][0].item())
        summary["dead_names"].append((
            world.names[idx], int(world.npc[idx, age_col].item()), pi))
        world.log_event(world.tick + 1, 2, npc_a=idx, poi_id=pi,
                        val1=world.npc[idx, age_col].item())

    summary["deaths"] = len(summary["dead_names"])

    # Waisen: Kinder deren beide Eltern tot → adoptieren (nächster Haushalt)
    if hasattr(world, 'households') and len(dead_indices) > 0:
        alive_now = world.npc[:, L.col("alive")].bool()
        pa_ids = world.npc[:, L.col("parent_a")].long().clamp(min=0)
        pb_ids = world.npc[:, L.col("parent_b")].long().clamp(min=0)
        is_child = alive_now & (age < 15) & (world.npc[:, L.col("parent_a")] >= 0)
        pa_alive = alive_now[pa_ids] & (world.npc[:, L.col("parent_a")] >= 0)
        pb_alive = alive_now[pb_ids] & (world.npc[:, L.col("parent_b")] >= 0)
        orphans = is_child & ~pa_alive & ~pb_alive

        for idx in orphans.nonzero(as_tuple=True)[0].tolist():
            # Nächsten lebenden Haushalt in gleicher Siedlung finden
            child_poi = (world.assign[idx] > 0).nonzero(as_tuple=True)[0]
            if len(child_poi) == 0:
                continue
            pi = int(child_poi[0].item())
            for hh in world.households:
                a, b = hh[0], hh[1]
                if alive_now[a] and (world.assign[a, pi] > 0):
                    hh[2].append(idx)
                    world.npc[idx, L.col("parent_a")] = float(a)
                    world.npc[idx, L.col("parent_b")] = float(b) if alive_now[b] else float(a)
                    world.rel[idx, a] = world.rel[a, idx] = 0.5
                    world.trust[idx, a] = world.trust[a, idx] = 0.2
                    break

    # ── 4. GEBURTEN ────────────────────────────────────
    fertile = (alive
               & (world.npc[:, L.col("sex")] == 1)
               & (age >= S.fertility_min_age)
               & (age <= S.fertility_max_age)
               & (world.npc[:, hp_col] > S.fertility_min_health)
               & (cal > S.fertility_min_calories))
    fertility = S.fertility_rate * world.npc[:, hp_col] * (cal / 10).clamp(max=1)
    conceive = torch.bernoulli(fertility * fertile.float())

    for mom_idx in conceive.nonzero(as_tuple=True)[0].tolist():
        if world.max_id >= S.max_npcs:
            break
        pi = int((world.assign[mom_idx] > 0).nonzero(as_tuple=True)[0][0].item())
        males = (alive & (world.npc[:, L.col("sex")] == 0)
                 & (world.assign[:, pi] > 0) & (age >= 16) & (age <= 60))
        male_idx = males.nonzero(as_tuple=True)[0]
        if len(male_idx) == 0:
            continue
        dad_idx = male_idx[torch.randint(len(male_idx), (1,)).item()].item()

        ci = world.max_id
        sex = float(torch.randint(2, (1,)).item())
        name = np.random.choice(world.names_m if sex == 0 else world.names_f)

        parent_traits = (world.npc[mom_idx, L.trait_start():L.trait_end()]
                         + world.npc[dad_idx, L.trait_start():L.trait_end()]) / 2
        child_traits = (parent_traits + torch.randn(L.n_traits, device=dev) * 0.08).clamp(0, 1)

        world.npc[ci, L.trait_start():L.trait_end()] = child_traits
        world.npc[ci, hp_col] = 1.0
        world.npc[ci, cal_col] = 7.0
        world.npc[ci, age_col] = 0.0
        world.npc[ci, L.col("valence")] = 0.1
        world.npc[ci, L.col("arousal")] = 0.2
        world.npc[ci, L.col("dominance")] = 0.3
        world.npc[ci, L.col("sex")] = sex
        world.npc[ci, L.col("born_tick")] = float(world.tick + 1)
        world.npc[ci, L.faction_start():L.faction_end()] = \
            world.npc[mom_idx, L.faction_start():L.faction_end()].clone()
        world.npc[ci, L.col("status")] = 0.0
        world.npc[ci, L.col("alive")] = 1.0
        world.npc[ci, L.col("parent_a")] = float(mom_idx)
        world.npc[ci, L.col("parent_b")] = float(dad_idx)
        world.assign[ci, pi] = 1.0
        world.names[ci] = name

        world.rel[ci, mom_idx] = world.rel[mom_idx, ci] = 0.9
        world.rel[ci, dad_idx] = world.rel[dad_idx, ci] = 0.7
        world.trust[ci, mom_idx] = world.trust[mom_idx, ci] = 0.5

        world.max_id += 1
        summary["births"] += 1
        summary["born_names"].append((name, int(sex), pi))
        world.log_event(world.tick + 1, 1, npc_a=ci, npc_b=mom_idx, poi_id=pi)

        # Kind zum Household der Eltern hinzufügen
        if hasattr(world, 'households'):
            for hh in world.households:
                if mom_idx in hh[:2] or dad_idx in hh[:2]:
                    hh[2].append(ci)
                    break

    # ── 5. MIGRATION ───────────────────────────────────
    desperate = alive & ((cal < S.migration_cal) | (world.npc[:, hp_col] < S.migration_hp))
    migrates = torch.bernoulli(desperate.float() * S.migration_prob)
    migrant_ids = migrates.nonzero(as_tuple=True)[0]

    if len(migrant_ids) > 0:
        food_ratio = (food_supply / food_demand.clamp(min=1)).unsqueeze(0)
        water_score = world.poi[:, POILayout.WATER].unsqueeze(0)
        crowding = (1 - pop_per_poi / world.poi[:, POILayout.CAPACITY].clamp(min=1)).unsqueeze(0)
        social_pull = world.rel @ world.assign

        utility = food_ratio * 0.3 + water_score * 0.2 + crowding * 0.2 + social_pull * 0.3
        current_pop = pop_per_poi.clone()

        for idx in migrant_ids.tolist():
            cur = int((world.assign[idx] > 0).nonzero(as_tuple=True)[0][0].item())
            utils = utility[idx].clone()
            utils[cur] = -1
            over_cap = current_pop >= world.poi[:, POILayout.CAPACITY]
            utils[over_cap] = -1
            new = int(utils.argmax().item())
            if new != cur and utils[new] > 0:
                world.assign[idx] = 0
                world.assign[idx, new] = 1
                current_pop[cur] -= 1
                current_pop[new] += 1
                summary["migrations"] += 1
                world.log_event(world.tick + 1, 5, npc_a=idx, poi_id=new, val1=cur)

    # ── 6. SOZIALES ────────────────────────────────────
    if (world.tick + 1) % S.social_interval == 0:
        roles = assign_roles(world.npc, L, S)
        world.npc[:, L.role_start():L.role_end()] = roles
        social = compute_social_embedding(world.npc, world.assign, world.poi, L, S)
        world.npc[:, L.social_start():L.social_end()] = social
        base_aff = compute_affinity_matrix(world.npc, L, S)
        world.rel = (1 - S.affinity_blend) * world.rel + S.affinity_blend * base_aff

    # ── 6b. PAARBILDUNG (alle 26 Wochen, vektorisiert) ───
    if (world.tick + 1) % 26 == 0:
        if not hasattr(world, 'households'):
            world.households = []

        paired = torch.zeros(N, dtype=torch.bool, device=dev)
        for hh in world.households:
            paired[hh[0]] = True
            paired[hh[1]] = True

        sex = world.npc[:, L.col("sex")]
        single_m = alive & (age >= 18) & (sex < 0.5) & ~paired
        single_f = alive & (age >= 18) & (sex > 0.5) & ~paired
        m_ids = single_m.nonzero(as_tuple=True)[0]
        f_ids = single_f.nonzero(as_tuple=True)[0]

        if len(m_ids) > 0 and len(f_ids) > 0:
            # Affinität + gleiche Siedlung als Maske (Tensor-Ops)
            aff_block = world.rel[m_ids][:, f_ids]                # (n_m, n_f)
            same_poi = (world.assign[m_ids] @ world.assign[f_ids].T) > 0  # (n_m, n_f)
            aff_block = aff_block * same_poi.float()

            best_vals, best_idx = aff_block.max(dim=1)
            chance = torch.rand(len(m_ids), device=dev)
            will_pair = (best_vals > 0.3) & (chance < 0.15)

            f_taken = torch.zeros(len(f_ids), dtype=torch.bool, device=dev)
            for mi in will_pair.nonzero(as_tuple=True)[0].tolist():
                fi = best_idx[mi].item()
                if f_taken[fi]:
                    continue
                f_taken[fi] = True
                m, f = m_ids[mi].item(), f_ids[fi].item()
                world.rel[m, f] = world.rel[f, m] = 0.85
                world.trust[m, f] = world.trust[f, m] = 0.4
                world.households.append((m, f, []))
                summary.setdefault("new_pairs", []).append(
                    (world.names[m], world.names[f]))
                pi = int((world.assign[m] > 0).nonzero(as_tuple=True)[0][0].item())
                world.log_event(world.tick + 1, 6, npc_a=m, npc_b=f, poi_id=pi)

    # ── 7. ALTERN ──────────────────────────────────────
    world.npc[:, age_col] += alive.float() / 52.0

    # ── 8. KONFIGURIERTE EVENTS ──────────────────────────
    for evt in S.raw.get("events", []):
        if evt.get("season") and S.season_names[si] != evt["season"]:
            continue
        if torch.rand(1).item() >= evt.get("probability", 0):
            continue
        sev_range = evt.get("effect", {}).get("severity_range", [0.5, 1.0])
        severity = sev_range[0] + torch.rand(1).item() * (sev_range[1] - sev_range[0])
        cal_loss = evt.get("effect", {}).get("calories_loss_days", 0) * severity
        for pi in evt.get("affected_pois", []):
            if pi < n_poi:
                members = (world.assign[:, pi] > 0) & alive
                world.npc[members, cal_col] = (world.npc[members, cal_col] - cal_loss).clamp(min=0)
        summary[evt["name"]] = round(severity, 2)

    # ── 9. VAD ─────────────────────────────────────────
    v_col, a_col, d_col = L.col("valence"), L.col("arousal"), L.col("dominance")
    world.npc[:, v_col] = (0.7 * world.npc[:, v_col]
        + 0.2 * (world.npc[:, hp_col] - 0.5)
        + 0.1 * ((world.npc[:, cal_col] / 15).clamp(max=1) - 0.5)) * alive.float()
    danger = world.assign @ world.poi[:, POILayout.DANGER]
    world.npc[:, a_col] = (0.8 * world.npc[:, a_col]
        + 0.1 * danger
        + 0.1 * (1 - world.npc[:, cal_col] / 15).clamp(min=0)) * alive.float()

    world.tick += 1
    return summary


# ============================================================
#  OUTPUT
# ============================================================

def print_status(world):
    L = world.layout
    alive = world.alive_mask
    n = alive.sum().item()

    print(f"\n{'='*65}")
    print(f"  TICK {world.tick} – WOCHE {world.week}, {world.year} – "
          f"{world.season_name.upper()}")
    print(f"{'='*65}")

    print(f"\n  {'Settlement':<30s} {'Pop':>5s} {'HP':>6s} {'Cal':>6s}")
    print(f"  {'─'*50}")
    for pi in range(world.poi.shape[0]):
        members = (world.assign[:, pi] > 0) & alive
        pop = members.sum().item()
        cap = int(world.poi[pi, POILayout.CAPACITY].item())
        hp = world.npc[members, L.col("health")].mean().item() if pop > 0 else 0
        cal = world.npc[members, L.col("calories")].mean().item() if pop > 0 else 0
        bar = "█" * int(pop / cap * 10) if cap > 0 else ""
        print(f"  {world.poi_names[pi]:<30s} {pop:3d}/{cap:3d} {hp:5.2f} {cal:5.1f}d {bar}")
    print(f"\n  Gesamt: {n} lebend")


def print_tick_summary(summary, world):
    notable = summary["deaths"] > 0 or summary["births"] > 0
    new_pairs = summary.get("new_pairs", [])
    notable = notable or bool(new_pairs)
    # Check for any config-driven event
    event_names = [e["name"] for e in world.sim.raw.get("events", [])]
    event_hits = {k: summary[k] for k in event_names if k in summary}
    notable = notable or bool(event_hits)

    if notable:
        print(f"\n  Tick {summary['tick']}: ", end="")
        parts = []
        if summary["births"] > 0:
            names = ", ".join(n[0] for n in summary["born_names"])
            parts.append(f"+{summary['births']} born ({names})")
        if summary["deaths"] > 0:
            names = ", ".join(f"{n[0]}({n[1]})" for n in summary["dead_names"])
            parts.append(f"-{summary['deaths']} died ({names})")
        if summary["migrations"] > 0:
            parts.append(f"{summary['migrations']} migrated")
        for ename, sev in event_hits.items():
            parts.append(f"{ename.upper()} ({sev:.1f})")
        for p in new_pairs:
            parts.append(f"pair: {p[0]}+{p[1]}")
        print(" | ".join(parts))


# ============================================================
#  MAIN
# ============================================================

def main():
    args = sys.argv[1:]

    if "--help" in args:
        print("Usage: python3 sim/tick_gpu.py [weeks] [--status] [--db] [--bench] [--config path]")
        return

    config_path = None
    for i, a in enumerate(args):
        if a == "--config" and i + 1 < len(args):
            config_path = args[i + 1]

    print(f"Device: {DEVICE}")
    world = init_world(config_path=config_path)
    world = world.to(DEVICE)

    use_db = "--db" in args
    if use_db:
        from db import init_db, snapshot, print_db_summary
        init_db(layout=world.layout)
        snapshot(world.to(torch.device("cpu")))
        world = world.to(DEVICE)
        print("  DB initialisiert, Tick 0 gesnapshoted.")

    n_weeks = 52
    for a in args:
        if a.isdigit():
            n_weeks = int(a)

    if "--status" in args:
        print_world_summary(world)
        return

    snap_interval = 52

    t0 = time.time()
    for i in range(n_weeks):
        summary = tick(world)
        print_tick_summary(summary, world)
        if world.tick % 52 == 0:
            print_status(world)
        if use_db and world.tick % snap_interval == 0:
            world_cpu = world.to(torch.device("cpu"))
            result = snapshot(world_cpu)
            world = world.to(DEVICE)
            print(f"    → DB: {result['n_alive']} NPCs, "
                  f"{result['n_edges']} Edges, {result['n_groups']} Gruppen")

    elapsed = time.time() - t0
    tps = n_weeks / elapsed
    print_status(world)
    print(f"\n  {n_weeks} Wochen in {elapsed:.2f}s ({tps:.0f} Ticks/s)")

    if use_db and world.tick % snap_interval != 0:
        world_cpu = world.to(torch.device("cpu"))
        snapshot(world_cpu)
        world = world.to(DEVICE)
    if use_db:
        print_db_summary()

    if "--bench" in args:
        print(f"\n  Benchmark: 5200 Ticks (100 Jahre)...")
        w2 = init_world(config_path=config_path, seed=42).to(DEVICE)
        t0 = time.time()
        for _ in range(5200):
            tick(w2)
        elapsed = time.time() - t0
        print(f"  100 Jahre in {elapsed:.2f}s ({5200/elapsed:.0f} Ticks/s), Pop: {w2.n_alive}")


if __name__ == "__main__":
    main()
