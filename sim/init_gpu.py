"""
OCEAN – Generischer NPC/World Simulator. Weltgenerierung aus Config.
"""

import torch
import numpy as np
from faker import Faker
from world import (
    DEVICE, POILayout, WorldState,
    load_config, assign_roles, compute_social_embedding,
)


def init_world(config_path=None, seed=2100):
    torch.manual_seed(seed)
    np.random.seed(seed)

    config, layout, sim = load_config(config_path)
    settlements = config["settlements"]
    factions = config["factions"]

    # Namen: aus Faker (locale + seed) oder statischer Liste
    names_cfg = config.get("names", {})
    if "locale" in names_cfg:
        fake = Faker(names_cfg["locale"])
        Faker.seed(seed)  # deterministisch
        pool = names_cfg.get("pool_size", 100)
        names_m = list({fake.first_name_male() for _ in range(pool * 3)})[:pool]
        names_f = list({fake.first_name_female() for _ in range(pool * 3)})[:pool]
    else:
        names_m = names_cfg.get("m", ["John", "James", "Robert", "William"])
        names_f = names_cfg.get("f", ["Mary", "Jane", "Alice", "Emma"])

    n_poi = len(settlements)

    # ── POI-Tensor ──────────────────────────────────────
    poi = torch.zeros(n_poi, POILayout.D_POI)
    poi_names = []

    for i, s in enumerate(settlements):
        poi[i] = torch.tensor([
            s["x"], s["y"], s["capacity"], s["water"],
            s["food"], s["danger"], s["shelter"]
        ])
        poi_names.append(s["name"])

    # ── NPC-Tensor ──────────────────────────────────────
    MAX = sim.max_npcs
    npc = torch.zeros(MAX, layout.D_NPC)
    assign = torch.zeros(MAX, n_poi)
    names = [""] * MAX
    n_created = 0

    for poi_idx, s in enumerate(settlements):
        faction_name = s["faction"]
        faction_idx = layout.faction_names.index(faction_name)
        faction_spec = factions[faction_name]

        # Trait-Profile aus Config
        trait_mu = torch.tensor([faction_spec["traits"][t][0] for t in layout.trait_names])
        trait_std = torch.tensor([faction_spec["traits"][t][1] for t in layout.trait_names])

        for _ in range(s["pop"]):
            i = n_created
            sex = np.random.choice([0.0, 1.0])
            names[i] = np.random.choice(names_m if sex == 0 else names_f)

            age = np.random.triangular(
                sim.age_dist["min"], sim.age_dist["mode"], sim.age_dist["max"])

            # Traits
            traits = (trait_mu + trait_std * torch.randn(layout.n_traits)).clamp(0, 1)
            npc[i, layout.trait_start():layout.trait_end()] = traits

            # Vitals
            npc[i, layout.col("health")] = 0.8 + np.random.random() * 0.2 if age < 55 else 0.6 + np.random.random() * 0.2
            npc[i, layout.col("calories")] = 7.0 + np.random.random() * 14.0
            npc[i, layout.col("age")] = age

            # Emotions
            npc[i, layout.col("valence")] = -0.1 + np.random.random() * 0.4
            npc[i, layout.col("arousal")] = 0.2 + np.random.random() * 0.3
            npc[i, layout.col("dominance")] = 0.3 + np.random.random() * 0.4

            # Demographics
            npc[i, layout.col("sex")] = sex
            npc[i, layout.col("born_tick")] = -age * 52

            # Faction one-hot
            npc[i, layout.faction_start() + faction_idx] = 1.0

            # Meta
            npc[i, layout.col("status")] = min(age, 60) / 60.0
            npc[i, layout.col("alive")] = 1.0
            npc[i, layout.col("parent_a")] = -1
            npc[i, layout.col("parent_b")] = -1

            assign[i, poi_idx] = 1.0
            n_created += 1

    # Rollen
    alive_mask = npc[:, layout.col("alive")].bool()
    roles = assign_roles(npc, layout, sim)
    npc[:, layout.role_start():layout.role_end()] = roles

    # Social Embeddings
    social = compute_social_embedding(npc, assign, poi, layout, sim)
    npc[:, layout.social_start():layout.social_end()] = social

    # ── Relationships ───────────────────────────────────
    rel = torch.zeros(MAX, MAX)
    trust = torch.zeros(MAX, MAX)

    # Basis: Siedlungs-Nachbarn kennen sich
    for poi_idx in range(n_poi):
        members = assign[:, poi_idx].nonzero(as_tuple=True)[0]
        n_m = len(members)
        if n_m < 2:
            continue
        base = 0.3 if n_m < 30 else 0.15 if n_m < 60 else 0.08
        for a in members:
            for b in members:
                if a < b:
                    val = base + np.random.random() * 0.2
                    rel[a, b] = val
                    rel[b, a] = val

    # ── Paare und Familien bilden ──────────────────────
    households = []

    def pair_score(m, f):
        om = npc[m, layout.trait_start():layout.trait_end()]
        of_ = npc[f, layout.trait_start():layout.trait_end()]
        s = (1 - abs(om[0] - of_[0]).item()) * 0.3   # ähnliches O
        s += (1 - abs(om[3] - of_[3]).item()) * 0.3   # ähnliches A
        s += abs(om[2] - of_[2]).item() * 0.1          # komplementäres E
        s -= om[4].item() * of_[4].item() * 0.2        # hohes N×N = instabil
        age_diff = abs(npc[m, layout.col("age")].item() - npc[f, layout.col("age")].item())
        s -= min(age_diff / 30, 0.3)
        return s

    for poi_idx in range(n_poi):
        members = assign[:, poi_idx].nonzero(as_tuple=True)[0].tolist()
        adults_m = [i for i in members if npc[i, layout.col("sex")].item() == 0
                    and npc[i, layout.col("age")].item() >= 18]
        adults_f = [i for i in members if npc[i, layout.col("sex")].item() == 1
                    and npc[i, layout.col("age")].item() >= 18]
        children = [i for i in members if npc[i, layout.col("age")].item() < 15]

        # Greedy Matching nach Kompatibilität
        pairs = []
        if adults_m and adults_f:
            scores = [(m, f, pair_score(m, f)) for m in adults_m for f in adults_f]
            scores.sort(key=lambda x: -x[2])
            paired_m, paired_f = set(), set()
            for m, f, sc in scores:
                if m in paired_m or f in paired_f:
                    continue
                if sc < 0:
                    continue
                pairs.append((m, f))
                paired_m.add(m)
                paired_f.add(f)
                if len(pairs) >= int(min(len(adults_m), len(adults_f)) * 0.7):
                    break

        child_idx = 0
        for a, b in pairs:
            rel[a, b] = rel[b, a] = 0.8 + np.random.random() * 0.2
            trust[a, b] = trust[b, a] = 0.4 + np.random.random() * 0.3

            n_kids = min(np.random.choice([0, 1, 1, 2, 2, 3]),
                         len(children) - child_idx)
            kids = []
            for _ in range(n_kids):
                kid = children[child_idx]
                npc[kid, layout.col("parent_a")] = float(b)  # Mutter
                npc[kid, layout.col("parent_b")] = float(a)  # Vater
                rel[kid, a] = rel[a, kid] = 0.7 + np.random.random() * 0.2
                rel[kid, b] = rel[b, kid] = 0.85 + np.random.random() * 0.15
                trust[kid, a] = trust[a, kid] = 0.3
                trust[kid, b] = trust[b, kid] = 0.5
                kids.append(kid)
                child_idx += 1

            for ci in range(len(kids)):
                for cj in range(ci + 1, len(kids)):
                    rel[kids[ci], kids[cj]] = rel[kids[cj], kids[ci]] = 0.6
                    trust[kids[ci], kids[cj]] = trust[kids[cj], kids[ci]] = 0.2

            households.append((a, b, kids))

        # Übrige Kinder auf bestehende Haushalte verteilen
        remaining_kids = children[child_idx:]
        poi_hh = [h for h in households
                  if h[0] in set(members) or h[1] in set(members)]
        for ki, kid in enumerate(remaining_kids):
            if poi_hh:
                target = poi_hh[ki % len(poi_hh)]
                target[2].append(kid)
                npc[kid, layout.col("parent_a")] = float(target[1])
                npc[kid, layout.col("parent_b")] = float(target[0])
                rel[kid, target[0]] = rel[target[0], kid] = 0.6
                rel[kid, target[1]] = rel[target[1], kid] = 0.7
                trust[kid, target[0]] = trust[target[0], kid] = 0.2
                trust[kid, target[1]] = trust[target[1], kid] = 0.3

    # Event-Log Tensor: initial 10k Slots
    event_log = torch.zeros(10000, 7)

    world = WorldState(
        npc=npc, poi=poi, assign=assign,
        rel=rel, trust=trust,
        tick=0, max_id=n_created,
        events=[], names=names, poi_names=poi_names,
        layout=layout, sim=sim,
        names_m=names_m, names_f=names_f,
        event_log=event_log, event_cursor=0,
    )
    world.households = households

    return world


def print_world_summary(world):
    L = world.layout
    alive = world.alive_mask
    n = alive.sum().item()

    print(f"\n{'='*60}")
    print(f"  {world.sim.raw['meta']['name']} – TICK {world.tick}")
    print(f"  {n} NPCs, {world.poi.shape[0]} Siedlungen")
    print(f"  Tensor: ({world.sim.max_npcs}, {L.D_NPC}) = "
          f"{world.sim.max_npcs * L.D_NPC} floats")
    print(f"  Device: {DEVICE}")
    print(f"  Traits: {L.trait_names}")
    print(f"  Factions: {L.faction_names}")
    print(f"  Roles: {L.role_names}")
    print(f"{'='*60}\n")

    for pi in range(world.poi.shape[0]):
        members = (world.assign[:, pi] > 0) & alive
        pop = members.sum().item()
        cap = int(world.poi[pi, POILayout.CAPACITY].item())
        avg_hp = world.npc[members, L.col("health")].mean().item() if pop > 0 else 0
        avg_cal = world.npc[members, L.col("calories")].mean().item() if pop > 0 else 0
        print(f"  {world.poi_names[pi]:<30s} {pop:3d}/{cap:3d}  "
              f"HP:{avg_hp:.2f}  Cal:{avg_cal:.1f}d")

    # Fraktionen
    print(f"\n  Fraktionen:")
    for fi, fname in enumerate(L.faction_names):
        mask = (world.npc[:, L.faction_start() + fi] > 0) & alive
        n_f = mask.sum().item()
        if n_f > 0:
            traits = world.npc[mask, L.trait_start():L.trait_end()].mean(dim=0)
            trait_str = " ".join(f"{s}={v:.2f}" for s, v in zip(L.trait_names, traits))
            print(f"    {fname:<15s}: {n_f:3d}  {trait_str}")

    # Rollen
    print(f"\n  Rollen:")
    for ri, rname in enumerate(L.role_names):
        mask = (world.npc[:, L.role_start() + ri] > 0) & alive
        n_r = mask.sum().item()
        if n_r > 0:
            print(f"    {rname:<12s}: {n_r:3d}")

    edges = (world.rel > 0.1).sum().item() // 2
    print(f"\n  Beziehungen (affinity > 0.1): {edges}")
    print()


if __name__ == "__main__":
    world = init_world()
    print_world_summary(world)
