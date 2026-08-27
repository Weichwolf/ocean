"""
OCEAN – Generischer NPC/World Simulator. Weltgenerierung aus Config.
"""

import torch
import numpy as np
from faker import Faker
import social
from world import (
    DEVICE, NameTable, POILayout, WorldState,
    load_config, assign_roles, compute_social_embedding,
    compute_provision, group_first_mask, role_demand, smooth_provision,
)


def init_world(config_path=None, seed=2100):
    torch.manual_seed(seed)
    np.random.seed(seed)

    config, layout, sim = load_config(config_path)
    settlements = config["settlements"]
    factions = config["factions"]
    L = layout

    names_cfg = config.get("names", {})
    if "locale" in names_cfg:
        fake = Faker(names_cfg["locale"])
        Faker.seed(seed)
        pool = names_cfg.get("pool_size", 100)
        names_m = list({fake.first_name_male() for _ in range(pool * 3)})[:pool]
        names_f = list({fake.first_name_female() for _ in range(pool * 3)})[:pool]
    else:
        names_m = names_cfg.get("m", ["John", "James", "Robert", "William"])
        names_f = names_cfg.get("f", ["Mary", "Jane", "Alice", "Emma"])

    n_poi = len(settlements)
    poi = torch.tensor([[s["x"], s["y"], s["capacity"], s["water"],
                         s["food"], s["danger"], s["shelter"]] for s in settlements])
    poi_names = [s["name"] for s in settlements]

    # Papierkorbzeile am Ende: Schreibvorgänge nicht ausgewählter Elemente laufen
    # dorthin, damit der Tick ohne Verzweigung auskommt.
    MAX = sim.max_npcs
    npc = torch.zeros(MAX + 1, L.D_NPC)
    assign = torch.zeros(MAX + 1, n_poi)

    pops = torch.tensor([s["pop"] for s in settlements])
    n = int(pops.sum())
    if n > MAX:
        raise ValueError(f"Bevölkerung {n} > max_npcs {MAX}")
    who = torch.arange(n)
    poi_of = torch.repeat_interleave(torch.arange(n_poi), pops)

    f_idx = torch.tensor([L.faction_names.index(s["faction"]) for s in settlements])
    mu = torch.tensor([[factions[s["faction"]]["traits"][t][0] for t in L.trait_names]
                       for s in settlements])
    sd = torch.tensor([[factions[s["faction"]]["traits"][t][1] for t in L.trait_names]
                       for s in settlements])

    traits = (mu[poi_of] + sd[poi_of] * torch.randn(n, L.n_traits)).clamp(0, 1)
    ages = torch.from_numpy(np.random.triangular(
        sim.age_dist["min"], sim.age_dist["mode"], sim.age_dist["max"], n)).float()
    sex = torch.randint(2, (n,)).float()
    u = torch.rand(n)

    npc[who, None] = 0
    npc[:n, L.trait_start():L.trait_end()] = traits
    npc[:n, L.base_start():L.base_end()] = traits
    npc[:n, L.col("health")] = torch.where(ages < 55, 0.8 + u * 0.2, 0.6 + u * 0.2)
    npc[:n, L.col("calories")] = 7.0 + torch.rand(n) * 14.0
    npc[:n, L.col("age")] = ages
    npc[:n, L.col("valence")] = -0.1 + torch.rand(n) * 0.4
    npc[:n, L.col("arousal")] = 0.2 + torch.rand(n) * 0.3
    npc[:n, L.col("dominance")] = 0.3 + torch.rand(n) * 0.4
    npc[:n, L.col("sex")] = sex
    npc[:n, L.col("born_tick")] = -ages * 52
    npc[:n, L.col("name_idx")] = torch.randint(1 << 20, (n,)).float()
    npc[who, L.faction_start() + f_idx[poi_of]] = 1.0
    npc[:n, L.col("alive")] = 1.0
    npc[:n, L.col("parent_a")] = -1
    npc[:n, L.col("parent_b")] = -1
    npc[:n, L.col("partner")] = -1
    assign[who, poi_of] = 1.0

    A = config["affect"]
    n_idx = L.trait_start() + L.trait_names.index("n")
    alive = npc[:, L.col("alive")]
    npc[:, L.col("valence_base")] = (
        A["temperament_base"] - A["temperament_n_weight"] * (npc[:, n_idx] - 0.5)) * alive
    npc[:, L.col("stress")] = ((0.10 + 0.25 * npc[:, n_idx]
                                + 0.004 * npc[:, L.col("age")]) * alive).clamp(0, 1)

    # Rollen: erst Eignung, dann Bedarf – Trägheit verhindert das Schwingen
    npc[:, L.role_start():L.role_end()] = assign_roles(npc, L, sim)
    box = type("Box", (), {"prov_ema": None})()
    for _ in range(24):
        per_capita, _ = compute_provision(npc, assign, L, sim, alive > 0)
        npc[:, L.role_start():L.role_end()] = assign_roles(
            npc, L, sim,
            demand=assign @ role_demand(smooth_provision(box, per_capita, sim), sim))

    standing = npc[:, L.role_start():L.role_end()] @ sim.role_standing
    npc[:, L.col("status")] = ((sim.status_role_weight * standing
                                + 0.30 * (npc[:, L.col("age")] / 60).clamp(max=1)
                                + (0.70 - sim.status_role_weight) * 0.5) * alive).clamp(0, 1)
    npc[:, L.social_start():L.social_end()] = compute_social_embedding(
        npc, assign, poi, L, sim)

    # ── Bindungen, Paare, Familien – alles über Stichproben, kein N² ──
    K = sim.bond_slots
    bond_idx = torch.full((MAX + 1, K), -1, dtype=torch.long)
    bond_val = torch.zeros(MAX + 1, K)
    ids = torch.arange(MAX + 1)
    feats = social.social_features(npc, L, sim)
    poi_all = assign.argmax(dim=1)
    roster = social.build_roster(poi_all, n_poi, alive)
    M = sim.bond_peer_samples

    def best_match(pool_mask):
        peers = social.sample_peers(poi_all, *roster, M)
        aff = (social.affinity(feats, ids.unsqueeze(1).expand(-1, M), peers,
                               sim.affinity_sigma)
               * (peers != ids.unsqueeze(1)).float() * pool_mask[peers])
        best, j = aff.max(dim=1)
        return peers.gather(1, j.unsqueeze(1)).squeeze(1), best

    for _ in range(4):
        target, best = best_match(alive)
        social.bond_strengthen(bond_idx, bond_val, target, best,
                               alive * (best > sim.bond_min).float())

    adult = alive * (npc[:, L.col("age")] >= 18).float()
    free_m = adult * (npc[:, L.col("sex")] < 0.5).float()
    free_f = adult * (npc[:, L.col("sex")] > 0.5).float()
    mate, score = best_match(free_f)
    pair = free_m * (score > 0.3).float() * (torch.rand(MAX + 1) < 0.7).float()
    pair = pair * group_first_mask(mate, torch.where(pair > 0, score,
                                                     torch.full_like(score, -1e9))).float()
    npc[:, L.col("partner")] = torch.where(pair > 0, mate.float(),
                                           npc[:, L.col("partner")])
    m_dest = torch.where(pair > 0, mate, torch.full_like(mate, MAX))
    npc[:, L.col("partner")].scatter_(0, m_dest, ids.float())
    social.bond_strengthen(bond_idx, bond_val, mate,
                           torch.full_like(pair, 0.9), pair)
    social.bond_strengthen(bond_idx, bond_val, ids,
                           torch.zeros(MAX + 1).scatter_(0, m_dest, pair * 0.9),
                           torch.zeros(MAX + 1).scatter_(0, m_dest, pair))

    # Kinder an vorhandene Haushalte: Väter als Stichprobenmenge
    father_pool = pair
    kid = alive * (npc[:, L.col("age")] < 15).float()
    dads, _ = best_match(father_pool)
    has_dad = father_pool[dads]
    take = kid * has_dad
    npc[:, L.col("parent_b")] = torch.where(take > 0, dads.float(),
                                            npc[:, L.col("parent_b")])
    npc[:, L.col("parent_a")] = torch.where(take > 0, npc[dads, L.col("partner")],
                                            npc[:, L.col("parent_a")])
    social.bond_strengthen(bond_idx, bond_val, dads, torch.full_like(take, 0.8), take)
    social.bond_strengthen(bond_idx, bond_val, npc[:, L.col("parent_a")].long().clamp(min=0),
                           torch.full_like(take, 0.9), take)

    npc[MAX] = 0
    assign[MAX] = 0
    bond_idx[MAX] = -1
    bond_val[MAX] = 0

    world = WorldState(
        npc=npc, poi=poi, assign=assign,
        bond_idx=bond_idx, bond_val=bond_val,
        tick=0, max_id=torch.tensor(float(n)),
        events=[], names=NameTable(npc, L, names_m, names_f),
        poi_names=poi_names, layout=L, sim=sim,
        names_m=names_m, names_f=names_f,
        event_log=torch.zeros(max(65537, 8 * n + 1), 7),
        cursor=torch.tensor(0.0), dropped=torch.tensor(0.0),
    )
    world.rng = np.random.default_rng(seed)
    world.prov_ema = box.prov_ema
    world.ties = social.ties(bond_val, 0.3)
    world.social_pull = social.bond_to_poi(bond_idx, bond_val, assign)
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

    edges = int((world.bond_val > 0.1).sum())
    print(f"\n  Bindungen (> 0.1): {edges}  "
          f"(Ø {edges / max(n, 1):.1f} je NPC, K={world.sim.bond_slots})")
    print()


if __name__ == "__main__":
    world = init_world()
    print_world_summary(world)
