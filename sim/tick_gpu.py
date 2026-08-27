"""
OCEAN – Generischer NPC/World Simulator. GPU-Tick.
"""

import torch
import numpy as np
import json
import time
import sys
import os

import social
from world import (
    DEVICE, POILayout, WorldState,
    load_config, assign_roles, compute_social_embedding,
    compute_provision, plasticity, role_demand,
    get_device,
    smooth_provision,
    group_first_mask, capacity_rank,
)

EVT = {"birth": 1, "death": 2, "illness": 3, "injury": 4, "migration": 5,
       "pair": 6, "adoption": 7, "climate": 8, "bereavement": 9}
from init_gpu import init_world, print_world_summary


def tick(world: WorldState) -> dict:
    """Ein Wochen-Tick. Maskenbasiert, ohne Device→Host-Synchronisation.

    Kein `nonzero`, kein `.item()`, keine Python-Liste im Pfad: jede Auswahl ist eine
    Maske, jede Einfügung ein Scatter. Zeile MAX ist Papierkorb – Schreibvorgänge
    nicht ausgewählter Elemente laufen dorthin statt in eine Verzweigung.
    """
    L, S = world.layout, world.sim
    npc, dev = world.npc, world.npc.device
    NT = npc.shape[0]
    TRASH = NT - 1
    n_poi = world.poi.shape[0]
    si, t = world.season_idx, world.tick + 1
    ch = S.ch
    idx = torch.arange(NT, device=dev)

    hp_col, cal_col, age_col = L.col("health"), L.col("calories"), L.col("age")
    ts, te = L.trait_start(), L.trait_end()
    alive = npc[:, L.col("alive")]

    shock = torch.zeros(NT, 4, device=dev)
    drift = torch.zeros(NT, L.n_traits, device=dev)

    def impact(name, mask):
        shock.add_(S.impact_vad[name].to(dev).unsqueeze(0) * mask.unsqueeze(1))
        drift.add_(S.impact_drift[name].to(dev).unsqueeze(0) * mask.unsqueeze(1))

    food_mult = S.season_food[si].to(dev)
    uv = S.season_uv[si].to(dev)
    disease_mult = S.season_disease[si].to(dev)
    poi_idx = world.assign.argmax(dim=1)

    # ── 1. ARBEIT ──────────────────────────────────────
    per_capita, factor = compute_provision(npc, world.assign, L, S, alive > 0)
    npc_factor = world.assign @ factor
    care_cov = npc_factor[:, ch["care"]]
    safety_cov = npc_factor[:, ch["safety"]]
    craft_cov = npc_factor[:, ch["craft"]]

    # ── 2. RESSOURCEN ──────────────────────────────────
    pop_per_poi = world.assign.T @ alive
    food_supply = (world.poi[:, POILayout.FOOD] * food_mult * factor[:, ch["food"]]
                   * (0.85 + torch.rand(n_poi, device=dev) * 0.30))

    nf = S.need_child_floor
    need = S.calorie_need * (nf + (1 - nf)
                             * (npc[:, age_col] / S.need_adult_age).clamp(max=1)) * alive
    food_demand = world.assign.T @ need

    status = npc[:, L.col("status")]
    guardian = npc[:, L.col("parent_a")].long()
    rank_food = torch.where(npc[:, age_col] < 15,
                            torch.maximum(status, S.household_share
                                          * status[guardian.clamp(min=0)]), status)
    weight = need * (1 + S.ration_inequality * (rank_food - 0.5)).clamp(min=0.2)
    share = weight / (world.assign @ (world.assign.T @ weight)).clamp(min=1e-6)
    npc[:, cal_col] = (npc[:, cal_col]
                       + ((world.assign @ food_supply) * share - need) / 2000).clamp(0, 30)

    # ── 3. GESUNDHEIT ──────────────────────────────────
    hp = npc[:, hp_col]
    cal = npc[:, cal_col]
    age = npc[:, age_col]
    stress = npc[:, L.col("stress")]
    c_trait = npc[:, ts + S.labor_trait_idx]

    shelter = ((world.assign @ world.poi[:, POILayout.SHELTER])
               * (1 - S.craft_shelter_weight)
               + craft_cov * S.craft_shelter_weight).clamp(0, 1)
    danger_eff = ((world.assign @ world.poi[:, POILayout.DANGER])
                  * (1 - safety_cov * S.safety_danger_reduction))
    care_shield = 1 - care_cov * S.care_damage_reduction

    hunger = (1 - cal / S.hunger_threshold).clamp(0, 1)
    recovery = (cal > S.hunger_threshold).float() * S.recovery_rate * (1 - uv * 0.3)
    uv_damage = uv * (1 - shelter) * S.uv_damage_factor
    hunger_damage = torch.where(
        cal <= 0, torch.tensor(S.hunger_zero, device=dev),
        torch.where(cal < S.hunger_threshold, torch.tensor(S.hunger_low, device=dev),
                    torch.tensor(0.0, device=dev)))

    sick = torch.bernoulli((S.disease_base * disease_mult
                            * (1 + S.affect["stress_disease_gain"] * stress)
                            * alive).clamp(0, 1))
    disease_damage = sick * (0.1 + torch.rand(NT, device=dev) * 0.2) * care_shield
    world.log_masked(t, EVT["illness"], sick, poi=poi_idx)
    impact("illness", sick)

    hurt = torch.bernoulli((S.accident_base * (1 - c_trait * 0.4)
                            * (1 - safety_cov * S.safety_accident_reduction)
                            * (1 + danger_eff) * alive).clamp(0, 1))
    accident_damage = hurt * (0.1 + torch.rand(NT, device=dev) * 0.3) * care_shield
    world.log_masked(t, EVT["injury"], hurt, poi=poi_idx)
    impact("injury", hurt)

    age_decay = torch.where(age > S.age_decay_start,
                            S.age_decay_rate * (1 + (age - S.age_decay_start) / 20),
                            torch.tensor(0.0, device=dev))
    infant_shield = torch.where(age < S.infant_shield_age,
                                torch.tensor(S.infant_shield_factor, device=dev),
                                torch.tensor(1.0, device=dev))

    npc[:, hp_col] = (hp + (recovery
                            - (uv_damage + disease_damage + accident_damage) * infant_shield
                            - hunger_damage - age_decay
                            - stress * S.affect["stress_health_cost"]) * alive).clamp(0, 1)

    # ── 4. TOD ─────────────────────────────────────────
    hp = npc[:, hp_col]
    death_prob = torch.where(
        hp <= 0, torch.tensor(1.0, device=dev),
        torch.where(age > 75, 0.02 * (age - 75),
                    torch.where((age > 60) & (hp < 0.3),
                                torch.tensor(0.01, device=dev),
                                torch.tensor(0.0, device=dev))))
    dead = torch.bernoulli((death_prob * alive).clamp(0, 1))
    dead[TRASH] = 0
    npc[:, L.col("alive")] = alive * (1 - dead)
    alive = npc[:, L.col("alive")]

    pa = npc[:, L.col("parent_a")].long()
    pb = npc[:, L.col("parent_b")].long()
    partner = npc[:, L.col("partner")].long()
    has_pa = (pa >= 0).float()
    has_pb = (pb >= 0).float()
    pa_c, pb_c = pa.clamp(min=0), pb.clamp(min=0)

    # Der Tod wird beim Elternteil vermerkt – so findet die Abfrage später das Kind
    world.log_masked(t, EVT["death"], dead, poi=poi_idx,
                     npc_b=torch.where(has_pa > 0, pa, torch.full_like(pa, -1)),
                     val1=0.0)

    # ── 5. TRAUER ──────────────────────────────────────
    # Bindung = Vertrauen + enge Freundschaft + Verwandtschaft. Ähnlichkeit allein
    # ließe die halbe Siedlung um jeden Toten trauern.
    kin = S.kin_bond
    grief = social.bond_gather(world.bond_idx, world.bond_val, dead)

    lost_child = torch.zeros(NT, device=dev)
    lost_child.index_add_(0, pa_c, dead * has_pa)
    lost_child.index_add_(0, pb_c, dead * has_pb)
    sibling_loss = (lost_child[pa_c] * has_pa - dead).clamp(min=0)
    partner_dead = dead[partner.clamp(min=0)] * (partner >= 0).float()

    grief = (grief
             + partner_dead * kin["partner"]
             + lost_child * kin["child"]
             + (dead[pa_c] * has_pa + dead[pb_c] * has_pb) * kin["parent"]
             + sibling_loss * kin["sibling"]) * alive
    grief = grief.clamp(max=1.5)

    mourns = (grief > S.affect["bereavement_min_bond"]).float()
    impact("bereavement", grief * mourns)
    lost = torch.where(partner_dead > 0, partner,
                       torch.where(dead[pa_c] * has_pa > 0, pa,
                                   torch.where(dead[pb_c] * has_pb > 0, pb,
                                               torch.full_like(pa, -1))))
    world.log_masked(t, EVT["bereavement"], mourns, poi=poi_idx, npc_b=lost)

    # Ein Massensterben trifft auch, wer niemanden persönlich verloren hat
    community = ((world.assign @ ((world.assign.T @ dead) / pop_per_poi.clamp(min=1)))
                 * S.affect["community_grief"] * alive)
    impact("bereavement", community * (community > 0.02).float())

    npc[:, L.col("partner")] = torch.where(
        (partner_dead > 0) | (dead > 0), torch.full_like(partner, -1), partner).float()

    # ── 6. WAISEN ──────────────────────────────────────
    orphan = (alive * (age < 15) * has_pa
              * (1 - alive[pa_c] * has_pa) * (1 - alive[pb_c] * has_pb))
    adopter_score = (alive * (age >= 18) * (npc[:, L.col("partner")] >= 0).float()
                     * (0.1 + status))
    best_per_poi = (adopter_score.unsqueeze(1) * world.assign).argmax(dim=0)
    poi_has_adopter = ((adopter_score.unsqueeze(1) * world.assign).sum(0) > 0).float()
    adopter = best_per_poi[poi_idx]
    adopt = orphan * poi_has_adopter[poi_idx]
    npc[:, L.col("parent_a")] = torch.where(
        adopt > 0, adopter.float(), npc[:, L.col("parent_a")])
    npc[:, L.col("parent_b")] = torch.where(
        adopt > 0, npc[adopter, L.col("partner")], npc[:, L.col("parent_b")])
    social.bond_strengthen(world.bond_idx, world.bond_val, adopter,
                           torch.full_like(adopt, 0.5), adopt)
    world.log_masked(t, EVT["adoption"], adopt, poi=poi_idx, npc_b=adopter)
    impact("adoption", adopt)

    # ── 7. GEBURTEN ────────────────────────────────────
    cal = npc[:, cal_col]
    fertile = (alive * (npc[:, L.col("sex")] == 1).float()
               * (age >= S.fertility_min_age).float()
               * (age <= S.fertility_max_age).float()
               * (npc[:, hp_col] > S.fertility_min_health).float()
               * (cal > S.fertility_min_calories).float())
    conceive = torch.bernoulli(
        (S.fertility_rate * npc[:, hp_col] * (cal / 10).clamp(max=1) * fertile).clamp(0, 1))

    male_ok = (alive * (npc[:, L.col("sex")] == 0).float()
               * (age >= 16).float() * (age <= 60).float())
    male_by_poi = (world.assign * male_ok.unsqueeze(1)).T
    K = S.max_births_per_poi
    gumbel = -torch.log(-torch.log(torch.rand_like(male_by_poi).clamp(min=1e-9))
                        .clamp(min=1e-9))
    fathers_pk = torch.topk(torch.log(male_by_poi + 1e-9) + gumbel, K, dim=1).indices
    poi_has_male = (male_by_poi.sum(dim=1) > 0).float()

    rank_poi = ((torch.cumsum(conceive.unsqueeze(1) * world.assign, dim=0)
                 * world.assign).sum(dim=1) - 1)
    eligible = conceive * poi_has_male[poi_idx] * (rank_poi < K).float()
    slot = (world.max_id + torch.cumsum(eligible, 0) - 1).long()
    born = eligible * (slot < S.max_npcs).float()
    dest = torch.where(born > 0, slot, torch.full_like(slot, TRASH))
    father = fathers_pk[poi_idx, rank_poi.clamp(0, K - 1).long()]

    kid_traits = ((npc[:, ts:te] + npc[father, ts:te]) / 2
                  + torch.randn(NT, L.n_traits, device=dev) * 0.08).clamp(0, 1)
    ones = torch.ones(NT, device=dev)
    child = torch.zeros(NT, L.D_NPC, device=dev)
    child[:, ts:te] = kid_traits
    child[:, L.base_start():L.base_end()] = kid_traits
    child[:, L.faction_start():L.faction_end()] = npc[:, L.faction_start():L.faction_end()]
    child[:, hp_col] = 1.0
    child[:, cal_col] = 7.0
    child[:, L.col("valence")] = 0.1
    child[:, L.col("arousal")] = 0.2
    child[:, L.col("dominance")] = 0.3
    child[:, L.col("valence_base")] = 0.1
    child[:, L.col("alive")] = 1.0
    child[:, L.col("born_tick")] = t
    child[:, L.col("sex")] = torch.randint(2, (NT,), device=dev).float()
    child[:, L.col("name_idx")] = torch.randint(1 << 20, (NT,), device=dev).float()
    child[:, L.col("status")] = status * S.household_share
    child[:, L.col("parent_a")] = idx.float()
    child[:, L.col("parent_b")] = father.float()
    child[:, L.col("partner")] = -1
    npc.scatter_(0, dest.unsqueeze(1).expand(-1, L.D_NPC), child)

    world.assign.scatter_(0, dest.unsqueeze(1).expand(-1, n_poi), world.assign.clone())
    born_kid = torch.zeros(NT, device=dev).scatter_(0, dest, born)
    born_kid[TRASH] = 0
    social.bond_strengthen(world.bond_idx, world.bond_val, idx,
                           torch.where(born_kid > 0, torch.full_like(born_kid, 0.9),
                                       torch.zeros_like(born_kid)), born_kid)
    social.bond_strengthen(world.bond_idx, world.bond_val, dest,
                           torch.full_like(born, 0.9), born)
    social.bond_strengthen(world.bond_idx, world.bond_val, father,
                           torch.full_like(born, 0.7), born)
    world.max_id = world.max_id + born.sum()
    world.log_masked(t, EVT["birth"], born, poi=poi_idx, npc_b=idx)
    impact("birth", born)
    impact("birth", torch.zeros(NT, device=dev).scatter_(0, father, born * 0.5))
    npc[TRASH] = 0
    world.assign[TRASH] = 0
    alive = npc[:, L.col("alive")]

    # ── 8. MIGRATION ───────────────────────────────────
    cal = npc[:, cal_col]
    distress = (((1 - cal / (S.migration_cal * 8)).clamp(0, 1)
                 + (1 - npc[:, hp_col] / max(S.migration_hp * 2, 1e-6)).clamp(0, 1)) / 2)
    wants = torch.bernoulli(
        (alive * S.migration_prob
         * (S.migration_base_wander + S.migration_distress_gain * distress)).clamp(0, 1))

    water = world.poi[:, POILayout.WATER] * factor[:, ch["water"]]
    utility = ((food_supply / food_demand.clamp(min=1)).unsqueeze(0) * 0.3
               + water.unsqueeze(0) * 0.2
               + (1 - pop_per_poi
                  / world.poi[:, POILayout.CAPACITY].clamp(min=1)).unsqueeze(0) * 0.2
               + world.social_pull * 0.3)
    utility = utility - world.assign * 1e6
    best_val, target = utility.max(dim=1)
    free = (world.poi[:, POILayout.CAPACITY] - pop_per_poi).clamp(min=0)
    rank = capacity_rank(target, torch.where(wants > 0, best_val,
                                             torch.full_like(best_val, -1e9)))
    moves = wants * (best_val > 0).float() * (rank < free[target]).float()
    world.assign = torch.where(
        moves.unsqueeze(1) > 0,
        torch.nn.functional.one_hot(target, n_poi).float(), world.assign)
    world.log_masked(t, EVT["migration"], moves, poi=target,
                     val1=poi_idx.float())
    impact("migration", moves)

    # ── 9. SOZIALES + STELLUNG ─────────────────────────
    if t % S.social_interval == 0:
        npc[:, L.role_start():L.role_end()] = assign_roles(
            npc, L, S,
            demand=world.assign @ role_demand(smooth_provision(world, per_capita, S), S))
        npc[:, L.social_start():L.social_end()] = compute_social_embedding(
            npc, world.assign, world.poi, L, S)
        # Bindung wächst aus wiederholter Nähe und erodiert ohne Kontakt.
        # Ähnlichkeit allein ist keine Bindung – deshalb wird nichts materialisiert.
        world.bond_val.mul_(S.affect["trust_decay"])
        social.clear_dead(world.bond_idx, world.bond_val, alive)
        alive_bond = (world.bond_val >= S.bond_prune)
        world.bond_idx = torch.where(alive_bond, world.bond_idx,
                                     torch.full_like(world.bond_idx, -1))
        world.bond_val = world.bond_val * alive_bond

        poi_now = world.assign.argmax(dim=1)
        feats = social.social_features(npc, L, S)
        roster = social.build_roster(poi_now, n_poi, alive)
        peers = social.sample_peers(poi_now, *roster, S.bond_peer_samples)
        aff = (social.affinity(feats, idx.unsqueeze(1).expand(-1, peers.shape[1]),
                               peers, S.affinity_sigma)
               * (peers != idx.unsqueeze(1)).float() * alive[peers])
        best, j = aff.max(dim=1)
        social.bond_strengthen(
            world.bond_idx, world.bond_val, peers.gather(1, j.unsqueeze(1)).squeeze(1),
            best, alive * (best > S.bond_min).float())

        world.ties = social.ties(world.bond_val, 0.3)
        world.social_pull = social.bond_to_poi(world.bond_idx, world.bond_val,
                                               world.assign)
        standing = npc[:, L.role_start():L.role_end()] @ S.role_standing.to(dev)
        w_role = S.status_role_weight
        npc[:, L.col("status")] = (
            w_role * standing + 0.30 * (age / 60).clamp(max=1)
            + (0.70 - w_role) * (world.ties / world.ties.max().clamp(min=1))).clamp(0, 1)

    # ── 10. PAARBILDUNG ────────────────────────────────
    if t % 26 == 0:
        free_m = alive * (age >= 18).float() * (npc[:, L.col("sex")] < 0.5).float() \
            * (npc[:, L.col("partner")] < 0).float()
        free_f = alive * (age >= 18).float() * (npc[:, L.col("sex")] > 0.5).float() \
            * (npc[:, L.col("partner")] < 0).float()
        poi_now = world.assign.argmax(dim=1)
        feats = social.social_features(npc, L, S)
        cands = social.sample_peers(poi_now, *social.build_roster(poi_now, n_poi, alive),
                                    S.bond_peer_samples)
        aff = (social.affinity(feats, idx.unsqueeze(1).expand(-1, cands.shape[1]),
                               cands, S.affinity_sigma) * free_f[cands])
        best_val, j = aff.max(dim=1)
        mate = cands.gather(1, j.unsqueeze(1)).squeeze(1)
        cand = (free_m * (best_val > 0.3).float()
                * (torch.rand(NT, device=dev) < 0.15).float())
        keep = group_first_mask(mate, torch.where(cand > 0, best_val,
                                                  torch.full_like(best_val, -1e9)))
        pairs = cand * keep.float()
        f_dest = torch.where(pairs > 0, mate, torch.full_like(mate, TRASH))
        social.bond_strengthen(world.bond_idx, world.bond_val, mate,
                               torch.full_like(pairs, 0.85), pairs)
        social.bond_strengthen(world.bond_idx, world.bond_val, idx,
                               torch.zeros(NT, device=dev).scatter_(0, f_dest,
                                                                    pairs * 0.85),
                               torch.zeros(NT, device=dev).scatter_(0, f_dest, pairs))
        npc[:, L.col("partner")] = torch.where(pairs > 0, mate.float(),
                                               npc[:, L.col("partner")])
        npc[:, L.col("partner")].scatter_(0, f_dest, idx.float())
        world.log_masked(t, EVT["pair"], pairs, poi=poi_idx, npc_b=mate)
        world.log_masked(t, EVT["pair"],
                         torch.zeros(NT, device=dev).scatter_(0, f_dest, pairs),
                         poi=poi_idx, npc_b=idx)
        impact("pair", pairs)
        impact("pair", torch.zeros(NT, device=dev).scatter_(0, f_dest, pairs))
        npc[TRASH] = 0

    # ── 11. ALTERN ─────────────────────────────────────
    npc[:, age_col] += alive / 52.0

    # ── 12. KONFIGURIERTE EVENTS ───────────────────────
    for ei, evt in enumerate(S.raw.get("events", [])):
        if evt.get("season") and S.season_names[si] != evt["season"]:
            continue
        if world.rng.random() >= evt.get("probability", 0):
            continue
        lo, hi = evt.get("effect", {}).get("severity_range", [0.5, 1.0])
        severity = lo + world.rng.random() * (hi - lo)
        cal_loss = evt.get("effect", {}).get("calories_loss_days", 0) * severity
        hit = torch.zeros(NT, device=dev)
        for pi in evt.get("affected_pois", []):
            if pi < n_poi:
                hit = torch.maximum(hit, world.assign[:, pi] * alive)
        npc[:, cal_col] = (npc[:, cal_col] - hit * cal_loss).clamp(min=0)
        world.log_masked(t, EVT["climate"], hit, poi=poi_idx, val1=severity)
        impact("climate", hit * severity)

    # ── 13. AFFEKT ─────────────────────────────────────
    cal = npc[:, cal_col]
    hp = npc[:, hp_col]
    hunger = (1 - cal / S.hunger_threshold).clamp(0, 1)
    A = S.affect
    n_trait = npc[:, ts + L.trait_names.index("n")]

    load = 0.006 * hunger + 0.005 * danger_eff + 0.006 * (1 - hp)
    stress = (npc[:, L.col("stress")] * (1 - A["stress_decay"])
              + shock[:, 3] + load).clamp(0, 1) * alive
    npc[:, L.col("stress")] = stress

    temperament = A["temperament_base"] - A["temperament_n_weight"] * (n_trait - 0.5)
    v_base = (npc[:, L.col("valence_base")] + A["setpoint_shift"] * shock[:, 0]
              - A["setpoint_return"]
              * (npc[:, L.col("valence_base")] - temperament)).clamp(-1, 1)
    npc[:, L.col("valence_base")] = v_base * alive

    target_v = (v_base + 0.55 * (hp - 0.5)
                + 0.30 * ((cal / 15).clamp(max=1) - 0.5) - 0.25 * stress)
    npc[:, L.col("valence")] = ((A["valence_decay"] * npc[:, L.col("valence")]
                                 + (1 - A["valence_decay"]) * target_v
                                 + shock[:, 0]).clamp(-1, 1)) * alive
    target_a = (0.20 + 0.35 * danger_eff + 0.30 * hunger + 0.30 * stress
                + 0.15 * (n_trait - 0.5))
    npc[:, L.col("arousal")] = ((A["arousal_decay"] * npc[:, L.col("arousal")]
                                 + (1 - A["arousal_decay"]) * target_a
                                 + shock[:, 1]).clamp(0, 1)) * alive
    target_d = 0.10 + 0.35 * npc[:, L.col("status")] + 0.30 * hp + 0.25 * (1 - stress)
    npc[:, L.col("dominance")] = ((A["dominance_decay"] * npc[:, L.col("dominance")]
                                   + (1 - A["dominance_decay"]) * target_d
                                   + shock[:, 2]).clamp(0, 1)) * alive

    # ── 14. PERSÖNLICHKEITSDRIFT ───────────────────────
    pa = npc[:, L.col("parent_a")].long()
    pb = npc[:, L.col("parent_b")].long()
    n_children = torch.zeros(NT, device=dev)
    n_children.index_add_(0, pa.clamp(min=0), (pa >= 0).float() * alive)
    n_children.index_add_(0, pb.clamp(min=0), (pb >= 0).float() * alive)
    isolation = 1 - (world.ties / S.isolation_target).clamp(0, 1)
    kinship = (0.5 * (npc[:, L.col("partner")] >= 0).float()
               + 0.5 * (n_children / 3).clamp(max=1))
    drivers = torch.stack([stress, hunger, isolation, (1 - danger_eff) * hp, kinship],
                          dim=1)

    plast = plasticity(npc[:, age_col], S).unsqueeze(1)
    traits = npc[:, ts:te]
    base = npc[:, L.base_start():L.base_end()]
    npc[:, ts:te] = (traits + plast
                     * (drift * S.plast["event_scale"]
                        + (drivers @ S.chronic_matrix.to(dev)) * S.plast["chronic_scale"]
                        + (base - traits) * S.plast["homeostasis"])
                     * alive.unsqueeze(1)).clamp(0, 1)

    npc[TRASH] = 0
    world.tick += 1
    return {"tick": t, "births": born.sum(), "deaths": dead.sum(),
            "migrations": moves.sum(), "illnesses": sick.sum(),
            "injuries": hurt.sum(), "mourners": mourns.sum()}


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


def print_year_summary(world, totals):
    """Jahresbericht. Einzige Stelle, an der Zähler zum Host wandern."""
    parts = " | ".join(f"{k}: {int(v)}" for k, v in totals.items() if int(v))
    print(f"  {world.year}: {parts}")


# ============================================================
#  MAIN
# ============================================================

def run(world, n_weeks, on_year=None):
    """Führt Ticks ohne Host-Synchronisation aus. Zähler bleiben auf dem Device."""
    totals = {}
    for i in range(n_weeks):
        summary = tick(world)
        for k, v in summary.items():
            if k != "tick":
                totals[k] = totals.get(k, 0) + v
        if world.tick % 52 == 0:
            world.grow_log(52 * world.npc.shape[0])
            if on_year:
                on_year(world, totals)
            totals = {}
    return totals


def main():
    args = sys.argv[1:]

    if "--help" in args:
        print("Usage: python3 sim/tick_gpu.py [weeks] [--status] [--db] [--bench] "
              "[--config path] [--device cpu|mps|cuda]")
        return

    config_path = None
    device = DEVICE
    for i, a in enumerate(args):
        if a == "--config" and i + 1 < len(args):
            config_path = args[i + 1]
        if a == "--device" and i + 1 < len(args):
            device = get_device(args[i + 1])

    print(f"Device: {device}")
    world = init_world(config_path=config_path).to(device)

    use_db = "--db" in args
    if use_db:
        from db import init_db, snapshot, print_db_summary
        init_db(layout=world.layout)
        snapshot(world.to(torch.device("cpu")))
        world = world.to(device)
        print("  DB initialisiert, Tick 0 gesnapshoted.")

    n_weeks = 52
    for a in args:
        if a.isdigit():
            n_weeks = int(a)

    if "--status" in args:
        print_world_summary(world)
        return

    def on_year(w, totals):
        print_year_summary(w, totals)
        if use_db and w.tick % 52 == 0:
            snapshot(w.to(torch.device("cpu")))
            w.to(device)

    t0 = time.time()
    run(world, n_weeks, on_year=on_year)
    elapsed = time.time() - t0

    print_status(world)
    print(f"\n  {n_weeks} Wochen in {elapsed:.2f}s "
          f"({n_weeks / elapsed:.0f} Ticks/s, {elapsed / n_weeks * 1000:.2f} ms/Tick)")
    if float(world.dropped) > 0:
        print(f"  WARNUNG: {int(world.dropped)} Ereignisse verworfen (Puffer zu klein)")

    if use_db:
        print_db_summary()

    if "--bench" in args:
        print("\n  Benchmark: 5200 Ticks (100 Jahre)...")
        w2 = init_world(config_path=config_path, seed=42).to(device)
        t0 = time.time()
        run(w2, 5200)
        elapsed = time.time() - t0
        print(f"  100 Jahre in {elapsed:.2f}s ({5200 / elapsed:.0f} Ticks/s), "
              f"Pop: {w2.n_alive}")


if __name__ == "__main__":
    main()
