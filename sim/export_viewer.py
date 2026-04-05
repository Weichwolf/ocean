"""
OCEAN Simulator – Export Viewer-Daten.

Generiert viewer_data.json mit NPCs, Gebäuden, Beziehungen, Gruppen
für den Leaflet-basierten Map Viewer.
"""

import json
import sys
import os
import numpy as np

sys.path.insert(0, os.path.dirname(__file__))

from init_gpu import init_world
from world import load_config
from osm import (
    fetch_buildings, parse_buildings, settlements_with_coords,
    assign_buildings_to_settlements, select_usable_buildings,
    assign_npcs_to_buildings,
)


def export_viewer_data(world, config, path="sim/viewer_data.json"):
    L = world.layout
    alive = world.alive_mask
    alive_ids = alive.nonzero(as_tuple=True)[0].tolist()
    npc_buildings = getattr(world, "npc_buildings", {})

    # Siedlungs-Koordinaten
    settlements = settlements_with_coords(config)
    settlement_map = {s["name"]: s for s in settlements}

    # Faction-Farben
    faction_colors = {
        "pragmatiker": "#e67e22",
        "ludditen": "#27ae60",
        "interpreter": "#8e44ad",
        "nomaden": "#3498db",
        "hybride": "#e74c3c",
        "ungebunden": "#95a5a6",
    }

    # ── Nodes ───────────────────────────────────────────
    nodes = []
    for i in alive_ids:
        poi_idx = int((world.assign[i] > 0).nonzero(as_tuple=True)[0][0].item())
        faction_idx = int(world.npc[i, L.faction_start():L.faction_end()].argmax().item())
        role_idx = int(world.npc[i, L.role_start():L.role_end()].argmax().item())
        age = world.npc[i, L.col("age")].item()
        faction = L.faction_names[faction_idx]
        role = L.role_names[role_idx] if age >= 15 else "child"

        # Position: aus OSM-Gebäude oder Siedlungs-Fallback
        if i in npc_buildings:
            lat = npc_buildings[i]["lat"]
            lon = npc_buildings[i]["lon"]
            building = npc_buildings[i]
        else:
            s = settlement_map.get(world.poi_names[poi_idx], {})
            lat = s.get("lat", 52.1)
            lon = s.get("lon", 9.35)
            building = None

        node = {
            "id": i,
            "name": world.names[i],
            "age": int(age),
            "sex": "m" if world.npc[i, L.col("sex")].item() < 0.5 else "f",
            "lat": lat,
            "lon": lon,
            "poi": world.poi_names[poi_idx],
            "faction": faction,
            "role": role,
            "color": faction_colors.get(faction, "#999"),
            "ocean": {
                t: round(world.npc[i, L.col(t)].item(), 2)
                for t in L.trait_names
            },
            "health": round(world.npc[i, L.col("health")].item(), 2),
            "calories": round(world.npc[i, L.col("calories")].item(), 1),
            "valence": round(world.npc[i, L.col("valence")].item(), 2),
            "arousal": round(world.npc[i, L.col("arousal")].item(), 2),
            "status": round(world.npc[i, L.col("status")].item(), 2),
        }

        if building:
            node["building"] = {
                "osm_id": building["osm_id"],
                "type": building["type"],
                "address": building.get("address"),
            }

        # Eltern
        pa = int(world.npc[i, L.col("parent_a")].item())
        pb = int(world.npc[i, L.col("parent_b")].item())
        if pa >= 0:
            node["parent_a"] = pa
        if pb >= 0:
            node["parent_b"] = pb

        # Events für diesen NPC
        if world.event_log is not None and world.event_cursor > 0:
            npc_events = world.get_events(npc_id=i)
            if npc_events.shape[0] > 0:
                EVENT_NAMES = {1: "birth", 2: "death", 3: "illness", 4: "injury",
                               5: "migration", 6: "pair", 7: "adoption", 8: "climate"}
                evts = []
                for row in npc_events.cpu().numpy():
                    evts.append({
                        "tick": int(row[0]),
                        "type": EVENT_NAMES.get(int(row[1]), "unknown"),
                        "other": int(row[3]) if row[3] >= 0 else None,
                        "poi": int(row[4]) if row[4] >= 0 else None,
                        "val": round(float(row[5]), 2),
                    })
                node["events"] = evts

        nodes.append(node)

    # ── Edges (top connections per NPC) ─────────────────
    edges = []
    rel_np = world.rel.cpu().numpy() if world.rel.device.type != "cpu" else world.rel.numpy()
    trust_np = world.trust.cpu().numpy() if world.trust.device.type != "cpu" else world.trust.numpy()
    alive_set = set(alive_ids)

    for i in alive_ids:
        # Top 8 connections
        row = rel_np[i]
        top_indices = np.argsort(-row)[:20]
        for j in top_indices:
            j = int(j)
            if j not in alive_set or j <= i:
                continue
            aff = float(row[j])
            tr = float(trust_np[i, j])
            if aff > 0.15 or abs(tr) > 0.1:
                edges.append({
                    "source": i,
                    "target": j,
                    "affinity": round(aff, 3),
                    "trust": round(tr, 3),
                })

    # ── Households ──────────────────────────────────────
    households = []
    for a, b, kids in getattr(world, "households", []):
        if a in alive_set and b in alive_set:
            households.append({
                "partners": [a, b],
                "children": [k for k in kids if k in alive_set],
            })

    # ── Settlements ─────────────────────────────────────
    sett_list = []
    for pi in range(world.poi.shape[0]):
        s = settlement_map.get(world.poi_names[pi], {})
        members = (world.assign[:, pi] > 0) & alive
        pop = members.sum().item()
        sett_list.append({
            "name": world.poi_names[pi],
            "lat": s.get("lat", 0),
            "lon": s.get("lon", 0),
            "pop": pop,
            "capacity": int(world.poi[pi, 2].item()),
        })

    data = {
        "tick": world.tick,
        "year": world.year,
        "season": world.season_name,
        "nodes": nodes,
        "edges": edges,
        "households": households,
        "settlements": sett_list,
        "factions": list(L.faction_names),
        "faction_colors": faction_colors,
    }

    with open(path, "w") as f:
        json.dump(data, f, ensure_ascii=False)

    size_kb = os.path.getsize(path) / 1024
    print(f"Viewer data: {len(nodes)} NPCs, {len(edges)} edges, "
          f"{len(households)} households → {path} ({size_kb:.0f} KB)")
    return data


if __name__ == "__main__":
    config, layout, sim = load_config()
    world = init_world()

    # OSM
    bbox = config["meta"].get("osm_bbox")
    if bbox:
        settlements = settlements_with_coords(config)
        osm = fetch_buildings(bbox)
        buildings = parse_buildings(osm)
        by_settlement = assign_buildings_to_settlements(buildings, settlements)
        usable = select_usable_buildings(
            by_settlement, config["meta"].get("buildings_usable_pct", 0.02))
        from osm import ensure_enough_buildings
        usable = ensure_enough_buildings(usable, world, by_settlement)
        assign_npcs_to_buildings(world, usable)

    export_viewer_data(world, config)
