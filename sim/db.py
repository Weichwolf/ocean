"""
OCEAN Simulator – Tensor ↔ DuckDB Sync.

Snapshots der GPU-Tensoren in DuckDB.
Graph, NPCs, Gruppen, Events – querybar.
"""

import duckdb
import numpy as np
import os
import torch
from sklearn.cluster import HDBSCAN

from world import POILayout as P, WorldState

DB_PATH = os.path.join(os.path.dirname(__file__), "outshine.db")
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")

# Schwellenwerte
EDGE_THRESHOLD = 0.12      # Mindest-Affinität für eine Kante
TRUST_THRESHOLD = 0.05     # Mindest-Trust für eine Kante


def get_db():
    return duckdb.connect(DB_PATH)


def init_db(layout=None):
    """Erstelle DB und Schema. Trait-Spalten aus Layout generiert."""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    db = duckdb.connect(DB_PATH)

    # Basis-Schema laden
    with open(SCHEMA_PATH) as f:
        schema = f.read()

    # Trait-Spalten dynamisch einfügen
    if layout:
        trait_cols = ",\n    ".join(f'"{t}" DOUBLE NOT NULL' for t in layout.trait_names)
        schema = schema.replace("-- TRAIT_COLUMNS", ",\n    " + trait_cols)
    else:
        schema = schema.replace("-- TRAIT_COLUMNS", "")

    for stmt in schema.split(";"):
        stmt = stmt.strip()
        if stmt:
            db.execute(stmt)
    db.close()


def _to_np(tensor):
    """Tensor → numpy, egal ob GPU oder CPU."""
    if tensor.device.type != "cpu":
        tensor = tensor.cpu()
    return tensor.detach().numpy()


def snapshot(world: WorldState, db=None):
    """Schreibe kompletten Weltzustand in DuckDB."""
    close_db = db is None
    if db is None:
        db = get_db()

    L = world.layout
    tick = world.tick
    npc_np = _to_np(world.npc)
    poi_np = _to_np(world.poi)
    assign_np = _to_np(world.assign)
    bond_idx = _to_np(world.bond_idx).astype(int)
    bond_val = _to_np(world.bond_val)
    alive = npc_np[:, L.col("alive")] > 0.5

    alive_ids = np.where(alive)[0]
    n_alive = len(alive_ids)

    # ── POIs (nur beim ersten Snapshot) ─────────────────
    existing = db.execute("SELECT COUNT(*) FROM pois").fetchone()[0]
    if existing == 0:
        for pi in range(poi_np.shape[0]):
            db.execute("""
                INSERT INTO pois (id, name, category, x, y, carrying_capacity,
                                  water_access, food_production, danger_level,
                                  shelter_quality)
                VALUES (?, ?, 'settlement', ?, ?, ?, ?, ?, ?, ?)
            """, [pi, world.poi_names[pi],
                  float(poi_np[pi, P.X]), float(poi_np[pi, P.Y]),
                  int(poi_np[pi, P.CAPACITY]),
                  float(poi_np[pi, P.WATER]), float(poi_np[pi, P.FOOD]),
                  float(poi_np[pi, P.DANGER]), float(poi_np[pi, P.SHELTER])])

    # ── NPCs (upsert) ──────────────────────────────────
    faction_names = L.faction_names
    role_names = L.role_names
    trait_names = L.trait_names

    for i in range(world.n_created):
        poi_idx = int(assign_np[i].argmax())
        fs, fe = L.faction_start(), L.faction_end()
        rs, re = L.role_start(), L.role_end()
        faction_idx = int(npc_np[i, fs:fe].argmax())
        role_idx = int(npc_np[i, rs:re].argmax())
        age = npc_np[i, L.col("age")]

        exists = db.execute("SELECT 1 FROM npcs WHERE id = ?", [int(i)]).fetchone()
        if exists:
            params = [world.poi_names[poi_idx] if poi_idx < len(world.poi_names) else str(poi_idx),
                      faction_names[faction_idx],
                      role_names[role_idx] if age >= 15 else "child"]
            if not alive[i]:
                db.execute("""
                    UPDATE npcs SET home_poi = (SELECT id FROM pois WHERE name = ?),
                                    faction = ?, role = ?, died_tick = ?
                    WHERE id = ? AND died_tick IS NULL
                """, [*params, tick, int(i)])
            else:
                db.execute("""
                    UPDATE npcs SET home_poi = (SELECT id FROM pois WHERE name = ?),
                                    faction = ?, role = ?
                    WHERE id = ?
                """, [*params, int(i)])
        else:
            sex = "m" if npc_np[i, L.col("sex")] < 0.5 else "f"
            pa = int(npc_np[i, L.col("parent_a")])
            pb = int(npc_np[i, L.col("parent_b")])
            parent_a = pa if pa >= 0 else None
            parent_b = pb if pb >= 0 else None
            ts = L.trait_start()
            trait_vals = [float(npc_np[i, ts + j]) for j in range(L.n_traits)]
            quoted_traits = ', '.join(f'"{t}"' for t in trait_names)
            db.execute(f"""
                INSERT INTO npcs (id, name, born_tick, sex, parent_a, parent_b,
                                  home_poi, faction, role,
                                  {quoted_traits})
                VALUES ({', '.join(['?'] * (9 + L.n_traits))})
            """, [int(i), world.names[i], int(npc_np[i, L.col("born_tick")]), sex,
                  parent_a, parent_b,
                  poi_idx, faction_names[faction_idx],
                  role_names[role_idx] if age >= 15 else "child",
                  *trait_vals])

    # ── NPC State ───────────────────────────────────────
    state_rows = []
    ss, se = L.social_start(), L.social_end()
    for i in alive_ids:
        poi_idx = int(assign_np[i].argmax())
        social = npc_np[i, ss:se].tolist()
        state_rows.append((
            int(i), tick, poi_idx,
            float(npc_np[i, L.col("health")]),
            float(npc_np[i, L.col("calories")]),
            float(npc_np[i, L.col("valence")]),
            float(npc_np[i, L.col("arousal")]),
            float(npc_np[i, L.col("dominance")]),
            float(npc_np[i, L.col("status")]),
            float(npc_np[i, L.col("stress")]),
            float(npc_np[i, L.col("valence_base")]),
            social,
        ))
    if state_rows:
        db.executemany("""
            INSERT INTO npc_state (npc_id, tick, poi_id, health, calories_stored,
                                   valence, arousal, dominance, status, stress,
                                   valence_base, social_vec)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, state_rows)

    # ── Kanten aus der Bindungsliste: O(N·K) statt O(N²) ─
    live = set(int(x) for x in alive_ids)
    seen = set()
    edge_rows = []
    for i in alive_ids:
        for k in range(bond_idx.shape[1]):
            j, v = int(bond_idx[i, k]), float(bond_val[i, k])
            if j < 0 or j not in live or v <= EDGE_THRESHOLD:
                continue
            key = (min(int(i), j), max(int(i), j))
            if key in seen:
                continue
            seen.add(key)
            edge_rows.append((tick, key[0], key[1], round(v, 4)))

    if edge_rows:
        db.executemany("""
            INSERT INTO edges (tick, npc_a, npc_b, bond)
            VALUES (?, ?, ?, ?)
        """, edge_rows)

    # ── Gruppen (HDBSCAN) ──────────────────────────────
    social_vecs = npc_np[alive, ss:se]
    n_groups = 0
    if len(social_vecs) > 10:
        clusterer = HDBSCAN(min_cluster_size=3, min_samples=2)
        labels = clusterer.fit_predict(social_vecs)

        unique_labels = set(labels)
        unique_labels.discard(-1)
        n_groups = len(unique_labels)

        group_rows = []
        member_rows = []
        for label in unique_labels:
            member_mask = labels == label
            member_ids = alive_ids[member_mask]
            # POI der Mehrheit
            poi_counts = {}
            for mid in member_ids:
                pi = int(assign_np[mid].argmax())
                poi_counts[pi] = poi_counts.get(pi, 0) + 1
            main_poi = max(poi_counts, key=poi_counts.get)

            group_rows.append((tick, int(label), main_poi,
                               world.poi_names[main_poi], len(member_ids)))
            for mid in member_ids:
                member_rows.append((tick, int(label), int(mid)))

        if group_rows:
            db.executemany("""
                INSERT INTO groups (tick, group_id, poi_id, poi_name, n_members)
                VALUES (?, ?, ?, ?, ?)
            """, group_rows)
        if member_rows:
            db.executemany("""
                INSERT INTO group_members (tick, group_id, npc_id)
                VALUES (?, ?, ?)
            """, member_rows)

    # ── World State ─────────────────────────────────────
    season_names = ["winter", "spring", "summer", "autumn"]
    db.execute("""
        INSERT OR REPLACE INTO world_state (tick, year, week, season,
                                            n_alive, n_groups)
        VALUES (?, ?, ?, ?, ?, ?)
    """, [tick, world.year, world.week, world.season_name, n_alive, n_groups])

    if close_db:
        db.close()

    return {
        "tick": tick,
        "n_alive": n_alive,
        "n_edges": len(edge_rows),
        "n_groups": n_groups,
    }


def snapshot_periodic(world: WorldState, interval=52):
    """Snapshot nur alle `interval` Ticks (default: jährlich)."""
    if world.tick % interval == 0:
        return snapshot(world)
    return None


# ============================================================
#  Queries – Graph aus DB lesen
# ============================================================

def query_npc(db, npc_id, tick=None):
    """Hole NPC mit aktuellem State."""
    if tick is None:
        tick = db.execute("SELECT MAX(tick) FROM npc_state WHERE npc_id = ?",
                          [npc_id]).fetchone()[0]
    return db.execute("""
        SELECT n.*, ns.health, ns.calories_stored, ns.valence, ns.arousal,
               ns.dominance, ns.status, p.name as poi_name
        FROM npcs n
        JOIN npc_state ns ON ns.npc_id = n.id AND ns.tick = ?
        JOIN pois p ON p.id = ns.poi_id
        WHERE n.id = ?
    """, [tick, npc_id]).fetchone()


def query_neighbors(db, npc_id, tick=None, limit=10):
    """Top-N Beziehungen eines NPC."""
    if tick is None:
        tick = db.execute("SELECT MAX(tick) FROM edges").fetchone()[0]
    return db.execute("""
        SELECT CASE WHEN e.npc_a = ? THEN e.npc_b ELSE e.npc_a END as other_id,
               n.name, e.bond,
               ns.health, p.name as poi_name
        FROM edges e
        JOIN npcs n ON n.id = CASE WHEN e.npc_a = ? THEN e.npc_b ELSE e.npc_a END
        LEFT JOIN npc_state ns ON ns.npc_id = n.id AND ns.tick = ?
        LEFT JOIN pois p ON p.id = ns.poi_id
        WHERE e.tick = ? AND (e.npc_a = ? OR e.npc_b = ?)
        ORDER BY e.bond DESC
        LIMIT ?
    """, [npc_id, npc_id, tick, tick, npc_id, npc_id, limit]).fetchall()


def query_group(db, npc_id, tick=None):
    """Finde Gruppe eines NPC und alle Mitglieder."""
    if tick is None:
        tick = db.execute("SELECT MAX(tick) FROM group_members").fetchone()[0]
    group = db.execute("""
        SELECT gm.group_id, g.poi_name, g.n_members
        FROM group_members gm
        JOIN groups g ON g.tick = gm.tick AND g.group_id = gm.group_id
        WHERE gm.tick = ? AND gm.npc_id = ?
    """, [tick, npc_id]).fetchone()
    if not group:
        return None, []
    members = db.execute("""
        SELECT n.id, n.name, n.faction, n.role,
               ROUND(n.o, 2), ROUND(n.c, 2), ROUND(n.e, 2),
               ROUND(n.a, 2), ROUND(n.n, 2)
        FROM group_members gm
        JOIN npcs n ON n.id = gm.npc_id
        WHERE gm.tick = ? AND gm.group_id = ?
    """, [tick, group[0]]).fetchall()
    return group, members


def query_family_tree(db, npc_id, depth=3):
    """Stammbaum: Eltern, Kinder, Geschwister."""
    npc = db.execute("SELECT * FROM npcs WHERE id = ?", [npc_id]).fetchone()
    if not npc:
        return None

    tree = {"npc": npc, "parents": [], "children": [], "siblings": []}

    # Eltern
    if npc[6] is not None:  # parent_a
        tree["parents"].append(
            db.execute("SELECT id, name, faction, born_tick, died_tick FROM npcs WHERE id = ?",
                       [npc[6]]).fetchone())
    if npc[7] is not None:  # parent_b
        tree["parents"].append(
            db.execute("SELECT id, name, faction, born_tick, died_tick FROM npcs WHERE id = ?",
                       [npc[7]]).fetchone())

    # Kinder
    tree["children"] = db.execute("""
        SELECT id, name, faction, born_tick, died_tick
        FROM npcs WHERE parent_a = ? OR parent_b = ?
        ORDER BY born_tick
    """, [npc_id, npc_id]).fetchall()

    # Geschwister (gleiche Eltern)
    if npc[6] is not None or npc[7] is not None:
        tree["siblings"] = db.execute("""
            SELECT id, name, born_tick, died_tick
            FROM npcs
            WHERE id != ?
              AND ((parent_a = ? AND ? IS NOT NULL)
                OR (parent_b = ? AND ? IS NOT NULL))
        """, [npc_id, npc[6], npc[6], npc[7], npc[7]]).fetchall()

    return tree


def query_settlement_graph(db, poi_name, tick=None):
    """Alle NPCs und Beziehungen in einer Siedlung."""
    if tick is None:
        tick = db.execute("SELECT MAX(tick) FROM npc_state").fetchone()[0]
    return db.execute("""
        SELECT n.id, n.name, n.faction, n.role,
               ns.health, ns.calories_stored, ns.status,
               ROUND(n.o,2), ROUND(n.c,2), ROUND(n.e,2),
               ROUND(n.a,2), ROUND(n.n,2)
        FROM npcs n
        JOIN npc_state ns ON ns.npc_id = n.id AND ns.tick = ?
        JOIN pois p ON p.id = ns.poi_id
        WHERE p.name = ? AND n.died_tick IS NULL
        ORDER BY ns.status DESC
    """, [tick, poi_name]).fetchall()


def print_db_summary(db=None):
    """Zusammenfassung der DB."""
    close = db is None
    if db is None:
        db = get_db()

    ticks = db.execute("SELECT MIN(tick), MAX(tick), COUNT(*) FROM world_state").fetchone()
    npcs = db.execute("SELECT COUNT(*) FROM npcs").fetchone()[0]
    alive = db.execute("SELECT COUNT(*) FROM npcs WHERE died_tick IS NULL").fetchone()[0]
    edges = db.execute("SELECT COUNT(*) FROM edges WHERE tick = ?", [ticks[1]]).fetchone()[0]
    groups = db.execute("SELECT COUNT(*) FROM groups WHERE tick = ?", [ticks[1]]).fetchone()[0]
    states = db.execute("SELECT COUNT(*) FROM npc_state").fetchone()[0]

    print(f"\n{'='*55}")
    print(f"  DATENBANK: {DB_PATH}")
    print(f"{'='*55}")
    print(f"  Snapshots:    {ticks[2]} (Tick {ticks[0]}–{ticks[1]})")
    print(f"  NPCs total:   {npcs} ({alive} lebend)")
    print(f"  NPC States:   {states}")
    print(f"  Edges:        {edges} (letzter Snapshot)")
    print(f"  Gruppen:      {groups} (letzter Snapshot)")

    # Siedlungen letzter Snapshot
    if ticks[1] is not None:
        print(f"\n  Siedlungen (Tick {ticks[1]}):")
        rows = db.execute("""
            SELECT p.name, COUNT(ns.npc_id) as pop, p.carrying_capacity,
                   ROUND(AVG(ns.health), 2), ROUND(AVG(ns.calories_stored), 1)
            FROM pois p
            LEFT JOIN npc_state ns ON ns.poi_id = p.id AND ns.tick = ?
            LEFT JOIN npcs n ON n.id = ns.npc_id AND n.died_tick IS NULL
            GROUP BY p.name, p.carrying_capacity
            ORDER BY pop DESC
        """, [ticks[1]]).fetchall()
        for r in rows:
            print(f"    {r[0]:<30s} {r[1]:3d}/{r[2]:3d}  HP:{r[3]}  Cal:{r[4]}d")

    if close:
        db.close()
    print()


if __name__ == "__main__":
    import sys
    if "--init" in sys.argv:
        init_db()
        print("DB initialisiert.")
    else:
        print_db_summary()
