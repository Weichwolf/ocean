"""
OCEAN Simulator – OSM Integration.

Lädt Gebäude aus OpenStreetMap via Overpass API,
berechnet Centroids, ordnet sie Siedlungen zu,
und weist NPCs echten Gebäuden zu.
"""

import json
import math
import os
import urllib.request
import urllib.parse

OSM_CACHE = os.path.join(os.path.dirname(__file__), "osm_buildings.json")
OVERPASS_URL = "https://overpass-api.de/api/interpreter"


def fetch_buildings(bbox, cache_path=None):
    """Lade Gebäude von Overpass API. Cached lokal.

    bbox: (south, west, north, east) in WGS84
    """
    if cache_path is None:
        cache_path = OSM_CACHE

    if os.path.exists(cache_path):
        print(f"  OSM Cache: {cache_path}")
        with open(cache_path) as f:
            return json.load(f)

    s, w, n, e = bbox
    query = f"""[out:json][timeout:120];
(
  way["building"]({s},{w},{n},{e});
  relation["building"]({s},{w},{n},{e});
);
out body;
>;
out skel qt;"""

    print(f"  OSM Overpass: {len(query)} bytes query, bbox={bbox}")
    data = urllib.parse.urlencode({"data": query}).encode()
    req = urllib.request.Request(OVERPASS_URL, data=data)
    req.add_header("User-Agent", "OCEAN-Simulator/1.0")

    with urllib.request.urlopen(req, timeout=120) as resp:
        raw = json.loads(resp.read())

    with open(cache_path, "w") as f:
        json.dump(raw, f)

    print(f"  OSM: {len(raw['elements'])} elements cached → {cache_path}")
    return raw


def parse_buildings(osm_data):
    """Parse Overpass JSON → Liste von Buildings mit Centroid.

    Returns: [{
        "osm_id": int,
        "lat": float, "lon": float,  # Centroid
        "tags": dict,
        "type": str,  # building tag value
        "name": str | None,
        "address": str | None,
    }]
    """
    # Node-Index: id → (lat, lon)
    nodes = {}
    for el in osm_data["elements"]:
        if el["type"] == "node":
            nodes[el["id"]] = (el["lat"], el["lon"])

    buildings = []
    for el in osm_data["elements"]:
        if el["type"] != "way":
            continue
        tags = el.get("tags", {})
        if "building" not in tags:
            continue

        # Centroid aus Nodes berechnen
        way_nodes = el.get("nodes", [])
        lats, lons = [], []
        for nid in way_nodes:
            if nid in nodes:
                lat, lon = nodes[nid]
                lats.append(lat)
                lons.append(lon)

        if not lats:
            continue

        centroid_lat = sum(lats) / len(lats)
        centroid_lon = sum(lons) / len(lons)

        # Adresse zusammenbauen
        addr_parts = []
        if "addr:street" in tags:
            addr_parts.append(tags["addr:street"])
        if "addr:housenumber" in tags:
            addr_parts.append(tags["addr:housenumber"])

        buildings.append({
            "osm_id": el["id"],
            "lat": centroid_lat,
            "lon": centroid_lon,
            "tags": tags,
            "type": tags.get("building", "yes"),
            "name": tags.get("name"),
            "address": " ".join(addr_parts) if addr_parts else None,
        })

    return buildings


def haversine_km(lat1, lon1, lat2, lon2):
    """Distanz in km zwischen zwei WGS84-Koordinaten."""
    R = 6371
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2
         + math.cos(math.radians(lat1))
         * math.cos(math.radians(lat2))
         * math.sin(dlon / 2) ** 2)
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def assign_buildings_to_settlements(buildings, settlements):
    """Ordne jedes Gebäude der nächsten Siedlung zu.

    settlements: [{name, lat, lon, ...}]
    Returns: dict[settlement_name] → [building, ...]
    """
    result = {s["name"]: [] for s in settlements}

    for b in buildings:
        best_dist = float("inf")
        best_settlement = None
        for s in settlements:
            d = haversine_km(b["lat"], b["lon"], s["lat"], s["lon"])
            if d < best_dist:
                best_dist = d
                best_settlement = s["name"]
        if best_settlement and best_dist < 5.0:  # max 5km Radius
            b["settlement"] = best_settlement
            b["dist_km"] = round(best_dist, 3)
            result[best_settlement].append(b)

    return result


def select_usable_buildings(buildings_by_settlement, usable_pct=0.02, seed=2100):
    """Wähle X% der Gebäude als noch nutzbar aus.

    Bevorzugt: Wohngebäude, Bauernhöfe, massive Bauten.
    Meidet: Garagen, Schuppen, Dächer.
    Returns: dict[settlement] → [building, ...]
    """
    import random
    rng = random.Random(seed)

    # Priorisierung: höher = eher nutzbar
    PRIORITY = {
        "residential": 10, "house": 10, "detached": 10,
        "apartments": 12, "farm": 9, "terrace": 8,
        "semidetached_house": 9, "yes": 5,
        "church": 7, "civic": 7, "school": 6, "industrial": 4,
        "commercial": 3, "retail": 3,
        "garage": 0, "garages": 0, "shed": 0, "roof": 0,
        "hut": 1, "barn": 2, "farm_auxiliary": 1,
    }

    result = {}
    for settlement, buildings in buildings_by_settlement.items():
        # Sortiere nach Priorität (mit Jitter)
        scored = [(b, PRIORITY.get(b["type"], 3) + rng.random()) for b in buildings]
        scored.sort(key=lambda x: -x[1])

        n_usable = max(1, int(len(buildings) * usable_pct))
        result[settlement] = [b for b, _ in scored[:n_usable]]

    return result


def _building_dict(building, occupant_index=0):
    """Building-Dict mit ~2m Offset pro Bewohner (Kreis-Anordnung)."""
    import math
    lat, lon = building["lat"], building["lon"]
    if occupant_index > 0:
        # 2m ≈ 0.000018° lat, 0.000028° lon bei 52°N
        angle = (occupant_index * 2.39996)  # goldener Winkel → Spirale
        r = 0.000018 * (1 + occupant_index * 0.3)
        lat += r * math.cos(angle)
        lon += r * 1.55 * math.sin(angle)  # lon-Korrektur für Breitengrad
    return {
        "osm_id": building["osm_id"],
        "lat": lat,
        "lon": lon,
        "type": building["type"],
        "name": building.get("name"),
        "address": building.get("address"),
    }


def assign_npcs_to_buildings(world, usable_buildings):
    """Weise NPCs nutzbaren Gebäuden zu. Familien zusammen.

    1. Households (Init-Paare + Kinder) → ein Gebäude
    2. Übrige Erwachsene → eigenes Gebäude
    3. Kinder ohne Household → beim Elternteil (parent_a/parent_b)
       Falls Eltern kein Gebäude: beim nächsten Erwachsenen gleicher Siedlung
    """
    L = world.layout
    npc_buildings = {}
    households = getattr(world, "households", [])
    alive = world.alive_mask

    for poi_idx in range(world.poi.shape[0]):
        settlement_name = world.poi_names[poi_idx]
        buildings = usable_buildings.get(settlement_name, [])
        if not buildings:
            continue

        members = (world.assign[:, poi_idx] > 0) & alive
        member_set = set(members.nonzero(as_tuple=True)[0].tolist())
        if not member_set:
            continue

        assigned = set()
        b_idx = 0

        # Track occupants per building for offset
        building_occupants = {}  # osm_id → count

        def _place(npc_idx, building):
            oid = building["osm_id"]
            occ = building_occupants.get(oid, 0)
            npc_buildings[npc_idx] = _building_dict(building, occupant_index=occ)
            building_occupants[oid] = occ + 1
            assigned.add(npc_idx)

        # 1. Households: Familie bekommt ein Gebäude
        for a, b, kids in households:
            family = [x for x in [a, b] + kids if x in member_set]
            if not family:
                continue
            bld = buildings[b_idx % len(buildings)]
            for npc_idx in family:
                _place(npc_idx, bld)
            b_idx += 1

        # 2. Erwachsene ohne Household → eigenes Gebäude
        remaining = member_set - assigned
        adults = [i for i in remaining
                  if world.npc[i, L.col("age")].item() >= 15]
        children = [i for i in remaining
                    if world.npc[i, L.col("age")].item() < 15]

        for npc_idx in adults:
            _place(npc_idx, buildings[b_idx % len(buildings)])
            b_idx += 1

        # 3. Kinder → bei Eltern platzieren
        for child_idx in children:
            placed = False
            for parent_col in ["parent_a", "parent_b"]:
                pid = int(world.npc[child_idx, L.col(parent_col)].item())
                if pid >= 0 and pid in npc_buildings:
                    # Gleiches Gebäude wie Elternteil, nächster Offset
                    parent_osm = npc_buildings[pid]["osm_id"]
                    parent_bld = next(
                        (b for b in buildings if b["osm_id"] == parent_osm),
                        buildings[0])
                    _place(child_idx, parent_bld)
                    placed = True
                    break

            if not placed:
                if adults:
                    guardian = adults[child_idx % len(adults)]
                    g_osm = npc_buildings[guardian]["osm_id"]
                    g_bld = next(
                        (b for b in buildings if b["osm_id"] == g_osm),
                        buildings[0])
                    _place(child_idx, g_bld)
                else:
                    _place(child_idx, buildings[0])

    world.npc_buildings = npc_buildings
    return npc_buildings


def buildings_to_db(db, buildings, tick=0):
    """Schreibe Gebäude in DuckDB."""
    db.execute("""
        CREATE TABLE IF NOT EXISTS osm_buildings (
            osm_id BIGINT PRIMARY KEY,
            lat DOUBLE NOT NULL,
            lon DOUBLE NOT NULL,
            type VARCHAR,
            name VARCHAR,
            address VARCHAR,
            settlement VARCHAR,
            tags JSON
        )
    """)

    rows = [(b["osm_id"], b["lat"], b["lon"], b["type"],
             b.get("name"), b.get("address"),
             b.get("settlement"),
             json.dumps(b.get("tags", {})))
            for b in buildings]

    db.executemany("""
        INSERT OR IGNORE INTO osm_buildings
            (osm_id, lat, lon, type, name, address, settlement, tags)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, rows)

    # NPC-Building Zuordnung
    db.execute("""
        CREATE TABLE IF NOT EXISTS npc_buildings (
            npc_id INTEGER NOT NULL,
            tick INTEGER NOT NULL,
            osm_id BIGINT NOT NULL,
            PRIMARY KEY (npc_id, tick)
        )
    """)


def npc_buildings_to_db(db, npc_buildings, tick):
    """Schreibe NPC→Building Zuordnung in DB."""
    rows = [(int(npc_id), tick, int(b["osm_id"]))
            for npc_id, b in npc_buildings.items()]
    if rows:
        db.executemany("""
            INSERT OR IGNORE INTO npc_buildings (npc_id, tick, osm_id)
            VALUES (?, ?, ?)
        """, rows)


# ============================================================
#  Siedlungs-Koordinaten aus Config extrahieren
# ============================================================

def settlements_with_coords(config):
    """Konvertiere Config-Settlements (x/y in km) zu lat/lon.

    Braucht einen Referenzpunkt in der Config.
    Fallback: Münster St. Bonifatius, Hameln.
    """
    ref_lat = config.get("meta", {}).get("ref_lat", 52.1035)
    ref_lon = config.get("meta", {}).get("ref_lon", 9.3565)

    result = []
    for s in config["settlements"]:
        # x = Ost-West in km, y = Nord-Süd in km
        # 1° lat ≈ 111km, 1° lon ≈ 65km bei 52°N
        lat = ref_lat + s["y"] / 111.0
        lon = ref_lon + s["x"] / 65.0
        result.append({
            "name": s["name"],
            "lat": lat,
            "lon": lon,
        })

    return result


# ============================================================
#  MAIN – Test
# ============================================================

if __name__ == "__main__":
    from world import load_config

    config, layout, sim = load_config()

    # Siedlungs-Koordinaten
    settlements = settlements_with_coords(config)
    print(f"\nSiedlungen ({len(settlements)}):")
    for s in settlements:
        print(f"  {s['name']:<30s} {s['lat']:.4f}°N {s['lon']:.4f}°E")

    # Bounding Box berechnen
    lats = [s["lat"] for s in settlements]
    lons = [s["lon"] for s in settlements]
    margin = 0.01  # ~1km
    bbox = (min(lats) - margin, min(lons) - margin,
            max(lats) + margin, max(lons) + margin)
    print(f"\nBounding Box: {bbox}")

    # Buildings laden
    osm = fetch_buildings(bbox)
    buildings = parse_buildings(osm)
    print(f"\nGebäude: {len(buildings)}")

    # Typen
    types = {}
    for b in buildings:
        t = b["type"]
        types[t] = types.get(t, 0) + 1
    for t, n in sorted(types.items(), key=lambda x: -x[1])[:10]:
        print(f"  {t:<20s}: {n}")

    # Zuordnung
    by_settlement = assign_buildings_to_settlements(buildings, settlements)
    print(f"\nGebäude pro Siedlung (gesamt):")
    for name, blds in sorted(by_settlement.items(), key=lambda x: -len(x[1])):
        print(f"  {name:<30s}: {len(blds)}")

    # Nutzbare Gebäude (1-2%)
    usable_pct = config["meta"].get("buildings_usable_pct", 0.02)
    usable = select_usable_buildings(by_settlement, usable_pct)
    total_usable = sum(len(v) for v in usable.values())
    print(f"\nNutzbare Gebäude ({usable_pct*100:.0f}%): {total_usable}")
    for name, blds in sorted(usable.items(), key=lambda x: -len(x[1])):
        types = {}
        for b in blds:
            types[b["type"]] = types.get(b["type"], 0) + 1
        top = ", ".join(f"{t}:{n}" for t, n in sorted(types.items(), key=lambda x: -x[1])[:3])
        print(f"  {name:<30s}: {len(blds):3d}  ({top})")
