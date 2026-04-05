# OCEAN – Config-Driven NPC World Simulator

A GPU-accelerated population simulator that generates living worlds with emergent social structures, families, economies, and individual biographies. Every NPC has a personality, relationships, a job, a home (real OSM building), and a history that emerges from simulation rather than being scripted.

Built for open-world RPGs where NPCs need to feel like they've lived before the player arrives.

## What it does

Drop a `config.json` with traits, factions, roles, settlements, and seasons. The simulator generates a population, assigns them to real buildings from OpenStreetMap, forms families based on personality compatibility, and runs a week-by-week simulation where resources, health, social bonds, migration, births, deaths, and pair formation play out on the GPU.

After 10 simulated years, every surviving NPC has a queryable biography: where they lived, who they loved, what they survived. This is the state an LLM reads to roleplay that character.

## Architecture

```
config.json          ← The only setting-specific file
     │
     ▼
┌─────────────────────────────────────────────────┐
│  world.py          TensorLayout from config     │
│  init_gpu.py       Population generation        │
│  tick_gpu.py       GPU tick (PyTorch MPS/CUDA)  │
│  osm.py            OpenStreetMap buildings       │
│  db.py             DuckDB snapshots + queries   │
│  export_viewer.py  JSON export for viewer       │
│  viewer.html       Leaflet map UI               │
│  serve.py          HTTP server                  │
└─────────────────────────────────────────────────┘
```

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install torch duckdb faker scikit-learn

# Generate world + simulate 10 years + launch viewer
python3 sim/serve.py
# → opens http://localhost:8080/viewer.html

# Or step by step:
python3 sim/init_gpu.py              # inspect initial state
python3 sim/tick_gpu.py 520          # 10 years
python3 sim/tick_gpu.py 520 --db     # with DuckDB snapshots
python3 sim/tick_gpu.py 5200 --bench # 100 years benchmark
```

## The NPC tensor

Every NPC is a single row in a `(MAX_NPC, D)` tensor. Columns are generated dynamically from `config.json`:

```
[traits...]  [vitals]  [emotions]  [demographics]  [faction₁..ₙ]  [role₁..ₙ]  [social₁..₆]  [status] [alive] [parents]
 O C E A N   hp cal age  V A D      sex born_tick   one-hot        one-hot      embedding      float    bool    a  b
```

For the Outshine config: `(2000, 54)` – 54 floats per NPC, 2000 slots.

## What's in config.json

| Section | Controls |
|---|---|
| `meta` | Name, start year, max NPCs, locale, OSM bbox |
| `names` | Faker locale for name generation (deterministic seed) |
| `traits` | Personality dimensions (OCEAN or any model) |
| `vitals` | health, calories, age |
| `emotions` | VAD (valence, arousal, dominance) |
| `factions` | Names, trait profiles (mean/std), 2D embeddings |
| `roles` | Trait-based scoring, gender bias, min age, 2D embeddings |
| `seasons` | Food/water/UV/disease multipliers per season |
| `simulation` | All rates: fertility, mortality, migration, recovery, damage |
| `events` | Configurable seasonal events (flash floods, etc.) |
| `settlements` | Name, position, capacity, water, food, danger, shelter, faction, population |

Change the config, get a different world. OCEAN traits can be replaced with HEXACO or any other model.

## Simulation tick

Each week, in order:

1. **Resources** – food production per settlement (seasonal), distributed to NPCs
2. **Health** – recovery, UV damage, hunger, disease (Bernoulli), accidents, age decay
3. **Death** – health zero, old age, frailty
4. **Orphan adoption** – children with dead parents adopted by nearest household
5. **Births** – fertility based on health + calories, OCEAN inherited from parents with noise
6. **Migration** – desperate NPCs move to settlements with better food/water/social ties
7. **Social update** (every 4 weeks) – role assignment, social embedding, affinity matrix
8. **Pair formation** (every 26 weeks) – singles matched by affinity within settlement
9. **Aging** – +1/52 years
10. **Seasonal events** – from config (flash floods, etc.)
11. **VAD update** – emotions follow health and resources
12. **Event logging** – all events to tensor log, O(1) append

Everything is tensor operations. No Python loops over NPCs for core simulation. 48 ticks/s on Apple MPS for 600 NPCs.

## Social model

### Affinity (who likes whom)

NPC similarity in an embedding space:

```
features = [social_embedding(6D), traits × weights(5D)]  → 11D vector
affinity(a,b) = exp(-||features_a - features_b||² / 2σ²)
```

Social embedding = position + faction embedding + role embedding. Computed via matrix operations, no pairwise loops.

### Pair formation

Singles within the same settlement are matched by affinity. Vectorized: `aff_block = rel[m_ids][:, f_ids]` gives an (n_m × n_f) affinity matrix. Best match per male, 15% chance per half-year, greedy assignment.

### Families

Households track (partner_a, partner_b, [children]). Children inherit OCEAN from parents with Gaussian noise. Orphans are adopted by the nearest household in the same settlement.

### Roles (25)

Assigned from trait scores with gender bias and age restrictions:

```
farmer, fisher, herbalist, cook, waterwarden,
crafter, tanner, builder, salvager, tinker,
guard, scout, huntsman, marshal,
healer, midwife, caretaker, preacher, interpreter,
trader, courier, courtesan, gravedigger, thief,
elder
```

Scores are normalized by weight sum so roles with more trait terms don't dominate.

## OSM integration

Buildings are loaded from OpenStreetMap via Overpass API (cached locally). Only a configurable percentage (default 2%) are marked as usable – prioritizing residential buildings. NPCs are assigned to real buildings with real coordinates. Families share a building. Cohabitants are offset ~2m in a golden-angle spiral for map visibility.

## Event log

Pre-allocated tensor `(N, 7)` with auto-growing buffer. Columns: `[tick, type, npc_a, npc_b, poi_id, val1, val2]`. Types: birth, death, illness, injury, migration, pair formation, adoption, climate. O(1) append, batch logging for mass events. Queryable: `world.get_events(npc_id=238)` returns all events for that NPC.

## Viewer

Leaflet-based map viewer on real OSM tiles. Click an NPC to see:

- OCEAN personality bars
- VAD emotions with discrete labels (happy, sad, afraid, angry, tense, content)
- Health, calories, status
- Family (partner, children, parents – clickable)
- Event history (illness, migration, pair formation, etc.)
- Top connections with affinity/trust values
- OSM building link

Toggle connection lines and household overlays. Search by name, role, or faction.

## DuckDB

Optional persistence via `--db` flag. Schema generated dynamically from config (trait columns). Tables:

- `npcs` – stammdaten with traits
- `npc_state` – per-snapshot state (health, calories, VAD, social vector)
- `edges` – affinity + trust per snapshot
- `groups` – HDBSCAN clusters per snapshot
- `events` – event log
- `world_state` – population, season per tick
- `osm_buildings` – building data with settlement assignment
- `npc_buildings` – NPC → building mapping

Query example – who is Frieder, what happened to him:

```sql
SELECT n.name, n.faction, n.role, ns.health, ns.calories_stored
FROM npcs n JOIN npc_state ns ON ns.npc_id = n.id
WHERE n.name = 'Frieder' AND ns.tick = (SELECT MAX(tick) FROM npc_state);
```

## Quest system (design)

Quests are not scripts. They are **constraints on the world state** that are periodically evaluated while the simulation continues to run.

### How a quest is born

An LLM reads an NPC's tensor state + event history + relationships and recognizes quest potential:

```
Frieder: health 0.14, calories 0, daughter Regine (7),
         partner Hülya separated (Hameln-Kern, Elder),
         4 migrations in 10 years, injured.
→ LLM generates: escort quest (bring Regine to Hülya)
```

The LLM doesn't script the quest – it derives objectives from the world state.

### Quest as data

```json
{
  "id": "quest_001",
  "origin_tick": 520,
  "origin_npc": 238,
  "status": "active",
  "objectives": [
    {"type": "item_acquire", "item": "beinwell_salbe", "poi": 4},
    {"type": "npc_at_poi",   "npc": 642, "poi": 0},
    {"type": "npc_interact", "npc": 312, "item": "drahtfigur"}
  ],
  "fail_conditions": [
    {"type": "npc_dead", "npc": 642},
    {"type": "npc_dead", "npc": 312}
  ]
}
```

### The world doesn't wait

The simulation ticks while the player is on the quest. Frieder has health 0.14 – he may die in 4-6 weeks. Hülya may migrate. Machine activity on the route may change. The quest has an implicit time window that is never displayed – it follows from the world state.

### Consequence

Success and failure both change the world state: trust shifts, reputation changes, NPCs react based on their OCEAN profile. A high-A NPC is grateful. A low-A NPC calculates what they owe you. A high-N NPC remembers you saved them and becomes anxious about losing you.

### No quest journal needed

The player's reputation is distributed across NPC perspectives. There is no objective reputation – only perspectives (from DESIGN.md). The same player action produces different reactions from different NPCs based on their personality, relationship, and what they heard through the rumor system.

## Why simulate before playing

A randomly initialized NPC has stats but no history. After 10 years of simulation, every number is a consequence: health 0.14 because three summers of drought in Tündern, negative valence because a partner left, high trust with a neighbor because they survived the same epidemic.

For the first generation (alive at tick 0), the history is thin – they have no simulated childhood. Their children, born during the simulation, have a complete biography. **The second generation is the first real one.** After 100 years, nobody alive was part of the initialization – every living NPC is a product of the system.

This is what the LLM reads when it speaks as that character. It doesn't invent a backstory – it translates one.

## 3D open world pipeline

The simulation produces a living world with real coordinates. Turning it into a 3D game:

### Terrain

OSM has no elevation, but SRTM/Copernicus DEM provides 30m resolution globally. The Wesertal, the Klüt (258m), the Suntel (400m) – all available as heightmaps.

```
Heightmap (GeoTIFF) → Mesh (Vertex Grid) → Engine
```

### Buildings

OSM buildings have footprints (polygons), often with `building:levels`, `height`, `roof:shape`, `building:material`. Extrude footprint × levels × 3m, add roof from tag or default. For 30k buildings: instanced rendering.

### Roads

OSM `highway=*` tags with LineString geometry. Ribbon mesh on terrain. Width from road type. In 2150: asphalt cracked, dunes over highways, machine tracks keeping strips passable.

### Vegetation

Not from OSM – procedural from the climate model:

```
water_access > 0.8  → dense subtropical jungle (gravel pit lakes)
altitude > 200m     → dead tree trunks, erosion
near river          → reeds, sparse willows
else                → steppe, dust, dunes
```

### NPCs

Already have real coordinates, buildings, personalities, families. Position = their OSM building. Animation parameters from OCEAN:

```
E high  → longer stride, arms wider
N high  → head lowered, shoulders raised
A high  → leans toward conversation partner
C high  → upright posture, even gait
health low → short steps, slight sway
```

IK (inverse kinematics) is solved infrastructure in engines – FABRIK converges in 2-3 iterations. The actual work is mapping tensor values to animation blend weights.

### Character models

~20 base meshes varied by texture/color/clothing/age cover 600 NPCs:

```
5 base bodies  (m/f × young/old/child)
× 6 faction outfits (colors, materials)
× 3 condition stages (healthy/sick/injured)
× 25 role items (weapon/satchel/tools/nothing)
= ~30 meshes + texture swaps
```

Sources: Synty Studios (low-poly packs), Quaternius (free), Mixamo (animations), or AI-generated via Meshy/Tripo3D for stylized.

## Engine: Godot 4

Godot is the target engine. Reasons:

- **Scenes are text files** (`.tscn`) – writable from CLI like JSON, no GUI needed
- **Headless mode** – `godot --headless --script build_world.gd`
- **Vulkan** (Forward+), Metal via MoltenVK, OpenGL fallback for web
- **Cross-platform** from one codebase: Windows, macOS, Linux, Web, Android, iOS, Steam Deck
- **GDScript** is Python-like – direct mapping from our simulation code
- **GDExtension** for C/C++/Rust bindings to our PyTorch simulation
- **No revenue share**, open source (MIT)

```bash
# Export from CLI, no GUI
godot --headless --export-release "Windows" build/game.exe
godot --headless --export-release "Web" build/game.html
```

Communication between simulation and engine: SharedMemory or TCP socket. The tensor state is the single source of truth – Godot renders it.

## Included: Outshine config

The repository ships with a config for **Outshine** – a post-apocalyptic setting in the Weserbergland (Hameln/Kirchohsen), ~2100, +7°C global temperature, no cloud formation. Machines have won. Humans live in the gaps.

- 13 settlements (Hameln-Kern, Kirchohsen, Oase Ohr, etc.)
- 6 factions (Pragmatiker, Ludditen, Interpreter, Nomaden, Hybride, Ungebunden)
- 615 initial NPCs
- 100 POIs with lore (see POI_HAMELN.md)
- Full concept document (see DESIGN.md)

## Performance

| Operation | Time |
|---|---|
| 1 year (52 ticks), 600 NPCs, MPS | ~1s |
| 10 years (520 ticks) | ~11s |
| 100 years (5200 ticks) | ~110s |
| Event log append | O(1) |
| Affinity matrix (600×600) | O(n²) but single GPU op |
| Pair formation | O(n_singles) tensor ops |
| Social clustering (HDBSCAN) | O(n log n) |

## License

Unlicensed. Do what you want.
