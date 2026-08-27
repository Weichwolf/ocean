# OCEAN – Config-Driven NPC World Simulator

A population simulator that generates living worlds with emergent social structures,
families, economies, and individual biographies. Every NPC has a personality, relationships,
a job, a home (real OSM building), and a history that emerges from simulation rather than
being scripted — and that history is written back into the NPC's state, not just into a log.

Built for open-world RPGs where NPCs need to feel like they've lived before the player arrives.

## What it does

Drop a `config.json` with traits, factions, roles, settlements, and seasons. The simulator
generates a population, assigns them to real buildings from OpenStreetMap, forms families,
and runs a week-by-week simulation where labour, resources, health, bonds, migration, births,
deaths, grief, and personality change play out as tensor operations.

After a simulated decade every surviving NPC has a queryable biography — and a personality
that differs measurably from the one they were born with, in the direction their life pushed it.

## Design constraints

Three properties drive every decision in this codebase:

| Constraint | Consequence |
|---|---|
| Events must change state, not only the log | Two-timescale affect + trait drift (§ Personality) |
| Roles must cause outcomes, not label them | Labour channels feed production, care, safety (§ Economy) |
| Population size is the point | No dense N² anywhere; sync-free tick (§ Tensors, § Performance) |

## Architecture

```
config.json          ← The only setting-specific file
     │
     ▼
┌─────────────────────────────────────────────────┐
│  world.py          TensorLayout, SimConfig      │
│  social.py         Bonds as (N, K) – no matrix  │
│  init_gpu.py       Vectorized world generation  │
│  tick_gpu.py       Weekly tick, branch-free     │
│  osm.py            OpenStreetMap buildings      │
│  db.py             DuckDB snapshots + queries   │
│  export_viewer.py  JSON export for viewer       │
│  viewer.html       Leaflet map UI               │
│  bench.py          CPU/GPU scaling benchmark    │
│  serve.py          Simulate + serve viewer      │
└─────────────────────────────────────────────────┘
```

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install torch duckdb faker scikit-learn

# Generate world, simulate 10 years, launch viewer
python3 sim/serve.py                 # → http://localhost:8080/viewer.html

# Or step by step:
python3 sim/init_gpu.py              # inspect initial state
python3 sim/tick_gpu.py 520          # 10 years
python3 sim/tick_gpu.py 5200         # 100 years
python3 sim/tick_gpu.py 520 --db     # with DuckDB snapshots
python3 sim/tick_gpu.py 520 --device mps
python3 sim/bench.py --scales 1,16,64,320
```

## The NPC tensor

Every NPC is a single row in a `(MAX_NPC + 1, D)` tensor. Columns are generated dynamically
from `config.json`. The extra row is a **trash row**: writes belonging to unselected elements
go there, which is what lets the tick run without branches (§ Tensors).

```
[traits] [constitution] [vitals] [emotions] [setpoint stress] [demographics]
 O C E A N   O C E A N   hp cal age  V A D    v_base  stress   sex born name

[faction₁..₆] [role₁..₂₅] [social₁..₆] [status alive parent_a parent_b partner]
```

For the Outshine config: `(4001, 63)` — 63 floats per NPC.

`constitution` is the OCEAN vector the NPC was **born with**. Current traits drift away from
it over a lifetime; the difference is the visible mark of a biography.

## Personality: what a life leaves behind

The naive version of this simulator stores a scalar `health` and calls the result a history.
It isn't: if a third of the population sits at health 0.2 permanently, health 0.2 says nothing
about anyone. State only carries biography if events move it and the movement persists.

### Two timescales of affect

```
valence      fast   weekly mood, decays in ~3 weeks
valence_base slow   affective setpoint, half-life ~3.3 years
stress       slow   allostatic load, half-life ~1.1 years
```

An event delivers an impulse to `valence`; a fraction (`setpoint_shift`) lands in
`valence_base`. The setpoint relaxes back toward a **temperament** derived from the N trait —
so adaptation is real but incomplete: bereavement raises N, higher N lowers the temperament,
and the mood floor stays lower afterwards. **The scar lives in the personality, and the
personality sets the mood floor.**

### Trait drift

```
plasticity(age) = exp(-age / 25 years)          # soft when young, set when old

Δtrait = plasticity · ( event_impulse · 0.20
                      + chronic_drivers · 0.0010
                      + (constitution - trait) · 0.004 )
```

Discrete events (illness, injury, migration, pairing, birth, bereavement, climate) push traits
in configured directions. Chronic conditions — stress, hunger, isolation, security, kinship —
push continuously. Homeostasis pulls back toward the constitution, so drift is a bounded
equilibrium rather than a random walk.

Everything is config: `impacts`, `chronic_drift`, `plasticity` in `config.json`.

### Grief propagates through bonds, not similarity

Affinity is *similarity*. If grief followed affinity, half a settlement would mourn every
death — measured: 32 % of all pairs exceeded the threshold, producing 8 bereavements per
person per year and saturating everyone's stress at 0.89.

Grief follows **bonds**: kinship (partner 1.0, child 0.9, parent 0.85, sibling 0.6) and
accumulated trust. Similarity only becomes a bond by growing into one over years of proximity.
A settlement-wide death toll adds a separate, smaller community shock to everyone present.

### Verification

30 simulated years, 642 living NPCs. Correlation between life history and current state:

| | ΔN | stress | valence_base | \|drift\| |
|---|---|---|---|---|
| bereavements | **0.68** | 0.40 | **−0.65** | 0.62 |
| migrations | 0.54 | 0.21 | −0.35 | 0.57 |
| illnesses | 0.22 | 0.12 | −0.13 | 0.07 |
| parenthood | 0.08 | 0.01 | 0.05 | 0.28 |

Dose–response by number of losses:

| losses | ΔN | valence_base | stress |
|---|---|---|---|
| 1–2 | +0.020 | +0.01 | 0.32 |
| 3–5 | +0.027 | −0.05 | 0.37 |
| 6+ | +0.199 | −0.36 | 0.56 |

Population-wide drift after 30 years: `N: μ=+0.13 σ=0.13 max=+0.53`, `E: μ=−0.05 min=−0.24`.

## Economy: roles that cause things

Roles used to be labels — 25 job titles assigned from trait scores, with food coming from a
per-settlement constant. Now every role declares what it **provides**:

| Channel | Providers | Effect |
|---|---|---|
| `food` | farmer 1.0, fisher 0.85, huntsman 0.6, cook 0.3, herbalist 0.25 | multiplies the settlement's yield |
| `water` | waterwarden 1.0 | raises effective water in migration utility |
| `care` | healer 1.0, herbalist 0.6, midwife 0.55, caretaker 0.4 | reduces disease and injury damage |
| `safety` | guard 1.0, marshal 0.85, scout 0.5, huntsman 0.3 | reduces accidents and effective danger |
| `craft` | builder 1.0, crafter 0.6, tinker 0.5, salvager 0.4 | maintains shelter against UV |

```
output_i  = role_provides · health_floored · (0.4 + 0.6·C)
per_capita_p = Σ_{i ∈ p} output_i / pop_p
factor_p  = floor + (1 - floor) · per_capita_p / target      (capped)
```

Lose your farmers and the yield falls to the foraging floor. That is the intended causality.
Four things had to be added to make it stable rather than lethal:

**Labour capacity needs a floor.** Capacity ∝ health creates hunger → weak → smaller harvest →
hunger with loop gain > 1. It wiped whole settlements in a single week. `0.35 + 0.65·health`
keeps the gain below 1: a famine becomes a decline, not an extinction.

**Roles need a demand signal.** Pure aptitude assignment gave Hameln-Kern 86 guards and one
cook. Role scores now include the settlement's shortfall per channel. That alone oscillates
in a 2-cycle (everyone switches to the same scarce job simultaneously), so switching carries
inertia and the demand signal is exponentially smoothed.

**Rations need a gradient.** Equal shares make a settlement starve in lockstep — everyone hits
zero calories the same week and dies the same week. Rations are `need × standing`, so scarcity
is graded and `status` finally has a consequence.

**Need is age-dependent, and children eat from the household.** Flat 14 000 kcal for a
five-year-old plus status-weighted rationing produced 48 % infant mortality. Need scales with
age, and a child's ration rank is inherited from its guardian.

The baseline config had to be recalibrated: the original settlement food levels held ~30 % of
the population at zero calories permanently, which only looked survivable because death
requires `health ≤ 0`. Settlement food is now 1.4× the original.

## Tensors: no dense N² anywhere

The affinity between two NPCs is a Gaussian kernel over an 11-dimensional feature vector:

```
features = [social_embedding(6D), traits × weights(5D)]
affinity(a,b) = exp(-‖f_a - f_b‖² / 2σ²)
```

A function of features never needs to be materialized. What *does* need storage is the part
that isn't a function of features — the actual bond — and that is sparse by nature.

```
before   rel, trust : (N, N) float32        806 MB at 9 840 NPCs
after    bond_idx   : (N, K) int64          K = 24 slots per NPC
         bond_val   : (N, K) float32        5.9 MB at 9 840 NPCs
```

Every social operation becomes a fixed-shape gather or scatter:

| Operation | Before | Now |
|---|---|---|
| grief from deaths | `trust @ dead`, N² | `Σ_k val · dead[idx]`, N·K |
| social pull per settlement | `rel @ assign`, N²·P | `einsum(nk,nkp→np)`, N·K·P |
| tie count | `(rel > τ).sum(1)`, N² | `(val > τ).sum(1)`, N·K |
| partner search | full N² affinity | 32 sampled peers from own settlement |
| bond formation | — | sorted roster + sampled peers, N log N |

Bonds grow from repeated proximity and erode without contact. Candidates come from
`build_roster` (one argsort groups the population by settlement) plus `sample_peers`
(uniform draws inside your own settlement) — both static-shape, both linear.

## The tick runs without asking the host anything

A branch-driven simulation is hostile to any accelerator: "who died, who was born, who
migrated" is a device→host round trip, and on Metal each one costs far more than the work
it guards.

```
                        CPU        MPS
kernel launch          1.6 µs     6.9 µs
nonzero → host         6.0 µs   797.0 µs      ×133
float(x.sum())         1.2 µs   243.0 µs      ×203
```

So the tick contains no `nonzero`, no `.item()`, no `.tolist()`, and no Python list of
households. Every selection is a float mask; every insertion is a `scatter_` whose unselected
entries are steered into the trash row. Newborn slots come from `cumsum` of the conception
mask, fathers from a Gumbel-top-K draw per settlement, migration capacity from a rank-within-
group computed by two stable sorts. Counters (`max_id`, event cursor, dropped events) stay on
the device; they are read once per simulated year, which is also when the event buffer grows.

Names never touch the hot path: the tensor holds a `name_idx`, resolved to a string only at
export.

## Performance

Apple A18 Pro, 6 cores (2P + 4E), 8 GB unified memory, PyTorch 2.8, ms per weekly tick:

| NPCs | state | CPU | MPS | MPS/CPU |
|---|---|---|---|---|
| 615 | 0.5 MB | **3.8** | 20.1 | 0.19× |
| 2 460 | 1.6 MB | **8.8** | 18.7 | 0.47× |
| 9 840 | 5.9 MB | 24.3 | **21.3** | 1.14× |
| 39 360 | 23.4 MB | 86.7 | **42.8** | 2.03× |
| 98 400 | 58.4 MB | 204.9 | **120.9** | 1.69× |
| 196 800 | 116.6 MB | 460.9 | **267.5** | 1.72× |

The crossover is at ~10 000 NPCs. Below it the arrays are too small to fill the GPU and launch
overhead dominates; above it the GPU wins by roughly its memory-bandwidth advantage over two
performance cores. At 196 800 NPCs a tick costs 1.36 µs per NPC — a simulated year of a
200 000-person world takes 14 seconds.

**On the Neural Engine:** PyTorch cannot target it. `torch.device("mps")` is the *GPU*; the ANE
is reachable only through CoreML, with static shapes and a narrow op set (essentially conv and
matmul in fp16). This tick needs scatter, gather, sort, cumsum and RNG, none of which the ANE
exposes. The tensor design here — fixed shapes, no data-dependent control flow, no host
round trips — is a precondition for such an export, not a substitute for it.

## Simulation tick

Each week, in order:

1. **Labour** – per-settlement provision per channel from the current role distribution
2. **Resources** – yield × labour factor, rationed by need × standing
3. **Health** – recovery, UV (shelter from craft), hunger, disease (raised by stress, damped by
   care), accidents (damped by safety), age decay, allostatic cost
4. **Death** – health zero, old age, frailty
5. **Grief** – bond-weighted loss + settlement-wide community shock
6. **Orphans** – adopted by the highest-standing partnered household in the settlement
7. **Births** – Gumbel-sampled father per settlement, OCEAN inherited with noise, constitution
   fixed at birth
8. **Migration** – graded by distress, capacity-limited by rank within destination
9. **Social** (every 4 weeks) – roles by aptitude + demand + inertia, embeddings, bond growth
   and decay, status
10. **Pairing** (every 26 weeks) – best of 32 sampled peers, one partner per person
11. **Aging**, **seasonal events**, **affect update**, **trait drift**

Steps 1–11 are pure tensor operations over the full population.

## Social model

Bonds are directed `(N, K)` lists. A bond is strengthened by proximity (each social update,
the strongest of 32 sampled settlement peers), by kinship at birth and adoption, and by
pairing. It decays 1 % per social update and is pruned below 0.02, so a relationship that
receives no reinforcement fades within a few years. Bonds to the dead are released.

Roles (25) are assigned from trait scores, gender bias, age gates, settlement demand and
switching inertia — the last two are what turn a job title into an economic position.

## OSM integration

Buildings are loaded from OpenStreetMap via Overpass API (cached locally). A configurable
percentage (default 2 %) is marked usable, prioritizing residential buildings. NPCs are
assigned to real buildings with real coordinates. Families share a building; cohabitants are
offset ~2 m in a golden-angle spiral for map visibility.

## Event log

Pre-allocated tensor `(N, 7)`: `[tick, type, npc_a, npc_b, poi_id, val1, val2]`.
Types: birth, death, illness, injury, migration, pair, adoption, climate, bereavement.

Appends are sync-free: the write position is `cursor + cumsum(mask) - 1`, overflow rows land
in a trash row and are counted in `dropped` (reported, never silent). The buffer grows once
per simulated year with enough headroom for the next.

A death is recorded against the deceased *and* their parent, so `get_events(npc_id)` returns
the death of your child as part of your history.

## Viewer

Leaflet map on real OSM tiles. Click an NPC:

- OCEAN bars with a **tick mark at the value they were born with** and the signed drift
- VAD emotions plus affective setpoint and stress
- Health, calories, status, family (partner, children, parents — clickable)
- Event history including bereavements with the name of the person lost
- Bonds with strength, OSM building link

## DuckDB

Optional persistence via `--db`. Schema generated from config. Tables: `npcs` (with traits),
`npc_state` (health, calories, VAD, stress, setpoint, social vector per snapshot), `edges`
(bonds — written from the `(N,K)` list, so snapshots are O(N·K) not O(N²)), `groups` (HDBSCAN),
`events`, `world_state`, `osm_buildings`, `npc_buildings`.

```sql
SELECT n.name, n.role, ns.health, ns.stress, ns.valence_base
FROM npcs n JOIN npc_state ns ON ns.npc_id = n.id
WHERE ns.tick = (SELECT MAX(tick) FROM npc_state)
ORDER BY ns.stress DESC LIMIT 10;
```

## Quest system (design)

Quests are not scripts. They are **constraints on the world state**, evaluated periodically
while the simulation keeps running.

An LLM reads an NPC's tensor state, drift, and event history and recognizes quest potential:

```
Frieder: health 0.14, calories 0, daughter Regine (7),
         partner Hülya separated (Hameln-Kern, Elder),
         4 migrations in 10 years, N drifted +0.31 since birth
→ escort quest (bring Regine to Hülya)
```

```json
{
  "id": "quest_001", "origin_tick": 520, "origin_npc": 238, "status": "active",
  "objectives": [
    {"type": "item_acquire", "item": "beinwell_salbe", "poi": 4},
    {"type": "npc_at_poi",   "npc": 642, "poi": 0}
  ],
  "fail_conditions": [{"type": "npc_dead", "npc": 642}]
}
```

The world doesn't wait. Frieder may die in 4–6 weeks; Hülya may migrate. The time window is
implicit and never displayed — it follows from the world state.

Success and failure both change that state. A high-A NPC is grateful; a low-A NPC calculates
what they owe you; a high-N NPC remembers you saved them and becomes anxious about losing you.
There is no objective reputation, only perspectives.

## Why simulate before playing

A randomly initialized NPC has stats but no history. After simulation every number is a
consequence — and, since events now move personality, so is the personality.

For the first generation (alive at tick 0) the history is thin. Their children have a complete
one. **The second generation is the first real one.** Measured over 100 years at ~700 NPCs:

| Year | Population | Founders alive | Born in sim | Median age |
|---|---|---|---|---|
| 1 | 630 | 599 | 31 | 25 |
| 20 | 666 | 382 | 284 | 34 |
| 50 | 704 | 156 | 548 | 27 |
| 70 | 709 | 3 | 706 | 26 |
| 100 | 687 | **0** | 687 | 23 |

By year 80 nobody alive was part of the initialization. 100 years = 5 200 ticks in 63 s on CPU.

Dead NPCs keep their tensor row: `max_npcs` sizes the *cumulative* population, not the
concurrent one (2 614 slots used over a century at ~700 concurrent). Slot recycling with
stable UIDs is the obvious next step for very long runs.

## 3D open world pipeline

The simulation produces a living world with real coordinates.

**Terrain** — OSM has no elevation; SRTM/Copernicus DEM gives 30 m globally. Heightmap
(GeoTIFF) → vertex grid → engine.

**Buildings** — OSM footprints with `building:levels`, `height`, `roof:shape`,
`building:material`. Extrude footprint × levels × 3 m; instanced rendering for 30 k buildings.

**Roads** — `highway=*` LineStrings as ribbon meshes on terrain, width by road type.

**Vegetation** — procedural from the climate model, not from OSM:

```
water_access > 0.8  → dense subtropical jungle (gravel pit lakes)
altitude > 200m     → dead tree trunks, erosion
near river          → reeds, sparse willows
else                → steppe, dust, dunes
```

**NPCs** — already have coordinates, buildings, personalities, families. Animation parameters
map from the tensor:

```
E high  → longer stride, arms wider        C high     → upright posture, even gait
N high  → head lowered, shoulders raised   health low → short steps, slight sway
A high  → leans toward conversation partner  stress high → guarded, faster scanning
```

IK is solved infrastructure (FABRIK converges in 2–3 iterations). The work is mapping tensor
values to blend weights.

**Character models** — ~30 meshes plus texture swaps cover 600 NPCs:

```
5 base bodies (m/f × young/old/child) × 6 faction outfits
× 3 condition stages × 25 role items
```

Sources: Synty, Quaternius, Mixamo, or Meshy/Tripo3D for stylized.

## Engine: Godot 4

- **Scenes are text files** (`.tscn`) – writable from CLI, no GUI needed
- **Headless mode** – `godot --headless --script build_world.gd`
- **Vulkan** (Forward+), Metal via MoltenVK, OpenGL fallback for web
- **Cross-platform** from one codebase, **GDScript** maps directly from the simulation
- **GDExtension** for C/C++/Rust bindings, **no revenue share**, MIT

```bash
godot --headless --export-release "Windows" build/game.exe
godot --headless --export-release "Web" build/game.html
```

Communication: shared memory or TCP socket. The tensor state is the single source of truth;
Godot renders it.

## Included: Outshine config

Post-apocalyptic Weserbergland (Hameln/Kirchohsen), ~2100, +7 °C, no cloud formation.
Machines have won; humans live in the gaps.

- 13 settlements, 6 factions, 615 initial NPCs, 100 POIs with lore (`POI_HAMELN.md`)
- Full concept document (`DESIGN.md`)

## License

Unlicensed. Do what you want.
