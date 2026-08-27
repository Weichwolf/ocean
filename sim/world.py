"""
OCEAN – Generischer NPC/World Simulator.

Tensor-Layout dynamisch aus JSON-Config generiert.
Traits, Factions, Roles, Seasons, Events – alles konfigurierbar.
"""

import json
import os
import torch
import numpy as np
from dataclasses import dataclass, field

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")


def get_device(name=None):
    """CPU ist Vorgabe. Der Tick verzweigt wöchentlich über Bevölkerungsereignisse
    (wer starb, wer gebar, wer zog fort); jede dieser Fragen ist eine Device→Host-
    Runde. Auf MPS kostet ein `nonzero` 671 µs gegen 7 µs auf der CPU – gemessen
    schlägt die CPU MPS bis mindestens 10 000 NPCs (sim/bench.py)."""
    name = name or os.environ.get("OCEAN_DEVICE", "cpu")
    if name == "auto":
        name = "cuda" if torch.cuda.is_available() else "cpu"
    if name == "mps" and not torch.backends.mps.is_available():
        name = "cpu"
    return torch.device(name)


DEVICE = get_device()


# ============================================================
#  CONFIG LOADER
# ============================================================

class TensorLayout:
    """Dynamisches Tensor-Layout, generiert aus Config."""

    def __init__(self, config):
        self.config = config
        self.columns = {}   # name → index
        self.ranges = {}    # group_name → (start, end)
        self._offset = 0

        # ── Traits (OCEAN oder beliebig) ────────────────
        trait_names = []
        for name, spec in config["traits"].items():
            short = spec["short"]
            self._add_col(f"trait_{short}", alias=short)
            trait_names.append(short)
        self.trait_names = trait_names
        self.n_traits = len(trait_names)
        self.ranges["traits"] = (self.columns[f"trait_{trait_names[0]}"],
                                 self.columns[f"trait_{trait_names[-1]}"] + 1)

        # ── Trait-Konstitution (Setpoint bei Geburt) ────
        start = self._offset
        for short in trait_names:
            self._add_col(f"base_{short}")
        self.ranges["trait_base"] = (start, self._offset)

        # ── Vitals ──────────────────────────────────────
        for name in config["vitals"]:
            self._add_col(name)

        # ── Emotions (schnell) ──────────────────────────
        for name in config["emotions"]:
            self._add_col(name)

        # ── Affekt-Langzeit (Setpoint + allostatische Last)
        self._add_col("valence_base")
        self._add_col("stress")

        # ── Demographics ────────────────────────────────
        self._add_col("sex")
        self._add_col("born_tick")
        self._add_col("name_idx")

        # ── Factions (one-hot) ──────────────────────────
        self.faction_names = list(config["factions"].keys())
        start = self._offset
        for fname in self.faction_names:
            self._add_col(f"faction_{fname}")
        self.ranges["factions"] = (start, self._offset)

        # ── Roles (one-hot) ─────────────────────────────
        self.role_names = list(config["roles"].keys())
        start = self._offset
        for rname in self.role_names:
            self._add_col(f"role_{rname}")
        self.ranges["roles"] = (start, self._offset)

        # ── Social Embedding ────────────────────────────
        self.social_dim = config["simulation"]["social_embed_dim"]
        start = self._offset
        for i in range(self.social_dim):
            self._add_col(f"social_{i}")
        self.ranges["social"] = (start, self._offset)

        # ── Status + Alive + Parents ────────────────────
        self._add_col("status")
        self._add_col("alive")
        self._add_col("parent_a")
        self._add_col("parent_b")
        self._add_col("partner")

        self.D_NPC = self._offset

    def _add_col(self, name, alias=None):
        self.columns[name] = self._offset
        if alias:
            self.columns[alias] = self._offset
        self._offset += 1

    def __getattr__(self, name):
        if name.startswith("_") or name in ("columns", "ranges", "config",
                                             "trait_names", "faction_names",
                                             "role_names", "n_traits",
                                             "social_dim", "D_NPC",
                                             "provide_names"):
            raise AttributeError(name)
        if name in self.columns:
            return self.columns[name]
        if name in self.ranges:
            return self.ranges[name]
        raise AttributeError(f"No column or range '{name}' in layout")

    def col(self, name):
        return self.columns[name]

    def trait_start(self):
        return self.ranges["traits"][0]

    def trait_end(self):
        return self.ranges["traits"][1]

    def base_start(self):
        return self.ranges["trait_base"][0]

    def base_end(self):
        return self.ranges["trait_base"][1]

    def faction_start(self):
        return self.ranges["factions"][0]

    def faction_end(self):
        return self.ranges["factions"][1]

    def role_start(self):
        return self.ranges["roles"][0]

    def role_end(self):
        return self.ranges["roles"][1]

    def social_start(self):
        return self.ranges["social"][0]

    def social_end(self):
        return self.ranges["social"][1]


class NameTable:
    """Namen liegen als Index im Tensor. Auflösung erst bei der Ausgabe."""

    def __init__(self, npc, layout, names_m, names_f):
        self.npc, self.layout = npc, layout
        self.pools = (names_m, names_f)

    def __getitem__(self, i):
        col = self.layout.col
        pool = self.pools[int(self.npc[i, col("sex")] > 0.5)]
        return pool[int(self.npc[i, col("name_idx")]) % len(pool)]

    def __len__(self):
        return self.npc.shape[0]


class POILayout:
    X, Y, CAPACITY, WATER, FOOD, DANGER, SHELTER = 0, 1, 2, 3, 4, 5, 6
    D_POI = 7


class SimConfig:
    """Alle Simulations-Parameter aus der Config."""

    def __init__(self, config):
        self.raw = config
        sim = config["simulation"]

        # Scalare
        self.recovery_rate = sim["recovery_rate"]
        self.uv_damage_factor = sim["uv_damage_factor"]
        self.hunger_zero = sim["hunger_damage"]["zero"]
        self.hunger_low = sim["hunger_damage"]["low"]
        self.hunger_threshold = sim["hunger_damage"]["threshold"]
        self.disease_base = sim["disease_base_rate"]
        self.accident_base = sim["accident_base_rate"]
        self.age_decay_start = sim["age_decay_start"]
        self.age_decay_rate = sim["age_decay_rate"]
        self.fertility_rate = sim["fertility_rate"]
        self.fertility_min_age = sim["fertility_min_age"]
        self.fertility_max_age = sim["fertility_max_age"]
        self.fertility_min_health = sim["fertility_min_health"]
        self.fertility_min_calories = sim["fertility_min_calories"]
        self.infant_shield_age = sim["infant_shield_age"]
        self.infant_shield_factor = sim["infant_shield_factor"]
        self.migration_cal = sim["migration_threshold_calories"]
        self.migration_hp = sim["migration_threshold_health"]
        self.migration_prob = sim["migration_probability"]
        self.migration_distress_gain = sim["migration_distress_gain"]
        self.migration_base_wander = sim["migration_base_wander"]
        self.max_births_per_poi = sim["max_births_per_settlement_tick"]
        self.bond_slots = sim["bond_slots"]
        self.bond_peer_samples = sim["bond_peer_samples"]
        self.bond_min = sim["bond_min"]
        self.bond_prune = sim["bond_prune"]
        self.calorie_need = sim["calorie_need_week"]
        self.need_child_floor = sim["calorie_need_child_floor"]
        self.need_adult_age = sim["calorie_need_adult_age"]
        self.social_interval = sim["social_update_interval"]
        self.affinity_sigma = sim["affinity_sigma"]
        self.affinity_blend = sim["affinity_blend_rate"]
        self.max_npcs = config["meta"]["max_npcs"]
        self.start_year = config["meta"]["start_year"]
        self.age_dist = sim["age_distribution"]

        # Saison-Tensoren
        season_order = list(config["seasons"].keys())
        self.season_names = season_order
        self.season_food = torch.tensor([config["seasons"][s]["food"] for s in season_order])
        self.season_water = torch.tensor([config["seasons"][s]["water"] for s in season_order])
        self.season_uv = torch.tensor([config["seasons"][s]["uv"] for s in season_order])
        self.season_disease = torch.tensor([config["seasons"][s]["disease"] for s in season_order])
        self.season_weeks = [config["seasons"][s]["weeks"] for s in season_order]

        # Trait-Gewichte für Social Embedding
        trait_shorts = [v["short"] for v in config["traits"].values()]
        self.trait_social_weights = torch.tensor([
            sim["trait_social_weights"].get(s, 0.1) for s in trait_shorts
        ])

        # Fraktions-Embeddings
        self.faction_embed = torch.tensor([
            config["factions"][f]["embed"] for f in config["factions"]
        ], dtype=torch.float32)

        # Rollen-Embeddings
        self.role_embed = torch.tensor([
            config["roles"][r]["embed"] for r in config["roles"]
        ], dtype=torch.float32)

        # Rollen-Scores: für jede Rolle, welche Traits mit welchem Gewicht
        self.role_score_matrix = self._build_role_scores(config, trait_shorts)

        self.min_age_vec = None
        self.age_override_vec = None

        # Rollen mit min_age
        self.role_min_ages = {}
        for rname, rspec in config["roles"].items():
            if "min_age" in rspec:
                self.role_min_ages[rname] = rspec["min_age"]

        # Gender bias pro Rolle: (n_roles, 2) – [m_bonus, f_bonus]
        roles = list(config["roles"].keys())
        self.role_gender_bias = torch.zeros(len(roles), 2)
        for ri, rname in enumerate(roles):
            gb = config["roles"][rname].get("gender_bias", {})
            self.role_gender_bias[ri, 0] = gb.get("m", 0.0)
            self.role_gender_bias[ri, 1] = gb.get("f", 0.0)

        # Rollen-Standing (soziale Stellung → status/dominance)
        self.role_standing = torch.tensor(
            [config["roles"][r].get("standing", 0.4) for r in roles])

        # ── Versorgungskanäle: welche Rolle liefert was ──
        labor = config["labor"]
        self.provide_names = list(labor["channels"].keys())
        self.provide_matrix = torch.zeros(len(roles), len(self.provide_names))
        for ri, rname in enumerate(roles):
            for ch, amount in config["roles"][rname].get("provides", {}).items():
                self.provide_matrix[ri, self.provide_names.index(ch)] = amount
        self.labor_target = torch.tensor(
            [labor["channels"][c]["target"] for c in self.provide_names])
        self.labor_floor = torch.tensor(
            [labor["channels"][c]["floor"] for c in self.provide_names])
        self.labor_ceiling = torch.tensor(
            [labor["channels"][c]["ceiling"] for c in self.provide_names])
        self.work_age_min = labor["work_age_min"]
        self.work_age_max = labor["work_age_max"]
        self.labor_trait_idx = trait_shorts.index(labor["trait"])
        self.labor_trait_weight = labor["trait_weight"]
        self.care_damage_reduction = labor["care_damage_reduction"]
        self.safety_accident_reduction = labor["safety_accident_reduction"]
        self.safety_danger_reduction = labor["safety_danger_reduction"]
        self.craft_shelter_weight = labor["craft_shelter_weight"]
        self.ch = {name: i for i, name in enumerate(self.provide_names)}

        # ── Affekt / Plastizität ────────────────────────
        self.affect = config["affect"]
        self.kin_bond = self.affect["kin_bond"]
        self.plast = config["plasticity"]
        self.isolation_target = sim["isolation_target_ties"]
        self.demand_weight = labor["demand_weight"]
        self.role_inertia = labor["role_inertia"]
        self.demand_smoothing = labor["demand_smoothing"]
        self.capacity_health_floor = labor["capacity_health_floor"]
        self.ration_inequality = labor["ration_inequality"]
        self.household_share = labor["household_share"]
        self.status_role_weight = sim["status_role_weight"]

        # Impacts: name → (vad_stress[4], drift[n_traits])
        self.impact_vad = {}
        self.impact_drift = {}
        for name, spec in config["impacts"].items():
            self.impact_vad[name] = torch.tensor([
                spec.get("valence", 0.0), spec.get("arousal", 0.0),
                spec.get("dominance", 0.0), spec.get("stress", 0.0)])
            d = torch.zeros(len(trait_shorts))
            for short, w in spec.get("drift", {}).items():
                if short in trait_shorts:
                    d[trait_shorts.index(short)] = w
            self.impact_drift[name] = d

        # Chronische Drift: (n_driver, n_traits), Reihenfolge = driver_names
        self.driver_names = list(config["chronic_drift"].keys())
        self.chronic_matrix = torch.zeros(len(self.driver_names), len(trait_shorts))
        for di, dname in enumerate(self.driver_names):
            for short, w in config["chronic_drift"][dname].items():
                if short in trait_shorts:
                    self.chronic_matrix[di, trait_shorts.index(short)] = w

    def _build_role_scores(self, config, trait_shorts):
        """Baue Matrix (n_roles, n_traits) für Rollenzuweisung."""
        roles = list(config["roles"].keys())
        n_roles = len(roles)
        n_traits = len(trait_shorts)
        matrix = torch.zeros(n_roles, n_traits)

        for ri, rname in enumerate(roles):
            score_spec = config["roles"][rname].get("score", {})
            for trait_key, weight in score_spec.items():
                inverted = trait_key.startswith("-")
                short = trait_key.lstrip("-")
                if short in trait_shorts:
                    ti = trait_shorts.index(short)
                    matrix[ri, ti] = -weight if inverted else weight

        return matrix

    def build_age_gates(self, layout):
        """Altersschranken als Vektoren statt als Python-Schleife über Rollen."""
        n = len(layout.role_names)
        self.min_age_vec = torch.zeros(n)
        self.age_override_vec = torch.zeros(n)
        cfg = self.raw.get("roles", {})
        for rname, min_age in self.role_min_ages.items():
            ri = layout.role_names.index(rname)
            self.min_age_vec[ri] = min_age
            if not cfg.get(rname, {}).get("score"):
                self.age_override_vec[ri] = 1.0

    def to(self, device):
        """Config-Tensoren einmalig aufs Device. Ohne das kopiert jeder Zugriff neu."""
        for k, v in self.__dict__.items():
            if torch.is_tensor(v):
                setattr(self, k, v.to(device))
            elif isinstance(v, dict) and v and all(torch.is_tensor(x) for x in v.values()):
                setattr(self, k, {kk: vv.to(device) for kk, vv in v.items()})
        return self

    def season_idx(self, tick):
        w = tick % 52
        for i, (start, end) in enumerate(self.season_weeks):
            if start <= w < end:
                return i
        return 0


# ============================================================
#  WORLD STATE
# ============================================================

@dataclass
class WorldState:
    npc: torch.Tensor
    poi: torch.Tensor
    assign: torch.Tensor
    bond_idx: torch.Tensor
    bond_val: torch.Tensor
    tick: int
    max_id: int
    events: list = field(default_factory=list)
    names: list = field(default_factory=list)
    poi_names: list = field(default_factory=list)
    names_m: list = field(default_factory=list)
    names_f: list = field(default_factory=list)

    # Event log tensor: (MAX_EVENTS, 7)
    # Columns: [tick, type, npc_a, npc_b, poi_id, val1, val2]
    # type: 0=none, 1=birth, 2=death, 3=illness, 4=injury, 5=migration,
    #       6=pair, 7=adoption, 8=climate
    event_log: torch.Tensor = None
    cursor: torch.Tensor = None
    dropped: torch.Tensor = None
    ties: torch.Tensor = None
    _rows: torch.Tensor = None
    prov_ema: torch.Tensor = None
    social_pull: torch.Tensor = None

    # References to config objects
    layout: TensorLayout = None
    sim: SimConfig = None

    def to(self, device):
        self.npc = self.npc.to(device)
        self.poi = self.poi.to(device)
        self.assign = self.assign.to(device)
        self.bond_idx = self.bond_idx.to(device)
        self.bond_val = self.bond_val.to(device)
        if self.event_log is not None:
            self.event_log = self.event_log.to(device)
        if self.cursor is not None:
            self.cursor = self.cursor.to(device)
        if self.dropped is not None:
            self.dropped = self.dropped.to(device)
        if self.ties is not None:
            self.ties = self.ties.to(device)
        if self.prov_ema is not None:
            self.prov_ema = self.prov_ema.to(device)
        if self.social_pull is not None:
            self.social_pull = self.social_pull.to(device)
        if self.sim is not None:
            self.sim.to(device)
        if torch.is_tensor(self.max_id):
            self.max_id = self.max_id.to(device)
        return self

    @property
    def event_cursor(self):
        return int(self.cursor.item())

    def log_masked(self, tick, etype, mask, poi=None, npc_b=None, val1=0.0):
        """Hängt ein Ereignis je gesetztem Maskenbit an. Ohne Device→Host-Runde.

        Die Schreibposition folgt aus cumsum(mask); überzählige Zeilen landen in der
        Papierkorbzeile am Ende des Puffers und werden in `dropped` gezählt.
        """
        if self.event_log is None:
            return
        cap = self.event_log.shape[0] - 1
        pos = (self.cursor + torch.cumsum(mask, 0) - 1).long()
        fits = (mask > 0) & (pos < cap)
        self.dropped = self.dropped + ((mask > 0) & (pos >= cap)).sum()

        n = mask.shape[0]
        dev = mask.device
        if self._rows is None or self._rows.shape[0] != n:
            self._rows = torch.zeros(n, 7, device=dev)
        rows = self._rows
        rows[:, 0] = tick
        rows[:, 1] = etype
        rows[:, 2] = torch.arange(n, device=dev, dtype=torch.float32)
        rows[:, 3] = -1 if npc_b is None else npc_b.float()
        rows[:, 4] = -1 if poi is None else poi.float()
        rows[:, 5] = val1 if torch.is_tensor(val1) else float(val1)
        self.event_log[torch.where(fits, pos, torch.full_like(pos, cap))] = rows
        self.cursor = self.cursor + mask.sum()

    def grow_log(self, headroom):
        """Vergrößert den Ereignispuffer. Einzige Host-Synchronisation der Schleife –
        Aufruf gehört außerhalb des Ticks, typisch einmal pro Jahr."""
        if self.event_log is None:
            return
        cap = self.event_log.shape[0] - 1
        while cap - self.event_cursor < headroom:
            cap *= 2
        if cap != self.event_log.shape[0] - 1:
            grown = torch.zeros(cap + 1, 7, device=self.event_log.device)
            grown[:self.event_log.shape[0] - 1] = self.event_log[:-1]
            self.event_log = grown

    def get_events(self, npc_id=None, tick_start=None, tick_end=None):
        """Query events from tensor. Returns (n, 7) tensor."""
        if self.event_log is None or self.event_cursor == 0:
            return torch.zeros(0, 7)
        log = self.event_log[:self.event_cursor]
        mask = torch.ones(log.shape[0], dtype=torch.bool, device=log.device)
        if npc_id is not None:
            mask = mask & ((log[:, 2] == npc_id) | (log[:, 3] == npc_id))
        if tick_start is not None:
            mask = mask & (log[:, 0] >= tick_start)
        if tick_end is not None:
            mask = mask & (log[:, 0] <= tick_end)
        return log[mask]

    @property
    def alive_mask(self):
        return self.npc[:, self.layout.col("alive")].bool()

    @property
    def n_created(self):
        return int(self.max_id)

    @property
    def n_alive(self):
        return self.alive_mask.sum().item()

    @property
    def season_idx(self):
        return self.sim.season_idx(self.tick)

    @property
    def season_name(self):
        return self.sim.season_names[self.season_idx]

    @property
    def year(self):
        return self.sim.start_year + self.tick // 52

    @property
    def week(self):
        return (self.tick % 52) + 1


# ============================================================
#  TENSOR-OPERATIONEN (config-getrieben)
# ============================================================

def smooth_provision(world, per_capita, sim):
    """Geglättetes Versorgungssignal. Ungedämpft schwingt die Rollenwahl im 2-Takt."""
    a = sim.demand_smoothing
    if world.prov_ema is None or world.prov_ema.shape != per_capita.shape:
        world.prov_ema = per_capita.clone()
    else:
        world.prov_ema = (1 - a) * world.prov_ema + a * per_capita
    return world.prov_ema


def role_demand(per_capita, sim):
    """(n_poi, n_roles) Bedarfsbonus. Wo ein Kanal fehlt, wird die Rolle attraktiv."""
    dev = per_capita.device
    shortfall = (1 - per_capita / sim.labor_target.to(dev).unsqueeze(0)).clamp(0, 1)
    prov = sim.provide_matrix.to(dev).clamp(max=1)
    return (prov.unsqueeze(0) * shortfall.unsqueeze(1)).amax(dim=2)


def assign_roles(npc, layout, sim, demand=None):
    """Weise Rollen zu: Eignung (Traits) + Gender-Bias + Bedarf der Siedlung."""
    N = npc.shape[0]
    dev = npc.device

    traits = npc[:, layout.trait_start():layout.trait_end()]  # (N, n_traits)
    age = npc[:, layout.col("age")]
    sex = npc[:, layout.col("sex")]  # 0=m, 1=f

    # Score-Matrix: positive Gewichte = Trait direkt, negative = invertiert
    score_matrix = sim.role_score_matrix.to(dev)  # (n_roles, n_traits)

    pos_mask = (score_matrix > 0).float()
    neg_mask = (score_matrix < 0).float()

    raw_scores = (traits @ (score_matrix * pos_mask).T
                  + (1 - traits) @ (-score_matrix * neg_mask).T)  # (N, n_roles)

    # Normalisiere: Rollen mit mehr Termen sollen nicht automatisch höher scoren
    weight_sums = score_matrix.abs().sum(dim=1).clamp(min=0.1)  # (n_roles,)
    scores = raw_scores / weight_sums.unsqueeze(0)

    # Gender bias: m_bonus für sex=0, f_bonus für sex=1
    gb = sim.role_gender_bias.to(dev)  # (n_roles, 2)
    gender_bonus = (1 - sex).unsqueeze(1) * gb[:, 0].unsqueeze(0) \
                 + sex.unsqueeze(1) * gb[:, 1].unsqueeze(0)  # (N, n_roles)
    scores = scores + gender_bonus
    if demand is not None:
        scores = scores + sim.demand_weight * demand
    # Berufswechsel kostet – ohne Trägheit schwingt die Zuweisung
    scores = scores + sim.role_inertia * npc[:, layout.role_start():layout.role_end()]

    # Kinder (< 15) bekommen keine Rolle
    child = (age < 15).float().unsqueeze(1)
    scores = scores * (1 - child) - child

    # Min-Age: blockiert Rolle unter Alter, Override für Elder-Typ
    if sim.min_age_vec is None:
        sim.build_age_gates(layout)
    gate = sim.min_age_vec.to(dev).unsqueeze(0)          # (1, n_roles)
    blocked = (age.unsqueeze(1) < gate).float()
    scores = scores * (1 - blocked) - blocked

    override = sim.age_override_vec.to(dev).unsqueeze(0)
    qualifies = ((age.unsqueeze(1) >= gate) * override
                 * npc[:, layout.col("alive")].unsqueeze(1))
    scores = scores * (1 - qualifies) + qualifies

    roles = torch.zeros(N, len(layout.role_names), device=dev)
    roles.scatter_(1, scores.argmax(dim=1).unsqueeze(1), 1.0)
    return roles * (1 - child)


def compute_social_embedding(npc, assign, poi, layout, sim):
    """Berechne Social Embedding aus Position + Fraktion + Rolle."""
    dev = npc.device
    pos = assign @ poi[:, POILayout.X:POILayout.Y+1]  # (N, 2)

    faction = npc[:, layout.faction_start():layout.faction_end()]
    f_embed = faction @ sim.faction_embed.to(dev)  # (N, 2)

    role = npc[:, layout.role_start():layout.role_end()]
    r_embed = role @ sim.role_embed.to(dev)  # (N, 2)

    return torch.cat([pos, f_embed, r_embed], dim=1)  # (N, 6)


def compute_provision(npc, assign, layout, sim, alive):
    """Pro-Kopf-Versorgung je Siedlung → Wirkfaktor je Kanal.

    Rollen sind erst dann etwas wert, wenn sie produzieren: Ertrag = Rollenleistung
    × Gesundheit × Arbeitstrait. Stirbt der letzte Bauer, fällt der Faktor auf floor.
    """
    dev = npc.device
    roles = npc[:, layout.role_start():layout.role_end()]
    age = npc[:, layout.col("age")]
    hp = npc[:, layout.col("health")]
    trait = npc[:, layout.trait_start() + sim.labor_trait_idx]

    # Gesundheit senkt die Leistung, hebt sie aber nicht auf: ohne Boden wird aus
    # Hunger→schwach→weniger Ernte→Hunger eine Rückkopplung mit Verstärkung > 1.
    fit = ((age >= sim.work_age_min) & (age <= sim.work_age_max) & alive).float()
    w = sim.labor_trait_weight
    h = sim.capacity_health_floor
    capacity = fit * (h + (1 - h) * hp) * (1 - w + w * trait)

    output = (roles @ sim.provide_matrix.to(dev)) * capacity.unsqueeze(1)
    poi_out = assign.T @ output
    pop = (assign * alive.float().unsqueeze(1)).sum(dim=0).clamp(min=1)

    per_capita = poi_out / pop.unsqueeze(1)
    ratio = per_capita / sim.labor_target.to(dev).unsqueeze(0)
    floor = sim.labor_floor.to(dev).unsqueeze(0)
    factor = floor + (1 - floor) * ratio
    return per_capita, torch.minimum(factor, sim.labor_ceiling.to(dev).unsqueeze(0))


def plasticity(age, sim):
    """Formbarkeit der Persönlichkeit. Jung = weich, alt = fest."""
    return torch.exp(-age / sim.plast["tau_years"]).clamp(min=sim.plast["floor"])


def _grouped_order(group, score):
    """Sortierindex: nach Gruppe aufsteigend, innerhalb der Gruppe Score absteigend."""
    by_score = torch.argsort(score, descending=True, stable=True)
    return by_score[torch.argsort(group[by_score], stable=True)]


def _rank_in_group(group, score):
    """(n,) Rang innerhalb der Gruppe, 0 = bester Score."""
    dev = group.device
    n = group.shape[0]
    order = _grouped_order(group, score)
    g = group[order]
    ar = torch.arange(n, device=dev)
    new_group = torch.ones(n, dtype=torch.bool, device=dev)
    if n > 1:
        new_group[1:] = g[1:] != g[:-1]
    start = torch.cummax(torch.where(new_group, ar, torch.zeros_like(ar)), dim=0).values
    rank = torch.empty(n, dtype=torch.long, device=dev)
    rank[order] = ar - start
    return rank


def group_first_mask(group, score):
    """Maske: pro Gruppe nur der Eintrag mit höchstem Score. Vektorisiert."""
    return _rank_in_group(group, score) == 0


def capacity_rank(dest, score):
    """Rang je Ziel-Siedlung nach Score. Für Kapazitätsgrenzen bei Migration."""
    return _rank_in_group(dest, score)


# ============================================================
#  CONFIG LADEN
# ============================================================

def load_config(path=None):
    """Lade Config und baue Layout + SimConfig."""
    if path is None:
        path = CONFIG_PATH
    with open(path) as f:
        config = json.load(f)
    layout = TensorLayout(config)
    sim = SimConfig(config)
    return config, layout, sim
