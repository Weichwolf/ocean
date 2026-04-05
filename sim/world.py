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


def get_device():
    if torch.backends.mps.is_available():
        return torch.device("mps")
    elif torch.cuda.is_available():
        return torch.device("cuda")
    return torch.device("cpu")


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

        # ── Vitals ──────────────────────────────────────
        for name in config["vitals"]:
            self._add_col(name)

        # ── Emotions ────────────────────────────────────
        for name in config["emotions"]:
            self._add_col(name)

        # ── Demographics ────────────────────────────────
        self._add_col("sex")
        self._add_col("born_tick")

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
                                             "social_dim", "D_NPC"):
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
    rel: torch.Tensor
    trust: torch.Tensor
    tick: int
    max_id: int
    events: list = field(default_factory=list)
    names: list = field(default_factory=list)
    poi_names: list = field(default_factory=list)
    names_m: list = field(default_factory=list)
    names_f: list = field(default_factory=list)

    # References to config objects
    layout: TensorLayout = None
    sim: SimConfig = None

    def to(self, device):
        self.npc = self.npc.to(device)
        self.poi = self.poi.to(device)
        self.assign = self.assign.to(device)
        self.rel = self.rel.to(device)
        self.trust = self.trust.to(device)
        return self

    @property
    def alive_mask(self):
        return self.npc[:, self.layout.col("alive")].bool()

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

def assign_roles(npc, layout, sim):
    """Weise Rollen zu basierend auf Trait-Score-Matrix + Gender-Bias."""
    N = npc.shape[0]
    dev = npc.device

    traits = npc[:, layout.trait_start():layout.trait_end()]  # (N, n_traits)
    age = npc[:, layout.col("age")]
    sex = npc[:, layout.col("sex")]  # 0=m, 1=f

    # Score-Matrix: positive Gewichte = Trait direkt, negative = invertiert
    score_matrix = sim.role_score_matrix.to(dev)  # (n_roles, n_traits)

    pos_mask = (score_matrix > 0).float()
    neg_mask = (score_matrix < 0).float()

    scores = (traits @ (score_matrix * pos_mask).T
              + (1 - traits) @ (-score_matrix * neg_mask).T)  # (N, n_roles)

    # Gender bias: m_bonus für sex=0, f_bonus für sex=1
    gb = sim.role_gender_bias.to(dev)  # (n_roles, 2)
    gender_bonus = (1 - sex).unsqueeze(1) * gb[:, 0].unsqueeze(0) \
                 + sex.unsqueeze(1) * gb[:, 1].unsqueeze(0)  # (N, n_roles)
    scores = scores + gender_bonus

    # Kinder (< 15) bekommen keine Rolle
    child_mask = age < 15
    scores[child_mask] = -1

    # Min-Age: blockiert Rolle unter Alter, Override für Elder-Typ
    config_roles = sim.raw.get("roles", {})
    for rname, min_age in sim.role_min_ages.items():
        ri = layout.role_names.index(rname)
        too_young = age < min_age
        scores[too_young, ri] = -1
        # Elder-Typ: Score-Override wenn keine eigenen Trait-Scores definiert
        if not config_roles.get(rname, {}).get("score"):
            old_enough = (age >= min_age) & npc[:, layout.col("alive")].bool()
            scores[old_enough, ri] = 1.0

    roles = torch.zeros(N, len(layout.role_names), device=dev)
    best = scores.argmax(dim=1)
    roles.scatter_(1, best.unsqueeze(1), 1.0)
    roles[child_mask] = 0

    return roles


def compute_social_embedding(npc, assign, poi, layout, sim):
    """Berechne Social Embedding aus Position + Fraktion + Rolle."""
    dev = npc.device
    pos = assign @ poi[:, POILayout.X:POILayout.Y+1]  # (N, 2)

    faction = npc[:, layout.faction_start():layout.faction_end()]
    f_embed = faction @ sim.faction_embed.to(dev)  # (N, 2)

    role = npc[:, layout.role_start():layout.role_end()]
    r_embed = role @ sim.role_embed.to(dev)  # (N, 2)

    return torch.cat([pos, f_embed, r_embed], dim=1)  # (N, 6)


def compute_affinity_matrix(npc, layout, sim):
    """(N, N) Affinitätsmatrix aus Social + Traits."""
    dev = npc.device
    traits = npc[:, layout.trait_start():layout.trait_end()]
    social = npc[:, layout.social_start():layout.social_end()]
    weights = sim.trait_social_weights.to(dev)

    features = torch.cat([social, traits * weights], dim=1)
    dist_sq = torch.cdist(features, features).pow(2)
    affinity = torch.exp(-dist_sq / (2 * sim.affinity_sigma ** 2))

    alive = npc[:, layout.col("alive")]
    mask = alive.unsqueeze(0) * alive.unsqueeze(1)
    return affinity * mask


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
