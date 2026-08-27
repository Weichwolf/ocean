"""Soziale Struktur ohne N²-Matrix.

Affinität ist ein Gauß-Kernel über einem 11-dimensionalen Merkmalsvektor – sie muss
nie materialisiert werden. Gespeichert wird nur, was nicht aus Merkmalen folgt: die
tatsächliche Bindung, als Liste fester Länge K je NPC. Damit wird aus O(N²) Speicher
O(N·K), und jede Operation ist ein Gather/Scatter mit statischer Form.
"""

import torch


def social_features(npc, layout, sim):
    """(N, social_dim + n_traits) – Grundlage jeder Affinitätsberechnung."""
    traits = npc[:, layout.trait_start():layout.trait_end()]
    social = npc[:, layout.social_start():layout.social_end()]
    return torch.cat([social, traits * sim.trait_social_weights], dim=1)


def affinity(features, a, b, sigma):
    """Affinität für ausgewählte Paare. (…, ) statt (N, N)."""
    d = features[a] - features[b]
    return torch.exp(-(d * d).sum(-1) / (2 * sigma ** 2))


def build_roster(poi_idx, n_poi, alive):
    """Mitglieder nach Siedlung gruppiert: (order, starts, counts).

    Ein Sortiervorgang ersetzt die Mitgliederlisten – O(N log N), statische Form.
    """
    dev = poi_idx.device
    key = torch.where(alive > 0, poi_idx, torch.full_like(poi_idx, n_poi))
    order = torch.argsort(key)
    counts = torch.zeros(n_poi + 1, device=dev).index_add_(
        0, key, torch.ones_like(key, dtype=torch.float32))
    starts = torch.cumsum(counts, 0) - counts
    return order, starts[:n_poi], counts[:n_poi]


def sample_peers(poi_idx, order, starts, counts, m):
    """(N, m) Zufallsnachbarn aus der eigenen Siedlung. Kein N²."""
    n = poi_idx.shape[0]
    dev = poi_idx.device
    c = counts[poi_idx].clamp(min=1).unsqueeze(1)
    offset = (torch.rand(n, m, device=dev) * c).long()
    return order[(starts[poi_idx].unsqueeze(1).long() + offset).clamp(0, n - 1)]


def bond_strengthen(bond_idx, bond_val, target, value, mask):
    """Bindung zu `target` auf mindestens `value` heben, wo `mask` gesetzt ist.

    Vorhandener Eintrag wird angehoben, sonst verdrängt der neue den schwächsten.
    """
    hit = (bond_idx == target.unsqueeze(1)) & (bond_idx >= 0)
    known = hit.any(dim=1)
    slot = torch.where(known, hit.float().argmax(dim=1), bond_val.argmin(dim=1))
    cur = bond_val.gather(1, slot.unsqueeze(1)).squeeze(1)
    keep = (mask <= 0) | (known & (cur >= value))
    new_val = torch.where(keep, cur, torch.maximum(cur * known.float(), value))
    new_idx = torch.where(keep, bond_idx.gather(1, slot.unsqueeze(1)).squeeze(1), target)
    bond_idx.scatter_(1, slot.unsqueeze(1), new_idx.unsqueeze(1))
    bond_val.scatter_(1, slot.unsqueeze(1), new_val.unsqueeze(1))


def bond_gather(bond_idx, bond_val, vec):
    """(N,) Σ_k bond_val · vec[bond_idx] – z. B. Trauer über tote Gebundene."""
    valid = (bond_idx >= 0).float()
    return (bond_val * valid * vec[bond_idx.clamp(min=0)]).sum(dim=1)


def bond_to_poi(bond_idx, bond_val, assign):
    """(N, n_poi) Bindungsgewicht je Zielsiedlung. Ersetzt rel @ assign."""
    valid = (bond_idx >= 0).float()
    return torch.einsum("nk,nkp->np", bond_val * valid, assign[bond_idx.clamp(min=0)])


def ties(bond_val, threshold):
    return (bond_val > threshold).float().sum(dim=1)


def clear_dead(bond_idx, bond_val, alive):
    """Bindungen an Tote lösen sich – sonst wächst die Liste mit Gespenstern zu."""
    keep = (bond_idx >= 0) & (alive[bond_idx.clamp(min=0)] > 0)
    bond_idx.copy_(torch.where(keep, bond_idx, torch.full_like(bond_idx, -1)))
    bond_val.mul_(keep)
