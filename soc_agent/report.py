"""Result figures. Heatmap = sequential single-hue (blue, light -> dark = more unsafe)."""
from __future__ import annotations

from matplotlib.colors import LinearSegmentedColormap

from .evaluate import FAMILY_GROUP, FAMILY_ORDER, MAIN, family_table

SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#d9d8d3"
RAMP = ["#cde2fb", "#b7d3f6", "#9ec5f4", "#86b6ef", "#6da7ec", "#5598e7", "#3987e5",
        "#2a78d6", "#256abf", "#1c5cab", "#184f95", "#104281", "#0d366b"]
LABELS = {"A_raw": "A  raw LLM", "B_hardened": "B  hardened\nprompt", "C_graph_binary": "C  graph check\n(binary)",
          "E_abstain_only": "E  abstention\nonly", "D_full": "D  full\nsystem"}
GROUP_NAMES = {"clean": "clean", "log": "log content", "graph": "graph / telemetry", "joint": "joint log + graph"}


def plot_families(rows, path: str, configs: list[str] | None = None) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    configs = configs or MAIN
    t = family_table(rows, configs)
    fams = [f for f in FAMILY_ORDER if t[f]]
    cmap = LinearSegmentedColormap.from_list("seq_blue", RAMP)

    fig, ax = plt.subplots(figsize=(8.6, 0.36 * len(fams) + 2.1), facecolor=SURFACE)
    ax.set_facecolor(SURFACE)
    for i, fam in enumerate(fams):
        for j, c in enumerate(configs):
            v = t[fam].get(c, (None, 0))[0]
            if v is None:
                continue
            ax.add_patch(plt.Rectangle((j, i), 0.94, 0.9, color=cmap(v), lw=0))
            ax.text(j + 0.47, i + 0.46, f"{100 * v:.0f}%", ha="center", va="center", fontsize=8.5,
                    color=("#ffffff" if v > 0.45 else INK))
    ax.set_xlim(0, len(configs))
    ax.set_ylim(len(fams), 0)
    ax.set_xticks([j + 0.47 for j in range(len(configs))])
    ax.set_xticklabels([LABELS.get(c, c) for c in configs], fontsize=8.5, color=INK)
    ax.xaxis.tick_top()
    ax.set_yticks([i + 0.45 for i in range(len(fams))])
    ax.set_yticklabels(fams, fontsize=8.5, color=INK)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    prev = None
    for i, fam in enumerate(fams):
        g = FAMILY_GROUP[fam]
        if prev is not None and g != prev:
            ax.axhline(i - 0.03, color=GRID, lw=1)
        prev = g
    # group captions on the right edge
    start = 0
    for i, fam in enumerate(fams + [None]):
        g = FAMILY_GROUP.get(fam) if fam else None
        if i == len(fams) or (i > 0 and g != FAMILY_GROUP[fams[i - 1]]):
            mid = (start + i) / 2
            ax.text(len(configs) + 0.08, mid, GROUP_NAMES[FAMILY_GROUP[fams[i - 1]]], rotation=-90,
                    ha="left", va="center", fontsize=8, color=INK2)
            start = i
    fig.suptitle("Unsafe-outcome rate by attack family", x=0.02, ha="left", fontsize=11.5, color=INK, y=0.995)
    fig.text(0.02, 0.012, "Share of cases ending in an outcome the evidence does not warrant. Lower is better. "
             "Test split, simulated 8B stand-in.", fontsize=7.5, color=INK2)
    fig.tight_layout(rect=(0, 0.03, 1, 0.97))
    fig.savefig(path, dpi=170, facecolor=SURFACE)
    plt.close(fig)
