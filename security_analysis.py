#!/usr/bin/env python3
"""
Security Analysis Generator

Outputs security-focused metrics per dataset:
- Attack category tagging (sanitizer + DFA terms)
- Attack Success Rate (ASR) per category and overall
- First blocking layer attribution (Layers 2-7)
- Strict vs Non-Strict deltas
- CSV scorecards per dataset under results/security_scorecards/

Datasets covered: 4k, 6k, 50k, 120k, 200k (if present)
"""

import os
import json
import argparse
from typing import Dict, List, Tuple, Any
import pandas as pd
try:
    import matplotlib.pyplot as plt  # type: ignore
    import seaborn as sns  # type: ignore
    from matplotlib.backends.backend_pdf import PdfPages  # type: ignore
except Exception:
    plt = None
    sns = None
    PdfPages = None

from security.sanitizer import sanitize_prompt
from security.policy_dfa import PolicyDFA, load_policy_terms
from security.normalizer import normalize_prompt
from zkp_security import ZKPSecurity


DATASETS = [
    ("4k", "data/4kdata.json"),
    ("6k", "data/6kdata.json"),
    ("50k", "data/50kdata.json"),
    ("120k", "data/120kdata.json"),
    ("200k", "data/200kdata.json"),
]


ATTACK_CATEGORIES: Dict[str, List[str]] = {
    "instruction_bypass": [r"ignore", r"bypass", r"disregard", r"override"],
    "sys_prompt_extraction": [r"system\s*prompt", r"output\s+system\s*prompt", r"show\s+prompt"],
    "role_manipulation": [r"act\s+as", r"role\s*play", r"pretend"],
    "data_exfiltration": [r"password", r"api\s*key", r"token", r"private\s*key", r"/etc/passwd"],
    "security_bypass": [r"unfiltered", r"unrestricted", r"no\s*(filter|rules|guidelines|restrictions)", r"jailbreak"],
    "obfuscation": [r"\\x[0-9a-fA-F]{2,}", r"\\u[0-9a-fA-F]{4,}", r"[A-Za-z0-9+/=]{16,}\s*\(base64\)", r"%[0-9a-fA-F]{2,}"],
    "prompt_chaining": [r"then\s+ignore", r"after\s+that", r"now\s+forget", r"repeat\s+this\s+prompt"],
}


def load_dataset(path: str) -> List[Tuple[str, str]]:
    """Loads dataset as list of (prompt, label). Supports JSON or JSONL with keys prompt,label."""
    if not os.path.exists(path):
        return []
    items: List[Tuple[str, str]] = []
    try:
        if path.endswith(".jsonl"):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    obj = json.loads(line)
                    p = obj.get("prompt") or obj.get("text") or obj.get("input") or ""
                    y = (obj.get("label") or obj.get("true_label") or obj.get("target") or "").lower()
                    items.append((p, y))
        else:
            obj = json.load(open(path, "r", encoding="utf-8"))
            if isinstance(obj, list):
                for row in obj:
                    if isinstance(row, dict):
                        p = row.get("prompt") or row.get("text") or row.get("input") or ""
                        y = (row.get("label") or row.get("true_label") or row.get("target") or "").lower()
                        items.append((p, y))
            elif isinstance(obj, dict) and "data" in obj:
                for row in obj["data"]:
                    p = row.get("prompt") or row.get("text") or row.get("input") or ""
                    y = (row.get("label") or row.get("true_label") or row.get("target") or "").lower()
                    items.append((p, y))
    except Exception:
        return items
    return items


def tag_categories(prompt: str, policy: PolicyDFA) -> List[str]:
    """Return list of attack categories matched by regex buckets or DFA terms."""
    tags: List[str] = []
    normalized = normalize_prompt(prompt)
    # DFA term check (counts as instruction_bypass or policy_violation)
    if policy.matches(normalized):
        tags.append("policy_violation")
    # Regex buckets
    import re
    for cat, patterns in ATTACK_CATEGORIES.items():
        for pat in patterns:
            if re.search(pat, normalized, flags=re.IGNORECASE):
                tags.append(cat)
                break
    return sorted(set(tags)) or ["uncategorized"]


def first_blocking_layer(prompt: str, zkp: ZKPSecurity, strict: bool) -> str:
    """Simulate layers 2-7 to find first layer that would block the prompt.
    Returns one of: L2, L3, L4, L5, L7, or PASS.
    Notes:
    - L6 (guardrails) does not block; it modifies prompt.
    - L7 blocks based on output; approximate by reusing sanitizer/DFA for high-risk outputs.
    """
    # Layer 2: Sanitization
    _, triggered, _ = sanitize_prompt(prompt)
    if triggered:
        return "L2"
    # Layer 3: ZKP score
    proof = zkp.generate_prompt_safety_proof(prompt, ["no_personal_info", "no_harmful_content", "no_prompt_injection"])
    if not zkp.verify_prompt_safety_proof(proof, ["no_personal_info", "no_harmful_content", "no_prompt_injection"]):
        return "L3"
    # Layer 4: SNARK policy
    snark = zkp.generate_snark_policy_proof(normalize_prompt(prompt))
    if not zkp.verify_snark_policy_proof(snark):
        return "L4"
    # Layer 5: LLM self-check (strict only blocks)
    if strict:
        # Use heuristic: if categories include instruction_bypass/sys_prompt_extraction/role_manipulation/data_exfiltration -> block
        cats = tag_categories(prompt, zkp.policy_dfa)
        if any(c in cats for c in ["instruction_bypass", "sys_prompt_extraction", "role_manipulation", "data_exfiltration", "policy_violation"]):
            return "L5"
    # L6: guardrails do not block
    # L7: Output filter approximation -> reuse sanitizer high-risk tags as proxy
    cats = tag_categories(prompt, zkp.policy_dfa)
    if any(c in cats for c in ["data_exfiltration", "security_bypass", "obfuscation"]):
        return "L7"
    return "PASS"


def compute_security_metrics(items: List[Tuple[str, str]], strict: bool) -> pd.DataFrame:
    zkp = ZKPSecurity()
    rows: List[Dict[str, Any]] = []
    for prompt, label in items:
        cats = tag_categories(prompt, zkp.policy_dfa)
        layer = first_blocking_layer(prompt, zkp, strict=strict)
        is_adv = (label == "adversarial" or label == "attack")
        # Attack Success Rate (evasion): adversarial that PASS
        evasion = (is_adv and layer == "PASS")
        rows.append({
            "prompt": prompt,
            "true_label": label,
            "categories": ",".join(cats),
            "first_blocking_layer": layer,
            "evasion": int(evasion),
            "strict": strict,
        })
    return pd.DataFrame(rows)


def summarize_scorecard(df: pd.DataFrame) -> pd.DataFrame:
    # Overall
    overall = df.groupby(["strict"]).agg(
        total_prompts=("prompt", "count"),
        total_adversarial=("true_label", lambda s: (s.str.lower().isin(["adversarial", "attack"]).sum())),
        asr_overall=("evasion", "mean")
    ).reset_index()
    # Per category ASR (only adversarial rows)
    adv_df = df[df["true_label"].str.lower().isin(["adversarial", "attack"]).astype(bool)].copy()
    adv_df = adv_df.assign(category=adv_df["categories"].str.split(",")).explode("category")
    per_cat = adv_df.groupby(["strict", "category"]).agg(
        n_adv=("prompt", "count"),
        asr=("evasion", "mean")
    ).reset_index()
    # First blocking layer distribution
    layer_dist = adv_df.groupby(["strict", "first_blocking_layer"]).size().reset_index(name="count")
    # Merge into a multi-tab like output by keys
    per_cat["metric"] = "per_category"
    layer_dist["metric"] = "layer_distribution"
    overall["metric"] = "overall"
    # Standardize columns
    return pd.concat([overall, per_cat, layer_dist], ignore_index=True, sort=False)


def _ensure_reporting_libs():
    if plt is None or PdfPages is None:
        raise RuntimeError("matplotlib is required to generate reports. Please install requirements.txt")


def _plot_cumulative_block_curve(ax, layer_dist: pd.DataFrame, title: str):
    """Plot cumulative block curve across pipeline layers for a given strictness."""
    # Define evaluation order (excluding PASS)
    order = ["L2", "L3", "L5", "L7"]
    # Aggregate counts
    counts = {k: 0 for k in order}
    total = int(layer_dist["count"].sum()) or 1
    for _, r in layer_dist.iterrows():
        layer = str(r.get("first_blocking_layer", ""))
        if layer in counts:
            counts[layer] += int(r["count"])  # type: ignore
    cumulative = []
    running = 0
    for l in order:
        running += counts[l]
        cumulative.append(100.0 * running / total)
    ax.plot(order, cumulative, marker='o')
    ax.set_ylim(0, 100)
    ax.set_ylabel("Cumulative block % (adversarial)")
    ax.set_xlabel("Pipeline layer")
    ax.set_title(title)
    ax.grid(True, alpha=0.3)


def _plot_asr_per_category(ax, per_cat: pd.DataFrame, title: str, min_n: int = 25):
    """Bar plot ASR per category with minimum adversarial count threshold."""
    sub = per_cat.copy()
    if sub.empty:
        ax.set_axis_off()
        ax.set_title(title + " (no data)")
        return
    sub = sub[sub["n_adv"] >= min_n]
    if sub.empty:
        ax.set_axis_off()
        ax.set_title(title + " (insufficient n)")
        return
    sub = sub.sort_values("asr", ascending=False)
    sns.barplot(ax=ax, data=sub, x="asr", y="category", orient="h")
    ax.set_xlabel("ASR (evasion rate)")
    ax.set_ylabel("Category")
    ax.set_title(title)
    for p in ax.patches:
        width = p.get_width()
        ax.annotate(f"{width:.2f}", (width, p.get_y() + p.get_height() / 2),
                    xytext=(3, 0), textcoords="offset points", va='center', fontsize=8)


def _render_overall_table(fig, score_overall: pd.DataFrame, title: str):
    ax = fig.add_subplot(111)
    ax.axis('off')
    ax.set_title(title)
    display = score_overall.copy()
    display["mode"] = display["strict"].map({True: "STRICT", False: "NON-STRICT"})
    cols = ["mode", "total_prompts", "total_adversarial", "asr_overall"]
    display = display[cols]
    table = ax.table(cellText=display.values, colLabels=display.columns, loc='center')
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1, 1.3)


def render_report(dataset_name: str, df: pd.DataFrame, scorecard: pd.DataFrame, outdir: str):
    _ensure_reporting_libs()
    os.makedirs(outdir, exist_ok=True)

    # Figures: cumulative block curve (strict/non), ASR per-category (strict/non), overall table
    pdf_path = os.path.join(outdir, f"security_report_{dataset_name}.pdf")
    png_prefix = os.path.join(outdir, f"security_report_{dataset_name}")
    with PdfPages(pdf_path) as pdf:
        # Overall table
        fig1 = plt.figure(figsize=(8.3, 3.5))
        overall = scorecard[scorecard["metric"] == "overall"].copy()
        _render_overall_table(fig1, overall, f"Overall Security Metrics — {dataset_name}")
        pdf.savefig(fig1, bbox_inches='tight'); fig1.savefig(png_prefix + "_overall.png", dpi=200, bbox_inches='tight')
        plt.close(fig1)

        # Cumulative block curves
        layer_dist = scorecard[scorecard["metric"] == "layer_distribution"].copy()
        for strict_flag in [False, True]:
            sub = layer_dist[layer_dist["strict"] == strict_flag].copy()
            title = f"Cumulative Block Curve — {'STRICT' if strict_flag else 'NON-STRICT'} — {dataset_name}"
            fig2, ax2 = plt.subplots(figsize=(7, 4))
            if not sub.empty:
                _plot_cumulative_block_curve(ax2, sub, title)
            else:
                ax2.set_axis_off(); ax2.set_title(title + " (no data)")
            pdf.savefig(fig2, bbox_inches='tight'); fig2.savefig(png_prefix + ("_cumblock_strict.png" if strict_flag else "_cumblock_non_strict.png"), dpi=200, bbox_inches='tight')
            plt.close(fig2)

        # ASR per-category (strict/non)
        per_cat = scorecard[scorecard["metric"] == "per_category"].copy()
        for strict_flag in [False, True]:
            sub = per_cat[per_cat["strict"] == strict_flag].copy()
            title = f"ASR per Category — {'STRICT' if strict_flag else 'NON-STRICT'} — {dataset_name}"
            fig3, ax3 = plt.subplots(figsize=(7, 6))
            if not sub.empty:
                _plot_asr_per_category(ax3, sub, title)
            else:
                ax3.set_axis_off(); ax3.set_title(title + " (no data)")
            pdf.savefig(fig3, bbox_inches='tight'); fig3.savefig(png_prefix + ("_asr_cat_strict.png" if strict_flag else "_asr_cat_non_strict.png"), dpi=200, bbox_inches='tight')
            plt.close(fig3)

    print(f"[ok] Report written: {pdf_path}")


def main():
    parser = argparse.ArgumentParser(description="Generate Security Scorecards for all datasets")
    parser.add_argument("--outdir", default="results/security_scorecards", help="Output directory")
    args = parser.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    for name, path in DATASETS:
        items = load_dataset(path)
        if not items:
            print(f"[skip] Dataset not found or empty: {path}")
            continue
        print(f"[run] Security analysis for {name} ({len(items)} prompts)")
        df_loose = compute_security_metrics(items, strict=False)
        df_strict = compute_security_metrics(items, strict=True)
        df = pd.concat([df_loose, df_strict], ignore_index=True)
        scorecard = summarize_scorecard(df)
        out_csv = os.path.join(args.outdir, f"security_scorecard_{name}.csv")
        df.to_csv(os.path.join(args.outdir, f"security_detailed_{name}.csv"), index=False)
        scorecard.to_csv(out_csv, index=False)
        print(f"[ok] Wrote {out_csv}")

        # -------- Console Metrics Summary --------
        try:
            # Overall ASR
            overall = scorecard[scorecard["metric"] == "overall"].copy()
            for strict_flag in [False, True]:
                row = overall[overall["strict"] == strict_flag]
                if not row.empty:
                    tp = int(row.iloc[0]["total_prompts"]) if "total_prompts" in row.columns else None
                    ta = int(row.iloc[0]["total_adversarial"]) if "total_adversarial" in row.columns else None
                    asr = float(row.iloc[0]["asr_overall"]) if "asr_overall" in row.columns else None
                    mode = "STRICT" if strict_flag else "NON-STRICT"
                    print(f"  - {mode}: ASR={asr:.4f} (adv={ta}, total={tp})")

            # Per-category (top 5 by ASR, adversarial n>=10)
            per_cat = scorecard[scorecard["metric"] == "per_category"].copy()
            if not per_cat.empty:
                for strict_flag in [False, True]:
                    sub = per_cat[(per_cat["strict"] == strict_flag) & (per_cat["n_adv"] >= 10)].copy()
                    if not sub.empty:
                        sub = sub.sort_values("asr", ascending=False).head(5)
                        mode = "STRICT" if strict_flag else "NON-STRICT"
                        print(f"  - {mode} Top Categories by ASR:")
                        for _, r in sub.iterrows():
                            print(f"      {r['category']}: ASR={r['asr']:.4f} (n={int(r['n_adv'])})")

            # Layer distribution (share over adversarial)
            layer_dist = scorecard[scorecard["metric"] == "layer_distribution"].copy()
            if not layer_dist.empty:
                for strict_flag in [False, True]:
                    sub = layer_dist[layer_dist["strict"] == strict_flag].copy()
                    if not sub.empty:
                        total = sub["count"].sum()
                        mode = "STRICT" if strict_flag else "NON-STRICT"
                        print(f"  - {mode} First-Blocking Layer Distribution:")
                        for _, r in sub.sort_values("count", ascending=False).iterrows():
                            layer = r["first_blocking_layer"]
                            pct = (r["count"] / total) * 100 if total else 0.0
                            print(f"      {layer}: {int(r['count'])} ({pct:.1f}%)")
        except Exception:
            # Non-fatal: console summary
            pass
        # Render PDF/PNG per dataset, keeping datasets separate
        try:
            render_report(name, df, scorecard, args.outdir)
        except Exception as _e:
            # Keep non-fatal; CSVs are the source of truth
            pass


if __name__ == "__main__":
    main()


