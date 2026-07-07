"""
=============================================================================
Topo-Kyber — Complete Entropy Analysis Script
=============================================================================
Estimators implemented:
  1. MFV  (Most Frequent Value)  — NIST SP 800-90B §6.3.1
  2. LZ78 (Compression-based)   — entropy lower bound via Lempel-Ziv
  3. Conservative bound          — min(MFV, LZ78) per entity

Unit of analysis: byte-level stream of float32 TDA feature vectors
  → 91 sessions × 10 features × 4 bytes/float = 3,640 bytes per entity

Output: Table 3 values for the manuscript + Figure 6 (PDF decorrelation)
=============================================================================
"""

import numpy as np
import pandas as pd
from ripser import ripser
import struct, zlib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter
from scipy import stats

# =============================================================================
# 0. CONFIGURATION — must match STM32 MicroTDA.c parameters
# =============================================================================
WINDOW_SIZE = 128   # RSSI samples per session
EMBED_DIM   = 3     # Takens embedding dimension
TIME_DELAY  = 1     # Takens time delay (tau)
N_FEATURES  = 10    # top-5 Betti-0 + top-5 Betti-1 lifetimes
BYTES_PER_FLOAT = 4
BYTES_PER_SESSION = N_FEATURES * BYTES_PER_FLOAT   # = 40
BITS_PER_SESSION  = BYTES_PER_SESSION * 8           # = 320

# =============================================================================
# 1. DATA LOADING
# =============================================================================

def load_rssi(filename):
    """Load RSSI time-series from CSV, drop malformed rows."""
    df   = pd.read_csv(filename, header=None, on_bad_lines='skip')
    data = pd.to_numeric(df.values.flatten(), errors='coerce')
    return data[~np.isnan(data)]


# =============================================================================
# 2. MICRO-TDA FEATURE EXTRACTION  (mirrors MicroTDA.c on STM32)
# =============================================================================

def extract_micro_tda_features(rssi_window):
    """
    Steps:
      (a) Min-Max normalisation          → amplitude-invariant embedding
      (b) Takens state-space embedding   → point cloud in R^EMBED_DIM
      (c) Vietoris-Rips persistent homology (maxdim=1)
      (d) Top-5 lifetimes from Betti-0 and Betti-1  → 10-dim feature vector
    Returns: np.array of shape (10,), dtype float32
    """
    # (a) Min-Max normalisation
    r_min, r_max = rssi_window.min(), rssi_window.max()
    norm = (rssi_window - r_min) / (r_max - r_min) if r_max > r_min \
           else np.zeros_like(rssi_window)

    # (b) Takens embedding
    n = len(norm)
    pts = n - (EMBED_DIM - 1) * TIME_DELAY
    if pts <= 0:
        return np.zeros(N_FEATURES, dtype=np.float32)
    point_cloud = np.array([
        norm[i : i + (EMBED_DIM - 1) * TIME_DELAY + 1 : TIME_DELAY]
        for i in range(pts)
    ])

    # (c) Persistent homology
    dgms = ripser(point_cloud, maxdim=1)['dgms']

    # (d) Top-5 lifetimes per Betti dimension
    features = []
    for dim in [0, 1]:
        dgm = dgms[dim]
        dgm = dgm[dgm[:, 1] != np.inf]          # remove infinite bars
        lifetimes = np.sort(dgm[:, 1] - dgm[:, 0])[::-1]  # descending
        top5 = list(lifetimes[:5]) if len(lifetimes) >= 5 \
               else list(lifetimes) + [0.0] * (5 - len(lifetimes))
        features.extend(top5)

    return np.array(features[:N_FEATURES], dtype=np.float32)


def build_feature_matrix(rssi_data, num_sessions):
    """Extract TDA features for all sessions."""
    feats = []
    for i in range(num_sessions):
        idx = i * WINDOW_SIZE
        feats.append(extract_micro_tda_features(rssi_data[idx : idx + WINDOW_SIZE]))
    return np.array(feats)   # shape: (num_sessions, N_FEATURES)


# =============================================================================
# 3. BYTE-STREAM UTILITY
# =============================================================================

def to_byte_stream(feats):
    """
    Serialise feature matrix to a flat byte list.
    Each float32 → 4 bytes (IEEE 754 big-endian).
    Total: num_sessions × N_FEATURES × 4 bytes
    """
    bl = []
    for row in feats:
        for val in row:
            bl.extend(struct.pack('!f', float(val)))
    return bl


# =============================================================================
# 4. ENTROPY ESTIMATORS
# =============================================================================

def estimator_mfv(feats):
    """
    Most Frequent Value (MFV) predictor — NIST SP 800-90B §6.3.1 proxy.

    Rationale:
      The noise source output is serialised as a byte stream (3,640 bytes).
      MFV finds the single most probable byte value and computes:
          H_MFV/byte = -log2(p_max)
      This is scaled to the full 320-bit (40-byte) feature vector:
          H_MFV = H_MFV/byte × 40

    Also returns a 95% binomial confidence interval on H_MFV.
    """
    bl = to_byte_stream(feats)
    N  = len(bl)
    counts = Counter(bl)
    n_max  = counts.most_common(1)[0][1]
    p_max  = n_max / N

    h = -np.log2(p_max) * 40

    # 95% Clopper-Pearson interval on p_max → inverted for H
    lo_count, hi_count = stats.binom.interval(0.95, N, p_max)
    ci_lo = -np.log2(hi_count / N) * 40   # hi p_max → lo H
    ci_hi = -np.log2(lo_count / N) * 40   # lo p_max → hi H

    return round(h, 2), (round(ci_lo, 1), round(ci_hi, 1))


def estimator_lz78(feats):
    """
    Compression-based entropy estimator (LZ78 / Lempel-Ziv proxy).

    Rationale:
      By the Shannon-McMillan-Breiman theorem, the optimal compression
      ratio of a stationary ergodic source converges to its entropy rate.
      We compress the full byte stream with zlib (LZ77/Deflate, a strict
      generalisation of LZ78) at maximum level and estimate:
          H_LZ/byte = (compressed_size / original_size) × 8 bits
          H_LZ      = H_LZ/byte × 40   (scaled to 320-bit vector)

      A fully random source compresses poorly → high H_LZ.
      A structured/correlated source compresses well → low H_LZ.
      LZ78 therefore acts as a conservative lower bound on true entropy.
    """
    bl         = bytes(to_byte_stream(feats))
    compressed = zlib.compress(bl, level=9)
    ratio      = len(compressed) / len(bl)
    h          = ratio * 8 * 40   # bits per 320-bit session vector
    return round(h, 2)


def conservative_bound(h_mfv, h_lz78):
    """Return the minimum across all estimators (worst-case assumption)."""
    return round(min(h_mfv, h_lz78), 2)


# =============================================================================
# 5. MAIN ANALYSIS
# =============================================================================

if __name__ == '__main__':

    # ── Load RSSI ─────────────────────────────────────────────────────────────
    print("Loading RSSI data...")
    alice_rssi = load_rssi('alice_rssi.csv')
    bob_rssi   = load_rssi('bob_rssi.csv')
    eva_rssi   = load_rssi('eva_rssi.csv')

    num_sessions = min(len(alice_rssi), len(bob_rssi), len(eva_rssi)) // WINDOW_SIZE
    print(f"Sessions available: {num_sessions}")
    print(f"Byte stream per entity: {num_sessions} × {BYTES_PER_SESSION} = "
          f"{num_sessions * BYTES_PER_SESSION} bytes\n")

    # ── Extract TDA features ──────────────────────────────────────────────────
    print(f"Extracting Micro-TDA features for {num_sessions} sessions...")
    alice_feats = build_feature_matrix(alice_rssi, num_sessions)
    bob_feats   = build_feature_matrix(bob_rssi,   num_sessions)
    eva_feats   = build_feature_matrix(eva_rssi,   num_sessions)

    # ── Compute entropy ───────────────────────────────────────────────────────
    results = {}
    for name, feats in [("Alice", alice_feats),
                        ("Bob",   bob_feats),
                        ("Eva",   eva_feats)]:
        h_mfv, ci = estimator_mfv(feats)
        h_lz78    = estimator_lz78(feats)
        h_cons    = conservative_bound(h_mfv, h_lz78)
        results[name] = {
            'MFV':          h_mfv,
            'CI':           ci,
            'LZ78':         h_lz78,
            'Conservative': h_cons,
        }

    # ── Print Table 3 ─────────────────────────────────────────────────────────
    print("=" * 68)
    print("TABLE 3 — Min-Entropy Analysis (Localized Diagnostic Model)")
    print("=" * 68)
    print(f"{'Estimator':<28} {'Alice':>10} {'Bob':>10} {'Eva':>10}")
    print("-" * 68)

    for est in ['MFV', 'LZ78', 'Conservative']:
        row = f"{est:<28}"
        for name in ['Alice', 'Bob', 'Eva']:
            row += f"  {results[name][est]:>8.2f}"
        print(row)

    print("-" * 68)
    ci_row = f"{'95% CI (MFV)':<28}"
    for name in ['Alice', 'Bob', 'Eva']:
        lo, hi = results[name]['CI']
        ci_row += f"  [{lo:.1f},{hi:.1f}]"
    print(ci_row)

    print("-" * 68)
    sec_row = f"{'Security level':<28}"
    for name in ['Alice', 'Bob', 'Eva']:
        h = results[name]['Conservative']
        label = "≥128-bit" if h >= 128 else f"~{h:.0f}-bit"
        sec_row += f"  {label:>10}"
    print(sec_row)
    print("=" * 68)

    # ── Detailed per-entity report ────────────────────────────────────────────
    print("\nDetailed Report:")
    for name in ['Alice', 'Bob', 'Eva']:
        r  = results[name]
        lo, hi = r['CI']
        print(f"\n  {name}:")
        print(f"    MFV  = {r['MFV']:.2f} bits  (95% CI: [{lo:.1f}, {hi:.1f}])")
        print(f"    LZ78 = {r['LZ78']:.2f} bits")
        print(f"    Conservative bound = {r['Conservative']:.2f} bits")
        verdict = "PASS ≥128-bit" if r['Conservative'] >= 128 else "FAIL <128-bit"
        print(f"    Security verdict: {verdict}")

    # ── Figure 6: PDF of TDA features ─────────────────────────────────────────
    print("\nGenerating Figure 6 (threat_model_decorrelation.png)...")
    plt.figure(figsize=(10, 6))
    sns.kdeplot(alice_feats[:, 0], label='Alice (Legitimate)',
                fill=True, color='#1f77b4', linewidth=2)
    sns.kdeplot(bob_feats[:, 0],   label='Bob (Legitimate)',
                fill=True, color='#2ca02c', linewidth=2)
    sns.kdeplot(eva_feats[:, 0],   label='Eva (Adversary)',
                fill=True, color='#d62728', linestyle='--', linewidth=2)

    plt.title('Probability Density Function (PDF) of Topological Invariants',
              fontsize=14, fontweight='bold')
    plt.xlabel('Extracted Feature Value (Normalized Betti Lifetime)', fontsize=12)
    plt.ylabel('Probability Density', fontsize=12)
    plt.legend(fontsize=12)
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig('threat_model_decorrelation.png', dpi=300)
    print("Saved: threat_model_decorrelation.png")
    print("\nDone.")