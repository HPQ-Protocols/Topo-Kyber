"""Auditable entropy diagnostics for the Topo-Kyber Micro-TDA feature stream.

This script deliberately reports empirical diagnostics rather than claiming
formal NIST SP 800-90B validation or standalone cryptographic entropy.
"""

import argparse
import json
import math
import zlib
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats


DEFAULT_WINDOW_SIZE = 128
DEFAULT_SESSIONS = 91
DEFAULT_H0_FEATURES = 20
DEFAULT_H1_FEATURES = 20
DEFAULT_Q_STEP = 0.35
EMBED_DIM = 3
TIME_DELAY = 1
CONFIDENCE = 0.95


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Extract 40 Micro-TDA features per fixed window, quantize them to "
            "40 byte symbols, and emit auditable MFV/compression diagnostics."
        )
    )
    parser.add_argument("--alice", default="alice_rssi.csv")
    parser.add_argument("--bob", default="bob_rssi.csv")
    parser.add_argument("--eve", default="eva_rssi.csv")
    parser.add_argument("--window-size", type=int, default=DEFAULT_WINDOW_SIZE)
    parser.add_argument("--sessions", type=int, default=DEFAULT_SESSIONS)
    parser.add_argument("--h0-features", type=int, default=DEFAULT_H0_FEATURES)
    parser.add_argument("--h1-features", type=int, default=DEFAULT_H1_FEATURES)
    parser.add_argument("--q-step", type=float, default=DEFAULT_Q_STEP)
    parser.add_argument(
        "--affine-scale",
        type=float,
        default=1.0,
        help="Public fixed scale applied before scalar quantization.",
    )
    parser.add_argument(
        "--affine-offset",
        type=float,
        default=0.0,
        help="Public fixed offset applied before scalar quantization.",
    )
    parser.add_argument("--output-json", default="entropy_audit.json")
    parser.add_argument("--output-symbols", default="entropy_quantized_symbols.csv")
    parser.add_argument(
        "--output-figure", default="threat_model_decorrelation.png"
    )
    return parser.parse_args()


def validate_args(args):
    if args.window_size <= 0 or args.sessions <= 0:
        raise ValueError("Window size and session count must be positive")
    if args.h0_features < 0 or args.h1_features < 0:
        raise ValueError("Feature counts must be non-negative")
    if args.h0_features + args.h1_features != 40:
        raise ValueError(
            "The manuscript pipeline requires exactly 40 features per session"
        )
    if args.q_step <= 0:
        raise ValueError("Quantization step must be positive")
    if not math.isfinite(args.affine_scale) or args.affine_scale <= 0:
        raise ValueError("Affine scale must be finite and positive")
    if not math.isfinite(args.affine_offset):
        raise ValueError("Affine offset must be finite")


def load_rssi(filename):
    """Load a numeric RSSI stream and report malformed-value removal."""
    path = Path(filename)
    if not path.is_file():
        raise FileNotFoundError(f"RSSI file not found: {path}")

    frame = pd.read_csv(path, header=None, on_bad_lines="skip")
    flattened = frame.to_numpy().ravel()
    numeric = pd.to_numeric(flattened, errors="coerce")
    valid = np.asarray(numeric[~pd.isna(numeric)], dtype=np.float64)
    if valid.size == 0:
        raise ValueError(f"No valid numeric RSSI samples found in {path}")
    return valid, int(len(flattened) - len(valid))


def rssi_diagnostics(values, malformed_removed):
    minimum = float(np.min(values))
    maximum = float(np.max(values))
    return {
        "count": int(len(values)),
        "malformed_removed": int(malformed_removed),
        "minimum_dbm": minimum,
        "maximum_dbm": maximum,
        "range_db": maximum - minimum,
        "mean_dbm": float(np.mean(values)),
        "standard_deviation_db": float(np.std(values, ddof=1)),
        "p01_dbm": float(np.percentile(values, 1)),
        "p25_dbm": float(np.percentile(values, 25)),
        "median_dbm": float(np.median(values)),
        "p75_dbm": float(np.percentile(values, 75)),
        "p99_dbm": float(np.percentile(values, 99)),
        "count_at_minimum": int(np.sum(values == minimum)),
        "count_at_maximum": int(np.sum(values == maximum)),
        "count_at_minus_90_dbm": int(np.sum(values == -90)),
        "count_at_minus_20_dbm": int(np.sum(values == -20)),
    }


def normalize_rssi(window):
    minimum = np.min(window)
    maximum = np.max(window)
    if maximum <= minimum:
        return np.zeros_like(window, dtype=np.float64)
    return (window - minimum) / (maximum - minimum)


def fixed_lifetimes(diagram, count):
    if count == 0:
        return np.empty(0, dtype=np.float64)
    if diagram.size == 0:
        return np.zeros(count, dtype=np.float64)

    lifetimes = diagram[:, 1] - diagram[:, 0]
    lifetimes = lifetimes[np.isfinite(lifetimes)]
    lifetimes = np.sort(lifetimes)[::-1][:count]
    if len(lifetimes) < count:
        lifetimes = np.pad(lifetimes, (0, count - len(lifetimes)))
    return lifetimes.astype(np.float64, copy=False)


def extract_micro_tda_features(rssi_window, h0_count, h1_count):
    from ripser import ripser

    normalized = normalize_rssi(rssi_window)
    embedded_points = len(normalized) - (EMBED_DIM - 1) * TIME_DELAY
    if embedded_points < 10:
        raise ValueError("Too few samples for the configured Takens embedding")

    point_cloud = np.asarray(
        [
            normalized[
                index:index + (EMBED_DIM - 1) * TIME_DELAY + 1:TIME_DELAY
            ]
            for index in range(embedded_points)
        ],
        dtype=np.float64,
    )
    diagrams = ripser(point_cloud, maxdim=1)["dgms"]
    return np.concatenate(
        (
            fixed_lifetimes(diagrams[0], h0_count),
            fixed_lifetimes(diagrams[1], h1_count),
        )
    )


def build_feature_matrix(values, sessions, window_size, h0_count, h1_count, entity):
    required_samples = sessions * window_size
    if len(values) < required_samples:
        raise ValueError(
            f"{entity} has {len(values)} samples but {required_samples} are "
            f"required for {sessions} fixed windows"
        )

    rows = []
    for session_index in range(sessions):
        start = session_index * window_size
        stop = start + window_size
        try:
            rows.append(
                extract_micro_tda_features(
                    values[start:stop], h0_count, h1_count
                )
            )
        except Exception as error:
            raise RuntimeError(
                f"TDA extraction failed for {entity} window {session_index}"
            ) from error
    return np.asarray(rows, dtype=np.float64)


def quantize_features(features, q_step, affine_scale, affine_offset):
    """Map each 40-feature vector to exactly 40 unsigned byte symbols."""
    mapped = affine_scale * features + affine_offset
    quantized = np.floor(mapped / q_step)
    clipped_low = int(np.sum(quantized < 0))
    clipped_high = int(np.sum(quantized > 255))
    quantized = np.clip(quantized, 0, 255).astype(np.uint8)
    return quantized, {
        "clipped_low_symbols": clipped_low,
        "clipped_high_symbols": clipped_high,
    }


def clopper_pearson_interval(successes, trials, confidence=CONFIDENCE):
    """Exact binomial confidence interval conditional on the selected symbol."""
    alpha = 1.0 - confidence
    lower = (
        0.0
        if successes == 0
        else float(stats.beta.ppf(alpha / 2, successes, trials - successes + 1))
    )
    upper = (
        1.0
        if successes == trials
        else float(
            stats.beta.ppf(
                1 - alpha / 2, successes + 1, trials - successes
            )
        )
    )
    return lower, upper


def mfv_diagnostic(symbols):
    stream = symbols.reshape(-1)
    trials = int(stream.size)
    counts = Counter(int(value) for value in stream)
    most_frequent_symbol, n_max = counts.most_common(1)[0]
    p_max = n_max / trials
    bits_per_symbol = -math.log2(p_max)
    bits_per_session = bits_per_symbol * symbols.shape[1]

    p_lower, p_upper = clopper_pearson_interval(n_max, trials)
    entropy_lower = -math.log2(p_upper) * symbols.shape[1]
    entropy_upper = (
        float("inf")
        if p_lower == 0
        else -math.log2(p_lower) * symbols.shape[1]
    )
    return {
        "stream_length_bytes": trials,
        "most_frequent_symbol": int(most_frequent_symbol),
        "n_max": int(n_max),
        "p_max": float(p_max),
        "bits_per_symbol_unrounded": float(bits_per_symbol),
        "bits_per_session_unrounded": float(bits_per_session),
        "bits_per_session_rounded": round(bits_per_session, 2),
        "conditional_clopper_pearson_95_p_interval": [p_lower, p_upper],
        "conditional_entropy_95_interval_bits": [entropy_lower, entropy_upper],
    }


def compression_diagnostic(symbols):
    stream = symbols.astype(np.uint8, copy=False).tobytes(order="C")
    compressed = zlib.compress(stream, level=9)
    original_length = len(stream)
    compressed_length = len(compressed)
    ratio = compressed_length / original_length
    raw_scaled_bits = ratio * 8 * symbols.shape[1]
    capped_bits = min(raw_scaled_bits, 8 * symbols.shape[1])
    return {
        "codec": "zlib level 9 (DEFLATE/LZ77 diagnostic; not LZ78)",
        "original_length_bytes": original_length,
        "compressed_length_bytes": compressed_length,
        "compression_ratio": float(ratio),
        "scaled_bits_per_session_unrounded": float(raw_scaled_bits),
        "capped_diagnostic_bits_per_session": float(capped_bits),
        "capped_diagnostic_bits_rounded": round(capped_bits, 2),
        "warning": (
            "Compression ratio is a finite-sample diagnostic, not a formal "
            "min-entropy lower bound."
        ),
    }


def entity_entropy_report(symbols):
    mfv = mfv_diagnostic(symbols)
    compression = compression_diagnostic(symbols)
    conservative_diagnostic = min(
        mfv["bits_per_session_unrounded"],
        compression["capped_diagnostic_bits_per_session"],
    )
    return {
        "mfv": mfv,
        "compression": compression,
        "conservative_diagnostic_bits_unrounded": conservative_diagnostic,
        "conservative_diagnostic_bits_rounded": round(
            conservative_diagnostic, 2
        ),
        "interpretation": "Empirical diagnostic only; not a security verdict.",
    }


def paired_feature_diagnostics(alice_features, bob_features, eve_features):
    def safe_pearson(first, second):
        if np.std(first) == 0 or np.std(second) == 0:
            return None
        return float(stats.pearsonr(first, second).statistic)

    return {
        "first_feature_pearson_alice_bob": safe_pearson(
            alice_features[:, 0], bob_features[:, 0]
        ),
        "first_feature_pearson_alice_eve": safe_pearson(
            alice_features[:, 0], eve_features[:, 0]
        ),
        "median_linf_alice_bob": float(
            np.median(np.max(np.abs(alice_features - bob_features), axis=1))
        ),
        "median_linf_alice_eve": float(
            np.median(np.max(np.abs(alice_features - eve_features), axis=1))
        ),
    }


def write_symbol_csv(path, symbols_by_entity):
    records = []
    for entity, matrix in symbols_by_entity.items():
        for session_index, row in enumerate(matrix):
            record = {"entity": entity, "window_index": session_index}
            record.update(
                {f"symbol_{index:02d}": int(value) for index, value in enumerate(row)}
            )
            records.append(record)
    pd.DataFrame.from_records(records).to_csv(path, index=False)


def generate_kde_figure(path, features_by_entity):
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import seaborn as sns

    plt.figure(figsize=(10, 6))
    styles = {
        "Alice": ("#1f77b4", "-", "Alice (Legitimate)"),
        "Bob": ("#2ca02c", "-", "Bob (Legitimate)"),
        "Eve": ("#d62728", "--", "Eve (Adversary)"),
    }
    for entity, features in features_by_entity.items():
        color, linestyle, label = styles[entity]
        sns.kdeplot(
            features[:, 0],
            label=label,
            fill=True,
            color=color,
            linestyle=linestyle,
            linewidth=2,
            cut=0,
        )

    plt.title("Distribution of the First Topological Feature", fontsize=14)
    plt.xlabel("Normalized Betti-0 Lifetime", fontsize=12)
    plt.ylabel("Kernel Density Estimate", fontsize=12)
    plt.legend(fontsize=11)
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.tight_layout()
    plt.savefig(path, dpi=300)
    plt.close()


def print_report(report):
    print("=" * 76)
    print("ENTROPY DIAGNOSTICS — 40 QUANTIZED BYTE SYMBOLS PER WINDOW")
    print("=" * 76)
    print(f"{'Entity':<10}{'MFV':>12}{'Compression':>16}{'Diagnostic min':>18}")
    print("-" * 76)
    for entity in ("Alice", "Bob", "Eve"):
        result = report["entities"][entity]["entropy"]
        print(
            f"{entity:<10}"
            f"{result['mfv']['bits_per_session_rounded']:>12.2f}"
            f"{result['compression']['capped_diagnostic_bits_rounded']:>16.2f}"
            f"{result['conservative_diagnostic_bits_rounded']:>18.2f}"
        )
    print("=" * 76)
    print("Interpretation: empirical diagnostics only; no standalone security PASS/FAIL.")

    for entity in ("Alice", "Bob", "Eve"):
        entity_report = report["entities"][entity]
        mfv = entity_report["entropy"]["mfv"]
        compression = entity_report["entropy"]["compression"]
        rssi = entity_report["rssi"]
        print(f"\n{entity} raw audit:")
        print(
            f"  MFV byte={mfv['most_frequent_symbol']}, "
            f"n_max={mfv['n_max']}, p_max={mfv['p_max']:.12f}, "
            f"H_raw={mfv['bits_per_session_unrounded']:.12f}"
        )
        print(
            f"  Compression={compression['compressed_length_bytes']}/"
            f"{compression['original_length_bytes']} bytes, "
            f"ratio={compression['compression_ratio']:.12f}, "
            f"H_raw={compression['scaled_bits_per_session_unrounded']:.12f}"
        )
        print(
            f"  RSSI min/max={rssi['minimum_dbm']:.1f}/{rssi['maximum_dbm']:.1f} dBm, "
            f"P1/P99={rssi['p01_dbm']:.1f}/{rssi['p99_dbm']:.1f} dBm, "
            f"count(-90)={rssi['count_at_minus_90_dbm']}, "
            f"count(-20)={rssi['count_at_minus_20_dbm']}"
        )


def main():
    args = parse_args()
    validate_args(args)

    files = {"Alice": args.alice, "Bob": args.bob, "Eve": args.eve}
    loaded = {entity: load_rssi(path) for entity, path in files.items()}
    rssi_by_entity = {entity: item[0] for entity, item in loaded.items()}
    malformed_by_entity = {entity: item[1] for entity, item in loaded.items()}

    features_by_entity = {
        entity: build_feature_matrix(
            values,
            args.sessions,
            args.window_size,
            args.h0_features,
            args.h1_features,
            entity,
        )
        for entity, values in rssi_by_entity.items()
    }

    symbols_by_entity = {}
    clipping_by_entity = {}
    for entity, features in features_by_entity.items():
        symbols, clipping = quantize_features(
            features,
            args.q_step,
            args.affine_scale,
            args.affine_offset,
        )
        symbols_by_entity[entity] = symbols
        clipping_by_entity[entity] = clipping

    report = {
        "scope": {
            "status": "localized empirical diagnostic",
            "formal_nist_sp_800_90b_validation": False,
            "standalone_cryptographic_entropy_claim": False,
        },
        "parameters": {
            "sessions": args.sessions,
            "segmentation": "fixed non-overlapping windows from flattened CSV streams",
            "window_size": args.window_size,
            "embedding_dimension": EMBED_DIM,
            "time_delay": TIME_DELAY,
            "h0_features": args.h0_features,
            "h1_features": args.h1_features,
            "features_per_window": args.h0_features + args.h1_features,
            "symbols_per_window": args.h0_features + args.h1_features,
            "q_step": args.q_step,
            "affine_scale": args.affine_scale,
            "affine_offset": args.affine_offset,
            "quantization_formula": (
                "clip(floor((affine_scale * feature + affine_offset) / q_step), "
                "0, 255)"
            ),
        },
        "entities": {},
        "paired_feature_diagnostics": paired_feature_diagnostics(
            features_by_entity["Alice"],
            features_by_entity["Bob"],
            features_by_entity["Eve"],
        ),
    }

    required_samples = args.sessions * args.window_size
    for entity in ("Alice", "Bob", "Eve"):
        report["entities"][entity] = {
            "file": files[entity],
            "rssi": rssi_diagnostics(
                rssi_by_entity[entity], malformed_by_entity[entity]
            ),
            "samples_used": required_samples,
            "unused_tail_samples": int(
                len(rssi_by_entity[entity]) - required_samples
            ),
            "quantization": clipping_by_entity[entity],
            "entropy": entity_entropy_report(symbols_by_entity[entity]),
        }

    Path(args.output_json).write_text(
        json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
    )
    write_symbol_csv(args.output_symbols, symbols_by_entity)
    generate_kde_figure(args.output_figure, features_by_entity)
    print_report(report)
    print(f"\nSaved audit JSON: {args.output_json}")
    print(f"Saved quantized symbols: {args.output_symbols}")
    print(f"Saved diagnostic figure: {args.output_figure}")


if __name__ == "__main__":
    main()