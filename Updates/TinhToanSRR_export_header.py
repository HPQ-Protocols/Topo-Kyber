import argparse
import csv
import hashlib
import json
import math
import warnings
from collections import Counter
from pathlib import Path

import numpy as np
from scipy.ndimage import median_filter


DEFAULT_FILES = {
    "Alice": "alice_rssi.csv",
    "Bob": "bob_rssi.csv",
    "Eve": "eva_rssi.csv",
}
DEFAULT_WINDOW_SIZE = 230
DEFAULT_Q_STEP = 0.35
DEFAULT_H0_FEATURES = 20
DEFAULT_H1_FEATURES = 20


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Recompute index-aligned paired-block SRR and export quantized "
            "Topo-Kyber trace vectors for the STM32 artifact."
        )
    )
    parser.add_argument("--alice", default=DEFAULT_FILES["Alice"])
    parser.add_argument("--bob", default=DEFAULT_FILES["Bob"])
    parser.add_argument("--eve", default=DEFAULT_FILES["Eve"])
    parser.add_argument("--window-size", type=int, default=DEFAULT_WINDOW_SIZE)
    parser.add_argument("--q-step", type=float, default=DEFAULT_Q_STEP)
    parser.add_argument("--h0-features", type=int, default=DEFAULT_H0_FEATURES)
    parser.add_argument("--h1-features", type=int, default=DEFAULT_H1_FEATURES)
    parser.add_argument(
        "--csv-column",
        help=(
            "CSV RSSI column name or zero-based index. It is optional for "
            "single-column files and auto-detected for headers containing RSSI."
        ),
    )
    parser.add_argument("--alice-mac", help="Explicit transmitter MAC for Alice PCAP")
    parser.add_argument("--bob-mac", help="Explicit transmitter MAC for Bob PCAP")
    parser.add_argument("--eve-mac", help="Explicit transmitter MAC for Eve PCAP")
    parser.add_argument(
        "--feature-transform",
        choices=("none", "alice-global-zca"),
        default="none",
        help=(
            "Feature transform before QIM. 'none' reproduces the pre-whitening "
            "audit. 'alice-global-zca' fits one offline ZCA frame to the common "
            "Alice blocks and applies it to all entities; this is not the "
            "session-adaptive calibration described by the firmware."
        ),
    )
    parser.add_argument(
        "--zca-regularization",
        type=float,
        default=1e-6,
        help="Positive diagonal regularizer for --feature-transform alice-global-zca.",
    )
    parser.add_argument(
        "--dither-seed",
        type=int,
        default=0,
        help="Base seed for reproducible per-block QIM dithers.",
    )
    parser.add_argument("--output-header", default="srr_features.h")
    parser.add_argument("--output-summary", default="srr_summary.json")
    parser.add_argument(
        "--confirm-index-aligned",
        action="store_true",
        help=(
            "Confirm that block i in all captures can be treated as the same "
            "acquisition interval. This is weaker than session/timestamp pairing."
        ),
    )
    return parser.parse_args()


def validate_args(args):
    if args.window_size <= 0:
        raise ValueError("--window-size must be positive")
    if args.q_step <= 0:
        raise ValueError("--q-step must be positive")
    if args.h0_features < 0 or args.h1_features < 0:
        raise ValueError("Feature counts must be non-negative")
    if args.h0_features + args.h1_features <= 0:
        raise ValueError("At least one persistence feature is required")
    if args.zca_regularization <= 0:
        raise ValueError("--zca-regularization must be positive")
    if args.dither_seed < 0:
        raise ValueError("--dither-seed must be non-negative")
    if not args.confirm_index_aligned:
        raise SystemExit(
            "Refusing to label blocks as paired without explicit confirmation. "
            "Re-run with --confirm-index-aligned only if the captures start from "
            "a common acquisition origin. For rigorous evaluation, pair by "
            "session ID or timestamp instead."
        )


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as input_file:
        for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_csv_column(column):
    if column is None:
        return None
    try:
        return int(column)
    except ValueError:
        return column.strip().lower()


def extract_csv_rssi(csv_file, csv_column=None):
    path = Path(csv_file)
    if not path.is_file():
        raise FileNotFoundError(f"CSV file not found: {path}")

    print(f"[*] Reading {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as input_file:
        rows = [
            [cell.strip() for cell in row]
            for row in csv.reader(input_file)
            if any(cell.strip() for cell in row)
        ]
    if not rows:
        raise ValueError(f"CSV file is empty: {path}")

    requested_column = parse_csv_column(csv_column)
    header = None
    column_index = None
    first_row = rows[0]
    normalized_header = [cell.lower() for cell in first_row]
    rssi_aliases = {
        "rssi",
        "rssi_dbm",
        "rssi (dbm)",
        "dbm",
        "signal",
        "signal_dbm",
        "dBm_AntSignal".lower(),
    }

    if isinstance(requested_column, str):
        if requested_column not in normalized_header:
            raise ValueError(
                f"CSV column {csv_column!r} not found in header of {path}"
            )
        header = first_row
        column_index = normalized_header.index(requested_column)
    elif isinstance(requested_column, int):
        column_index = requested_column
        try:
            float(first_row[column_index])
        except (ValueError, IndexError):
            header = first_row
    elif len(first_row) == 1:
        column_index = 0
        try:
            float(first_row[0])
        except ValueError:
            header = first_row
    else:
        matching_columns = [
            index
            for index, name in enumerate(normalized_header)
            if name in rssi_aliases or "rssi" in name
        ]
        if len(matching_columns) != 1:
            raise ValueError(
                f"Cannot identify one RSSI column in {path}; use --csv-column"
            )
        header = first_row
        column_index = matching_columns[0]

    if column_index is None or column_index < 0:
        raise ValueError(f"Invalid CSV column selection for {path}")

    data_rows = rows[1:] if header is not None else rows
    rssi_values = []
    for line_number, row in enumerate(data_rows, start=2 if header else 1):
        if column_index >= len(row):
            raise ValueError(f"Missing CSV column at {path}:{line_number}")
        try:
            value = float(row[column_index])
        except ValueError as error:
            raise ValueError(
                f"Invalid RSSI value {row[column_index]!r} at "
                f"{path}:{line_number}"
            ) from error
        if not math.isfinite(value):
            raise ValueError(f"Non-finite RSSI value at {path}:{line_number}")
        rssi_values.append(value)

    if not rssi_values:
        raise ValueError(f"No RSSI values found in {path}")
    metadata = {
        "format": "csv",
        "selected_column_index": column_index,
        "selected_column_name": (
            header[column_index] if header is not None else None
        ),
    }
    return np.asarray(rssi_values, dtype=np.float64), metadata


def extract_pcap_rssi(pcap_file, target_mac=None):
    from scapy.all import Dot11, RadioTap, rdpcap

    path = Path(pcap_file)
    if not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    print(f"[*] Reading {path}")
    packets = rdpcap(str(path))
    transmitter_macs = [
        packet.addr2
        for packet in packets
        if packet.haslayer(Dot11) and getattr(packet, "addr2", None)
    ]
    if not transmitter_macs:
        raise ValueError(f"No IEEE 802.11 transmitter addresses found in {path}")

    auto_selected = target_mac is None
    if auto_selected:
        target_mac = Counter(transmitter_macs).most_common(1)[0][0]
        warnings.warn(
            f"{path}: automatically selected most-common transmitter "
            f"{target_mac}. Use the entity-specific --*-mac option to audit "
            "the intended link explicitly.",
            stacklevel=1,
        )
    else:
        target_mac = target_mac.lower()
    rssi_values = []
    for packet in packets:
        transmitter = getattr(packet, "addr2", None)
        if (
            not packet.haslayer(Dot11)
            or transmitter is None
            or transmitter.lower() != target_mac
        ):
            continue
        if not packet.haslayer(RadioTap):
            continue
        rssi = getattr(packet[RadioTap], "dBm_AntSignal", None)
        if rssi is not None:
            rssi_values.append(float(rssi))

    if not rssi_values:
        raise ValueError(f"No radiotap RSSI values found for {target_mac} in {path}")
    metadata = {
        "format": "pcap",
        "selected_transmitter_mac": target_mac,
        "selection": "most-common addr2" if auto_selected else "explicit",
    }
    return np.asarray(rssi_values, dtype=np.float64), metadata


def load_rssi(path, csv_column=None, target_mac=None):
    suffix = Path(path).suffix.lower()
    if suffix in {".csv", ".txt"}:
        return extract_csv_rssi(path, csv_column)
    if suffix in {".pcap", ".pcapng", ".cap"}:
        return extract_pcap_rssi(path, target_mac)
    raise ValueError(
        f"Unsupported input format for {path}; expected CSV/TXT or PCAP/PCAPNG"
    )


def normalize_rssi(rssi):
    minimum = np.min(rssi)
    maximum = np.max(rssi)
    span = maximum - minimum
    if span <= 0:
        return np.zeros_like(rssi, dtype=np.float64)
    return (rssi - minimum) / span


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


def get_tda_features(rssi_window, h0_count, h1_count):
    from ripser import ripser

    normalized = normalize_rssi(rssi_window)
    smoothed = median_filter(normalized, size=5)

    embedding_dimension = 3
    delay = 2
    embedded = np.asarray(
        [
            smoothed[index:index + (embedding_dimension - 1) * delay + 1:delay]
            for index in range(len(smoothed) - (embedding_dimension - 1) * delay)
        ]
    )
    if len(embedded) < 10:
        raise ValueError("Too few embedded points for persistent homology")

    diagrams = ripser(embedded, maxdim=1)["dgms"]
    h0_lifetimes = fixed_lifetimes(diagrams[0], h0_count)
    h1_lifetimes = fixed_lifetimes(diagrams[1], h1_count)
    return np.concatenate((h0_lifetimes, h1_lifetimes))


def build_feature_blocks(signal, entity, window_size, h0_count, h1_count):
    complete_blocks = len(signal) // window_size
    feature_blocks = []
    for block_index in range(complete_blocks):
        start = block_index * window_size
        stop = start + window_size
        try:
            feature_blocks.append(
                get_tda_features(signal[start:stop], h0_count, h1_count)
            )
        except Exception as error:
            raise RuntimeError(
                f"TDA extraction failed for {entity} block {block_index}"
            ) from error

    feature_dimension = h0_count + h1_count
    if not feature_blocks:
        return np.empty((0, feature_dimension), dtype=np.float64)
    return np.asarray(feature_blocks, dtype=np.float64)


def apply_feature_transform(features, paired_blocks, method, regularization):
    trimmed = {
        entity: np.asarray(blocks[:paired_blocks], dtype=np.float64)
        for entity, blocks in features.items()
    }
    if method == "none":
        return trimmed, {
            "method": "none",
            "scope": "pre-whitening TDA lifetime vectors",
        }

    alice = trimmed["Alice"]
    if alice.shape[0] < 2:
        raise ValueError("Alice-global ZCA requires at least two paired blocks")

    mean = np.mean(alice, axis=0)
    centered_alice = alice - mean
    covariance = np.cov(centered_alice, rowvar=False, ddof=1)
    covariance = np.atleast_2d(covariance)
    eigenvalues, eigenvectors = np.linalg.eigh(covariance)
    regularized = np.maximum(eigenvalues, 0.0) + regularization
    whitening = (
        eigenvectors
        @ np.diag(1.0 / np.sqrt(regularized))
        @ eigenvectors.T
    )
    transformed = {
        entity: (blocks - mean) @ whitening.T
        for entity, blocks in trimmed.items()
    }
    warnings.warn(
        "Alice-global ZCA is fitted using all common evaluation blocks. It is "
        "an offline common-frame diagnostic, not session-adaptive pilot-only "
        "calibration and not a leakage-free train/test estimate.",
        stacklevel=1,
    )
    return transformed, {
        "method": "alice-global-zca",
        "scope": "offline common-frame diagnostic fitted on common Alice blocks",
        "regularization": regularization,
        "calibration_blocks": paired_blocks,
        "minimum_raw_eigenvalue": float(np.min(eigenvalues)),
        "maximum_raw_eigenvalue": float(np.max(eigenvalues)),
        "alice_mean": mean.tolist(),
        "whitening_matrix": whitening.tolist(),
    }


def wilson_interval(successes, trials, confidence_z=1.959963984540054):
    if trials <= 0:
        raise ValueError("Wilson interval requires at least one trial")
    proportion = successes / trials
    z_squared = confidence_z**2
    denominator = 1 + z_squared / trials
    center = (proportion + z_squared / (2 * trials)) / denominator
    half_width = (
        confidence_z
        * math.sqrt(
            proportion * (1 - proportion) / trials
            + z_squared / (4 * trials**2)
        )
        / denominator
    )
    return center - half_width, center + half_width


def percentage(value):
    return 100.0 * value


def write_c_header(path, key_blocks, metadata):
    paired_blocks = metadata["paired_blocks"]
    feature_dimension = metadata["parameters"]["feature_dimension"]

    def format_matrix(name, matrix):
        rows = [
            "    {" + ", ".join(str(int(value)) for value in row) + "}"
            for row in matrix
        ]
        return (
            f"static const int32_t {name}[SRR_TRACE_BLOCKS]"
            f"[SRR_TRACE_FEATURE_DIM] = {{\n"
            + ",\n".join(rows)
            + "\n};\n"
        )

    content = (
        "#ifndef SRR_FEATURES_H\n"
        "#define SRR_FEATURES_H\n\n"
        "#include <stdint.h>\n\n"
        "/* Index-aligned complete blocks; see srr_summary.json for caveats. */\n"
        "#define SRR_KEYS_FROM_TRACE 1\n"
        f"#define SRR_TRACE_BLOCKS {paired_blocks}\n"
        f"#define SRR_TRACE_FEATURE_DIM {feature_dimension}\n\n"
        + format_matrix("srr_K_A", key_blocks["Alice"])
        + "\n"
        + format_matrix("srr_K_B", key_blocks["Bob"])
        + "\n"
        + format_matrix("srr_K_E", key_blocks["Eve"])
        + "\n#endif /* SRR_FEATURES_H */\n"
    )
    Path(path).write_text(content, encoding="utf-8")


def main():
    args = parse_args()
    validate_args(args)

    files = {"Alice": args.alice, "Bob": args.bob, "Eve": args.eve}
    target_macs = {
        "Alice": args.alice_mac,
        "Bob": args.bob_mac,
        "Eve": args.eve_mac,
    }
    loaded = {
        entity: load_rssi(
            path,
            csv_column=args.csv_column,
            target_mac=target_macs[entity],
        )
        for entity, path in files.items()
    }
    rssi = {entity: result[0] for entity, result in loaded.items()}
    input_metadata = {
        entity: {
            "path": files[entity],
            "sha256": file_sha256(files[entity]),
            **loaded[entity][1],
        }
        for entity in files
    }
    feature_dimension = args.h0_features + args.h1_features

    features = {
        entity: build_feature_blocks(
            signal,
            entity,
            args.window_size,
            args.h0_features,
            args.h1_features,
        )
        for entity, signal in rssi.items()
    }

    sample_counts = {entity: len(signal) for entity, signal in rssi.items()}
    block_counts = {entity: len(blocks) for entity, blocks in features.items()}
    remainder_samples = {
        entity: count % args.window_size for entity, count in sample_counts.items()
    }
    paired_blocks = min(block_counts.values())
    if paired_blocks == 0:
        raise RuntimeError("No complete block is shared by all three captures")

    dropped_blocks = {
        entity: count - paired_blocks for entity, count in block_counts.items()
    }
    print(f"[*] RSSI samples: {sample_counts}")
    print(f"[*] Complete blocks: {block_counts}")
    print(f"[*] Remainder samples: {remainder_samples}")
    print(f"[*] Index-aligned paired blocks: {paired_blocks}")
    print(f"[*] Unpaired tail blocks excluded: {dropped_blocks}")
    warnings.warn(
        "Block-index pairing assumes synchronized capture origins and does not "
        "establish session-level pairing. State this limitation explicitly.",
        stacklevel=1,
    )
    if feature_dimension != 40:
        warnings.warn(
            f"Feature dimension is {feature_dimension}, whereas the manuscript "
            "currently describes L0=L1=20 (40 features).",
            stacklevel=1,
        )

    features, transform_metadata = apply_feature_transform(
        features,
        paired_blocks,
        args.feature_transform,
        args.zca_regularization,
    )
    print(f"[*] Feature transform: {transform_metadata['method']}")

    key_blocks = {entity: [] for entity in features}
    reject_ab = []
    reject_ae = []

    for block_index in range(paired_blocks):
        alice_features = features["Alice"][block_index]
        bob_features = features["Bob"][block_index]
        eve_features = features["Eve"][block_index]

        seed_sequence = np.random.SeedSequence(
            [args.dither_seed, block_index]
        )
        rng = np.random.default_rng(seed_sequence)
        dither = rng.uniform(
            -args.q_step / 2,
            args.q_step / 2,
            feature_dimension,
        )
        alice_key = np.floor((alice_features + dither) / args.q_step).astype(
            np.int32
        )
        helper = np.mod(alice_features + dither, args.q_step)
        bob_key = np.rint(
            (bob_features + dither - helper) / args.q_step
        ).astype(np.int32)
        eve_key = np.rint(
            (eve_features + dither - helper) / args.q_step
        ).astype(np.int32)

        key_blocks["Alice"].append(alice_key)
        key_blocks["Bob"].append(bob_key)
        key_blocks["Eve"].append(eve_key)

        if not np.array_equal(alice_key, bob_key):
            reject_ab.append(block_index)
        if not np.array_equal(alice_key, eve_key):
            reject_ae.append(block_index)

    key_blocks = {
        entity: np.asarray(blocks, dtype=np.int32)
        for entity, blocks in key_blocks.items()
    }
    ab_rejections = len(reject_ab)
    ae_rejections = len(reject_ae)
    ae_acceptances = paired_blocks - ae_rejections
    ab_srr = ab_rejections / paired_blocks
    ae_srr = ae_rejections / paired_blocks
    eve_bypass = ae_acceptances / paired_blocks
    ab_ci = wilson_interval(ab_rejections, paired_blocks)
    ae_ci = wilson_interval(ae_rejections, paired_blocks)
    bypass_ci = wilson_interval(ae_acceptances, paired_blocks)

    summary = {
        "pairing": {
            "method": "index-aligned complete blocks",
            "assumption": (
                "Capture origins are synchronized; block i refers to a comparable "
                "acquisition interval across Alice, Bob, and Eve."
            ),
            "limitation": (
                "This script does not prove session-level or timestamp-level pairing."
            ),
        },
        "files": files,
        "inputs": input_metadata,
        "sample_counts": sample_counts,
        "complete_block_counts": block_counts,
        "remainder_samples": remainder_samples,
        "paired_blocks": paired_blocks,
        "excluded_unpaired_tail_blocks": dropped_blocks,
        "parameters": {
            "window_size": args.window_size,
            "q_step": args.q_step,
            "h0_features": args.h0_features,
            "h1_features": args.h1_features,
            "feature_dimension": feature_dimension,
            "feature_transform": transform_metadata,
            "dither_seed": args.dither_seed,
            "dither_derivation": (
                "numpy SeedSequence([base_seed, zero_based_block_index])"
            ),
            "rounding": "numpy.rint (nearest integer; ties to even)",
            "acceptance_test": "exact equality of quantized key-index vectors",
        },
        "results": {
            "alice_bob": {
                "rejections": ab_rejections,
                "trials": paired_blocks,
                "srr": ab_srr,
                "wilson_95_ci": list(ab_ci),
                "rejected_block_indices_zero_based": reject_ab,
            },
            "alice_eve": {
                "rejections": ae_rejections,
                "trials": paired_blocks,
                "spoof_rejection_rate": ae_srr,
                "spoof_rejection_wilson_95_ci": list(ae_ci),
                "acceptances": ae_acceptances,
                "physical_bypass_probability": eve_bypass,
                "bypass_wilson_95_ci": list(bypass_ci),
                "rejected_block_indices_zero_based": reject_ae,
            },
        },
    }

    Path(args.output_summary).write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    write_c_header(args.output_header, key_blocks, summary)

    print(
        "Alice--Bob: "
        f"{ab_rejections}/{paired_blocks} rejects, "
        f"SRR={percentage(ab_srr):.2f}%, "
        f"Wilson 95% CI=[{percentage(ab_ci[0]):.2f}%, "
        f"{percentage(ab_ci[1]):.2f}%]"
    )
    print(
        "Alice--Eve: "
        f"{ae_rejections}/{paired_blocks} rejects, "
        f"spoof rejection={percentage(ae_srr):.2f}%, "
        f"Wilson 95% CI=[{percentage(ae_ci[0]):.2f}%, "
        f"{percentage(ae_ci[1]):.2f}%]"
    )
    print(
        "Eve bypass: "
        f"{ae_acceptances}/{paired_blocks}, "
        f"p_E={percentage(eve_bypass):.2f}%, "
        f"Wilson 95% CI=[{percentage(bypass_ci[0]):.2f}%, "
        f"{percentage(bypass_ci[1]):.2f}%]"
    )
    print(f"[*] Wrote {args.output_summary}")
    print(f"[*] Wrote {args.output_header}")


if __name__ == "__main__":
    main()