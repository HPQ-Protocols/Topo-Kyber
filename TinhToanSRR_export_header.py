import numpy as np
from ripser import ripser
from scipy.ndimage import median_filter
from collections import Counter
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import warnings

warnings.filterwarnings("ignore")

# ==========================================
# CẤU HÌNH
# ==========================================
FILES = {
    "Alice": "alice_linux.pcap",
    "Bob": "bob_linux.pcap",
    "Eva": "eva_linux.pcap"
}

WINDOW_SIZE = 230
Q_STEP = 0.35
SALT = b"Topo-Kyber-V2-Fixed-Salt"
FEATURE_DIM = 5   # Cố định số chiều
EXPORT_C_HEADER = "srr_features.h"

# ==========================================
# HÀM HỖ TRỢ
# ==========================================
def extract_rssi_robust(pcap_file):
    print(f"[*] Đang xử lý file: {pcap_file}...")
    try:
        from scapy.all import rdpcap, RadioTap, Dot11
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f" [!] Lỗi đọc file {pcap_file}: {e}")
        return np.array([])

    mac_list = [pkt.addr2 for pkt in packets if pkt.haslayer(Dot11) and getattr(pkt, 'addr2', None)]
    if not mac_list:
        return np.array([])
    
    target_mac = Counter(mac_list).most_common(1)[0][0]
    
    rssi_values = []
    for pkt in packets:
        if pkt.haslayer(Dot11) and getattr(pkt, 'addr2', None) == target_mac:
            if pkt.haslayer(RadioTap):
                try:
                    rssi = pkt[RadioTap].dBm_AntSignal
                    if rssi is not None:
                        rssi_values.append(rssi)
                except:
                    continue
    return np.array(rssi_values)

def normalize_rssi(rssi):
    r_min, r_max = np.min(rssi), np.max(rssi)
    return (rssi - r_min) / (r_max - r_min + 1e-6)

def get_tda_features(rssi_window):
    rssi_norm = normalize_rssi(rssi_window)
    smoothed = median_filter(rssi_norm, size=5)
    
    dim, delay = 3, 2
    n = len(smoothed)
    embedded = np.array([smoothed[i:i+(dim-1)*delay+1:delay] 
                        for i in range(n - (dim-1)*delay)])
    
    if len(embedded) < 10:
        return np.zeros(FEATURE_DIM)
    
    try:
        dgms = ripser(embedded, maxdim=1)['dgms']
        
        # Cố định số lượng features
        h0_lifetimes = np.sort(dgms[0][:-1,1] - dgms[0][:-1,0])[::-1][:3] if len(dgms[0]) > 1 else np.zeros(3)
        h1_lifetimes = np.sort(dgms[1][:,1] - dgms[1][:,0])[::-1][:2] if len(dgms[1]) > 0 else np.zeros(2)
        
        v = np.concatenate([h0_lifetimes, h1_lifetimes])
        # Padding hoặc cắt để luôn có FEATURE_DIM chiều
        if len(v) < FEATURE_DIM:
            v = np.pad(v, (0, FEATURE_DIM - len(v)), 'constant')
        else:
            v = v[:FEATURE_DIM]
        return v
    except:
        return np.zeros(FEATURE_DIM)


def write_c_header(path, K_A_blocks, K_B_blocks, K_E_blocks):
    def format_matrix(name, arr):
        rows = []
        for row in arr:
            rows.append("    {" + ", ".join(str(int(x)) for x in row) + "}")
        return (
            f"static const int32_t {name}[SRR_BLOCKS][SRR_FEATURE_DIM] = {{\n"
            + ",\n".join(rows)
            + "\n};\n"
        )

    content = (
        "#ifndef SRR_FEATURES_H\n"
        "#define SRR_FEATURES_H\n\n"
        "#include <stdint.h>\n\n"
        "#define SRR_KEYS_FROM_TRACE 1\n"
        f"#define SRR_TRACE_BLOCKS {len(K_A_blocks)}\n"
        f"#define SRR_TRACE_FEATURE_DIM {FEATURE_DIM}\n\n"
        + format_matrix("srr_K_A", np.asarray(K_A_blocks, dtype=np.int32))
        + "\n"
        + format_matrix("srr_K_B", np.asarray(K_B_blocks, dtype=np.int32))
        + "\n"
        + format_matrix("srr_K_E", np.asarray(K_E_blocks, dtype=np.int32))
        + "\n#endif /* SRR_FEATURES_H */\n"
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[*] Đã xuất header C: {path}")

# ==========================================
# MAIN
# ==========================================
if __name__ == "__main__":
    print("=== Topo-Kyber KDR Calculation ===")
    
    rssi = {name: extract_rssi_robust(path) for name, path in FILES.items()}
    
    features = {}
    for name in FILES:
        sig = rssi[name]
        feats = []
        for i in range(0, len(sig) - WINDOW_SIZE + 1, WINDOW_SIZE):
            window = sig[i:i + WINDOW_SIZE]
            feat = get_tda_features(window)
            feats.append(feat)
        features[name] = np.array(feats)
    
    total_blocks = len(features["Alice"])
    print(f"Tổng blocks: {total_blocks} (Window = {WINDOW_SIZE})")
    
    match_AB = match_AE = 0
    K_A_blocks, K_B_blocks, K_E_blocks = [], [], []
    
    for i in range(total_blocks):
        v_A = features["Alice"][i]
        v_B = features["Bob"][i]
        v_E = features["Eva"][i]
        
        np.random.seed(i)
        r_q = np.random.uniform(-Q_STEP/2, Q_STEP/2, len(v_A))
        
        K_A = np.floor((v_A + r_q) / Q_STEP).astype(np.int32)
        h   = (v_A + r_q) % Q_STEP
        
        K_B = np.round((v_B + r_q - h) / Q_STEP).astype(np.int32)
        K_E = np.round((v_E + r_q - h) / Q_STEP).astype(np.int32)

        K_A_blocks.append(K_A.copy())
        K_B_blocks.append(K_B.copy())
        K_E_blocks.append(K_E.copy())
        
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=SALT, info=b"topo-kyber-seed")
        seed_A = hkdf.derive(K_A.tobytes())
        
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=SALT, info=b"topo-kyber-seed")
        seed_B = hkdf.derive(K_B.tobytes())
        
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=SALT, info=b"topo-kyber-seed")
        seed_E = hkdf.derive(K_E.tobytes())
        
        if np.array_equal(seed_A, seed_B):
            match_AB += 1
        if np.array_equal(seed_A, seed_E):
            match_AE += 1

    print(f"\nQ_STEP = {Q_STEP}")
    print(f"Alice-Bob KDR : {(1 - match_AB/total_blocks)*100:.2f}%")
    print(f"Alice-Eva KDR : {(1 - match_AE/total_blocks)*100:.2f}%")
    print(f"Eve bypass p_E: {(match_AE/total_blocks)*100:.2f}%")
    write_c_header(EXPORT_C_HEADER, K_A_blocks, K_B_blocks, K_E_blocks)