import numpy as np
import matplotlib.pyplot as plt
from scapy.all import rdpcap, RadioTap, Dot11
from collections import Counter
from ripser import ripser
import os
import warnings

warnings.filterwarnings("ignore")

# ==========================================
# 1. HÀM ĐỌC PCAP (GIỮ NGUYÊN BẢN CHUẨN)
# ==========================================
def extract_rssi_real(pcap_file, max_pkts=5000):
    if not os.path.exists(pcap_file):
        print(f"[!] Không tìm thấy file: {pcap_file}")
        return None
    try:
        packets = rdpcap(pcap_file, count=max_pkts)
        rssi_values = []
        mac_list = [pkt.addr2 for pkt in packets if pkt.haslayer(Dot11) and pkt.addr2]
        if not mac_list: return None
        target_mac = Counter(mac_list).most_common(1)[0][0]
        for pkt in packets:
            if pkt.haslayer(RadioTap) and pkt.addr2 == target_mac:
                rssi = getattr(pkt[RadioTap], 'dBm_AntSignal', None)
                if rssi is not None: rssi_values.append(rssi)
        return np.array(rssi_values)
    except Exception as e:
        print(f"[!] Lỗi: {e}")
        return None

# ==========================================
# 2. VẼ BIỂU ĐỒ BONG BÓNG (BUBBLE CHART)
# ==========================================
def plot_bubble_tda(data_dict, start=0, end=200):
    names = list(data_dict.keys())
    fig, axes = plt.subplots(len(names), 2, figsize=(15, 16))
    plt.subplots_adjust(hspace=0.4, wspace=0.3)

    for i, name in enumerate(names):
        # --- Bước A: Xử lý dữ liệu ---
        rssi_window = data_dict[name][start:end]
        
        # Chuẩn hóa về [0, 1]
        norm = (rssi_window - np.min(rssi_window)) / (np.max(rssi_window) - np.min(rssi_window) + 1e-6)
        
        # Nhúng 3D, delay=1 để lấy trọn vẹn số điểm
        dim, delay = 3, 1
        embedded = np.array([norm[j : j + (dim - 1)*delay + 1 : delay] 
                             for j in range(len(norm) - (dim - 1)*delay)])
        
        # Tính TDA (Ripser)
        result = ripser(embedded, maxdim=1)
        h0, h1 = result['dgms'][0], result['dgms'][1]

        # --- Bước B: Vẽ Tín hiệu gốc (Cột 1) ---
        axes[i, 0].plot(rssi_window, color='black', lw=1.2)
        axes[i, 0].set_title(f"Raw RSSI: {name} (Packets {start}-{end})")
        axes[i, 0].set_ylabel("RSSI (dBm)")
        axes[i, 0].grid(alpha=0.3)

        # --- Bước C: Vẽ Bubble Diagram (Cột 2) ---
        max_val = 1.0 
        axes[i, 1].plot([0, max_val], [0, max_val], color='red', linestyle='--', alpha=0.5) # Đường chéo

        # 1. XỬ LÝ H0 (MÀU XANH)
        h0_finite = h0[h0[:, 1] != np.inf]
        # Làm tròn 3 chữ số thập phân để gom các điểm cực gần nhau do sai số dấy phẩy động
        h0_rounded = [tuple(np.round(pt, 3)) for pt in h0_finite]
        h0_counts = Counter(h0_rounded)

        for (birth, death), count in h0_counts.items():
            # Kích thước tỷ lệ với số lượng điểm chồng lên nhau (nhân với 30 để bong bóng đủ to)
            bubble_size = max(40, count * 30) 
            axes[i, 1].scatter(birth, death, s=bubble_size, c='#1f77b4', alpha=0.6, edgecolors='black')
            
            # Nếu có nhiều hơn 1 hạt chồng nhau, in con số lên giữa bong bóng
            if count > 0:
                axes[i, 1].text(birth, death, str(count), fontsize=9, fontweight='bold', 
                                ha='center', va='center', color='white')

        # 2. XỬ LÝ H1 (MÀU CAM)
        if len(h1) > 0:
            h1_rounded = [tuple(np.round(pt, 3)) for pt in h1]
            h1_counts = Counter(h1_rounded)
            
            for (birth, death), count in h1_counts.items():
                bubble_size = max(50, count * 40)
                axes[i, 1].scatter(birth, death, s=bubble_size, c='#ff7f0e', marker='o', alpha=0.7, edgecolors='black')
                if count > 0:
                    axes[i, 1].text(birth, death, str(count), fontsize=9, fontweight='bold', 
                                    ha='center', va='center', color='black')

        axes[i, 1].set_title(f"Bubble Persistence Diagram: {name}\nDetected: {len(h0_finite)} H0 | {len(h1)} H1")
        axes[i, 1].set_xlabel("Birth")
        axes[i, 1].set_ylabel("Death")
        axes[i, 1].set_xlim([-0.05, max_val])
        axes[i, 1].set_ylim([-0.05, max_val])
        axes[i, 1].grid(alpha=0.2)

        print(f"[+] {name}: Đã vẽ {len(h0_finite)} hạt H0 và {len(h1)} hạt H1 (đã gom nhóm).")

    plt.suptitle("OVERPLOTTING RESOLUTION: BUBBLE PERSISTENCE DIAGRAMS", fontsize=18, fontweight='bold')
    plt.savefig("TDA_Bubble_Chart.png", dpi=300, bbox_inches='tight')
    plt.show()

# ==========================================
# 3. THỰC THI
# ==========================================
if __name__ == "__main__":
    pcap_files = {
        'Alice': 'alice_linux.pcap',
        'Bob':   'bob_linux.pcap',
        'Eva':   'eva_linux.pcap'
    }
    
    data = {}
    for label, path in pcap_files.items():
        rssi = extract_rssi_real(path)
        if rssi is not None:
            data[label] = rssi

    if len(data) == 3:
        # Chạy cửa sổ 0-200
        print("\n[*] Đang tính toán và vẽ Bubble Chart...")
        plot_bubble_tda(data, start=0, end=200)
        print("\n[+] Hoàn tất! File TDA_Bubble_Chart.png đã được lưu.")
    else:
        print("[!] Không đủ 3 file PCAP để vẽ biểu đồ.")