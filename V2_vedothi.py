import matplotlib.pyplot as plt
import numpy as np

# =========================================================================
# 1. DỮ LIỆU THỰC TẾ CHÍNH XÁC
# Giao thức		text	    data	bss
# Classical TLS: 	38664	    156	        69080
# Hybrid TLS:		63544	    156	  	73816
# KEMTLS:		48204	    124	  	78128
# Pure PQ-TLS:		67284	    156	  	79760
# Topo-Kyber (Ours):	53644	    136	  	78136
# =========================================================================
labels = ['Classical TLS', 'Hybrid TLS', 'KEMTLS', 'Pure PQ-TLS', 'Topo-Kyber (Ours)']
flash_vals = [38820, 69236, 48328, 67440, 53780]    # text+data (Bytes)
sram_vals = [69236, 73972, 78252, 79916, 78272]     # data+bss (Bytes)
cycle_vals = [66046764, 68772671, 4597758, 8529399, 5614878]

# Quy đổi sang KB để vẽ đồ thị bộ nhớ
flash_kb = [v / 1024 for v in flash_vals]
sram_kb = [v / 1024 for v in sram_vals]

# Tính toán chính xác: So sánh Speed-up của Topo-Kyber so với chuẩn mã hóa Pure PQ-TLS (NIST)
pq_tls_cycles = cycle_vals[3]
speed_up_vs_pqtls = [pq_tls_cycles / v for v in cycle_vals]

# Cấu hình font chữ học thuật chuẩn Q1 / IEEE
plt.rcParams.update({'font.size': 11, 'font.family': 'serif'})

# =========================================================================
# ĐỒ THỊ 1: LATENCY & SPEED-UP ANALYSIS (Lollipop Chart)
# =========================================================================
fig1, ax1 = plt.subplots(figsize=(11, 5.5))
y_pos = np.arange(len(labels))
colors = ['#7f7f7f', '#7f7f7f', '#2ca02c', '#7f7f7f', '#d62728'] # KEMTLS xanh lá, Topo-Kyber đỏ

# Vẽ các đường ngang và điểm tròn đại diện cho Cycles
ax1.hlines(y_pos, xmin=0, xmax=cycle_vals, color=colors, alpha=0.6, linewidth=2)
ax1.scatter(cycle_vals, y_pos, color=colors, s=150, edgecolors='black', zorder=3)

# Cấu hình Log scale cho trục X
ax1.set_xscale('log')
ax1.set_xlabel('Execution Complexity [Clock Cycles] (Log Scale)', fontweight='bold')
ax1.set_yticks(y_pos)
ax1.set_yticklabels(labels, fontweight='bold')
ax1.set_title('Computational Latency & Speed-up Analysis vs. NIST PQ-TLS', pad=20, fontweight='bold')

# Thêm nhãn text hiển thị số chu kỳ máy và hệ số tăng tốc
for i, (val, s_up) in enumerate(zip(cycle_vals, speed_up_vs_pqtls)):
    ax1.text(val * 1.05, i + 0.15, f'{val:,} cycles', va='center', fontsize=9, color='black')
    if labels[i] == 'Topo-Kyber (Ours)':
        ax1.text(val * 1.05, i - 0.25, f'({s_up:.2f}x faster than PQ-TLS)', va='center', fontsize=10, color='#d62728', fontweight='bold')
    elif labels[i] == 'KEMTLS':
        ax1.text(val * 1.05, i - 0.25, f'(Fastest)', va='center', fontsize=9, color='#2ca02c', style='italic')

plt.tight_layout()
plt.savefig('cycles.png', dpi=300)


# =========================================================================
# ĐỒ THỊ 2: PERFORMANCE BUBBLE CHART (Three-Dimensional Trade-off Analysis)
# =========================================================================
fig2, ax2 = plt.subplots(figsize=(11, 7.8))

# Kích thước bong bóng tỷ lệ thuận với Flash ROM (giữ nguyên độ to nhỏ khác nhau)
bubble_sizes = [f * 20 for f in flash_kb] 
marker_colors = ['#bcbd22', '#1f77b4', '#2ca02c', '#9467bd', '#d62728']

# Vẽ các bong bóng dữ liệu lên không gian 2D
for i in range(len(labels)):
    ax2.scatter(cycle_vals[i], sram_kb[i], s=bubble_sizes[i], 
                color=marker_colors[i], alpha=0.75, edgecolors='black', linewidth=1.5,
                label=f"{labels[i]} (Flash: {flash_kb[i]:.1f} KB)")
    
    # Định vị text tên của từng quả bóng, tách KEMTLS và Topo-Kyber ra hai hướng
    if labels[i] == 'KEMTLS':
        offset_x, offset_y = 0.95, 0.45       
    elif labels[i] == 'Topo-Kyber (Ours)':
        offset_x, offset_y = 1.05, -0.55      
    elif labels[i] == 'Hybrid TLS':
        offset_x, offset_y = 1.0, 0.55       
    else:
        offset_x, offset_y = 1.0, 0.5
        
    ax2.text(cycle_vals[i] * offset_x, sram_kb[i] + offset_y, labels[i], 
             ha='center', va='center', fontsize=10, 
             fontweight='bold' if 'Ours' in labels[i] else 'normal')

# Cấu hình hệ trục tọa độ và lưới cho Đồ thị 2
ax2.set_xscale('log')
ax2.set_xlabel('Execution Latency [Clock Cycles] (Log Scale) $\\rightarrow$ Less is Better', fontweight='bold', labelpad=10)
ax2.set_ylabel('Static RAM Memory [KB] $\\rightarrow$ Less is Better', fontweight='bold', labelpad=10)
ax2.set_title('Comprehensive Post-Quantum Protocol Trade-off Analysis\n(Bubble Size Represents Flash ROM Footprint)', pad=15, fontweight='bold')

ax2.grid(True, which="both", ls="--", alpha=0.5)
ax2.set_xlim(min(cycle_vals) * 0.3, max(cycle_vals) * 3)
ax2.set_ylim(min(sram_kb) - 3, max(sram_kb) + 3.5)

# Cấu hình Khung chữ ôm sát, dính liền vào đuôi mũi tên chỉ vào Topo-Kyber
topo_x = cycle_vals[4]
topo_y = sram_kb[4]

ax2.annotate('Optimal Security Trade-off\n(Ours: Fast & Lightweight)', 
             xy=(topo_x, topo_y),             
             xytext=(topo_x * 1.45, topo_y - 1.5), 
             arrowprops=dict(facecolor='#d62728', shrinkA=0, shrinkB=8, width=1.5, headwidth=8, headlength=8),
             fontweight='bold', 
             color='#d62728', 
             ha='left', 
             va='center',
             bbox=dict(boxstyle="round,pad=0.4", fc="yellow", ec="#d62728", alpha=0.15, lw=1))

# Bảng chú thích Legend giữ nguyên kích thước bong bóng to nhỏ, kéo rộng dòng để không dính nhau
ax2.legend(loc='lower left', 
           title="Protocols & Flash Size", 
           frameon=True, 
           shadow=True, 
           labelspacing=2.2, 
           handletextpad=1.5)

plt.tight_layout()
plt.savefig('memory.png', dpi=300)

# hiển thị cả hai đồ thị lên màn hình
plt.show()