import matplotlib.pyplot as plt
import numpy as np

# 1. DỮ LIỆU THỰC TẾ
labels = ['Classical TLS', 'Hybrid TLS', 'KEMTLS', 'Pure PQ-TLS', 'Topo-Kyber (Ours)']
flash_vals = [38820, 69236, 48328, 67440, 53780]	# text+data
sram_vals = [69236, 73972, 78252, 79916, 78272]		# data+bss
cycle_vals = [66046764, 68772671, 4597758, 8529399, 5614878]

# Chuyển đổi sang KB
flash_kb = [v / 1024 for v in flash_vals]
sram_kb = [v / 1024 for v in sram_vals]

# Tính hệ số tăng tốc (Speed-up) so với Topo-Kyber
speed_up = [v / cycle_vals[-1] for v in cycle_vals]

# Cấu hình font chữ Q1
plt.rcParams.update({'font.size': 11, 'font.family': 'serif'})

# ---------------------------------------------------------
# HÌNH 1: MEMORY FOOTPRINT (FLASH & SRAM)
# ---------------------------------------------------------
fig1, ax1 = plt.subplots(figsize=(10, 6))
x = np.arange(len(labels))
width = 0.35

rects1 = ax1.bar(x - width/2, flash_kb, width, label='Flash (Text)', color='#1f77b4', edgecolor='black', alpha=0.9)
rects2 = ax1.bar(x + width/2, sram_kb, width, label='SRAM (Data+BSS)', color='#ff7f0e', edgecolor='black', alpha=0.9)

ax1.set_ylabel('Memory Usage (KB)', fontweight='bold')
ax1.set_title('Memory Footprint Comparison on STM32F407', pad=20, fontweight='bold')
ax1.set_xticks(x)
ax1.set_xticklabels(labels)
ax1.legend()
ax1.grid(axis='y', linestyle='--', alpha=0.5)

# Label giá trị
def autolabel(rects):
    for rect in rects:
        height = rect.get_height()
        ax1.annotate(f'{height:.1f}', xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=9)

autolabel(rects1)
autolabel(rects2)

plt.tight_layout()
plt.savefig('memory_footprint.png', dpi=300)
print("Saved: memory_footprint.png")


# ---------------------------------------------------------
# HÌNH 2: COMPUTATIONAL CYCLES (UNIQUE LOLLIPOP CHART)
# ---------------------------------------------------------
fig2, ax2 = plt.subplots(figsize=(10, 6))

# Đảo ngược thứ tự để giải pháp của mình nằm ở trên cùng hoặc dưới cùng cho dễ nhìn
y_pos = np.arange(len(labels))
colors = ['#7f7f7f', '#7f7f7f', '#7f7f7f', '#7f7f7f', '#d62728']

# Vẽ các đường ngang (thân kẹo)
ax2.hlines(y_pos, xmin=0, xmax=cycle_vals, color=colors, alpha=0.6, linewidth=2)
# Vẽ các điểm tròn (đầu kẹo)
ax2.scatter(cycle_vals, y_pos, color=colors, s=150, edgecolors='black', zorder=3)

# Cấu hình Log scale cho trục X
ax2.set_xscale('log')
ax2.set_xlabel('Clock Cycles (Log Scale)', fontweight='bold')
ax2.set_yticks(y_pos)
ax2.set_yticklabels(labels)
ax2.set_title('Computational Complexity and Speed-up Analysis', pad=20, fontweight='bold')

# Thêm nhãn giá trị và hệ số Speed-up
for i, (val, s_up) in enumerate(zip(cycle_vals, speed_up)):
    # Ghi số Cycles
    ax2.text(val, i + 0.2, f'{val:,} cycles', va='center', fontsize=10, fontweight='bold')
    # Ghi Speed-up (chỉ ghi cho các phương pháp chậm hơn)
    if s_up > 1:
        ax2.text(val, i - 0.25, f'({s_up:.1f}x slower)', va='center', fontsize=9, color='#555555', fontstyle='italic')
    else:
        ax2.text(val, i - 0.25, '(Fastest)', va='center', fontsize=9, color='#d62728', fontweight='bold')

ax2.grid(axis='x', which='both', linestyle=':', alpha=0.4)
ax2.set_xlim(left=1e6) # Giới hạn nhìn từ 1 triệu chu kỳ

plt.tight_layout()
plt.savefig('computational_cycles.png', dpi=300)
print("Saved: computational_cycles.png")

plt.show()