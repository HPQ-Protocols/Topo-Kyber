/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "usb_host.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "api.h"
#include "mldsa_api.h"
#include <string.h>
#include "randombytes.h"
#include "fips202.h" // Dùng hàm băm SHA3-256 có sẵn cho KDF và HMAC
#include <math.h>        // THÊM: Cần cho các hàm toán học của TDA
#include <stdio.h>
#include <stdlib.h> // THÊM DÒNG NÀY để hết lỗi 'rand'
#include "hmac_hkdf.h"

// TUYỆT CHIÊU: Tự khai báo 3 hàm của ML-DSA-44 để né xung đột Macro
//int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
//int crypto_sign(uint8_t *sm, size_t *smlen, const uint8_t *msg, size_t len, const uint8_t *sk);
//int crypto_sign_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *pk);
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
#define WINDOW_SIZE 40
#define FEATURE_DIM 10
#define Q_STEP 1.0f
/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
I2C_HandleTypeDef hi2c1;

I2S_HandleTypeDef hi2s3;

RNG_HandleTypeDef hrng;

SPI_HandleTypeDef hspi1;

/* USER CODE BEGIN PV */
// NHẤN MẠNH 1: Đưa các biến kết quả ra toàn cục để dễ quan sát Value (không phải Address)
volatile uint32_t result_classical = 0;
volatile uint32_t result_hybrid = 0;
volatile uint32_t result_kemtls = 0;
// volatile uint32_t result_pqtls = 0;
volatile uint32_t result_topokyber = 0;
volatile uint32_t result_pqtls = 0; // Biến xem cycles của Kyber+Dilithium
volatile uint32_t total_cycles = 0;

// --- THÊM MỚI: CÁC BIẾN LƯU BỘ NHỚ RAM (Hiển thị trực tiếp trên Live Expressions) ---
volatile uint32_t ram_classical = 0;
volatile uint32_t ram_hybrid = 0;
volatile uint32_t ram_kemtls = 0;
volatile uint32_t ram_topokyber = 0; // Gồm cả Static RAM và Stack xử lý TDA
volatile uint32_t ram_pqtls = 0;

#define SAMPLES 40
#define FEAT_LEN 10
#define Q_STEP 1.0f

// Dữ liệu RSSI thực tế trích xuất từ PCAP
const float test_rssi_alice[40] = {-84,-84,-83,-84,-84,-84,-84,-84,-85,-84,-89,-84,-84,-85,-84,-85,-85,-83,-85,-84,-83,-83,-86,-85,-84,-84,-84,-84,-83,-84,-85,-85,-85,-83,-86,-86,-84,-84,-84,-83};
const float test_rssi_bob[40]   = {-83, -86, -85, -85, -85, -83, -85, -81, -85, -85, -85, -85, -84, -86, -84, -85, -85, -84, -84, -86, -86, -86, -83, -83, -84, -85, -86, -84, -86, -84,-85, -85, -85, -85, -85, -85, -84, -87, -86, -85};

// Ma trận ZCA Whitening (Đã tính toán offline từ phân phối RSSI của thiết bị)
const float ZCA_Matrix[2][2] = {
    {1.1542f, -0.0123f},
    {-0.0123f, 1.1542f}
};
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_I2C1_Init(void);
static void MX_I2S3_Init(void);
static void MX_RNG_Init(void);
static void MX_SPI1_Init(void);
void MX_USB_HOST_Process(void);

/* USER CODE BEGIN PFP */
// THÊM: Khai báo hàm cho Topo-Kyber
void run_micro_tda(const float* rssi, float* features_out);
void benchmark_Topo_Kyber(void);

// THÊM DÒNG NÀY: Khai báo hàm benchmark tổng hợp
void benchmark_All_Protocols(void);

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
#include "uECC.h"
// THÊM HÀM NÀY ĐỂ ĐỌC BỘ ĐẾM CHU KỲ
uint32_t get_cycles(void) {
    return DWT->CYCCNT;
}
// Lưu ý: Bạn cần có sẵn các thư viện của Kyber (#include "api.h", v.v.)
// và hàm get_cycles() mà bạn vẫn đang dùng để đo.

// =========================================================================
// HÀM BỔ TRỢ: Bắt buộc phải có để uECC sinh được số ngẫu nhiên
// =========================================================================
int fake_rng(uint8_t *dest, unsigned size) {
    // Đây chỉ là hàm tạo số ngẫu nhiên giả để benchmark đo thời gian
    for (unsigned i = 0; i < size; ++i) {
        dest[i] = (uint8_t)(i ^ 0xAA);
    }
    return 1;
}

// =========================================================================
// 1. ĐO LƯỜNG CLASSICAL TLS 1.3 (Sử dụng đường cong secp256r1)
// =========================================================================
void benchmark_Classical_TLS(void) {
    static uint8_t public_key_client[64], private_key_client[32];
    static uint8_t public_key_server[64], private_key_server[32];
    static uint8_t shared_secret_client[32], shared_secret_server[32];

    // Khóa dài hạn ECDSA của Server (Nằm trong Chứng chỉ số - Sinh ngoài vòng đo)
    static uint8_t auth_pk_server[64], auth_sk_server[32];
    static uint8_t hash[32] = {0x12, 0x34};
    static uint8_t signature[64];

    uECC_set_rng(&fake_rng);
    const struct uECC_Curve_t * curve = uECC_secp256r1();

    // SỬA CHUẨN: Sinh trước khóa xác thực tĩnh để không tính vào chu kỳ Handshake
    uECC_make_key(auth_pk_server, auth_sk_server, curve);

    uint32_t start, end;
    start = get_cycles();

    // --- PHA 1: THỎA THUẬN KHÓA (ECDHE Key Exchange) ---
    uECC_make_key(public_key_client, private_key_client, curve);
    uECC_make_key(public_key_server, private_key_server, curve);
    uECC_shared_secret(public_key_server, private_key_client, shared_secret_client, curve);
    uECC_shared_secret(public_key_client, private_key_server, shared_secret_server, curve);

    // --- PHA 2: XÁC THỰC (ECDSA Authentication) ---
    uECC_sign(auth_sk_server, hash, sizeof(hash), signature, curve);
    uECC_verify(auth_pk_server, hash, sizeof(hash), signature, curve);

    end = get_cycles();
    result_classical = end - start;
}

// =========================================================================
// 2. ĐO LƯỜNG HYBRID TLS 1.3 (ECC + Kyber)
// =========================================================================
void benchmark_Hybrid_TLS(void) {
    static uint8_t public_key_client[64], private_key_client[32];
    static uint8_t public_key_server[64], private_key_server[32];
    static uint8_t shared_secret_ecc_client[32], shared_secret_ecc_server[32];

    static uint8_t auth_pk_server[64], auth_sk_server[32];
    static uint8_t hash[32] = {0x12, 0x34};
    static uint8_t signature[64];

    static uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    static uint8_t sk[CRYPTO_SECRETKEYBYTES];
    static uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    static uint8_t ss_server[CRYPTO_BYTES], ss_client[CRYPTO_BYTES];

    uECC_set_rng(&fake_rng);
    const struct uECC_Curve_t * curve = uECC_secp256r1();
    uECC_make_key(auth_pk_server, auth_sk_server, curve);

    uint32_t start, end;
    start = get_cycles();

    // --- PHA 1: Thỏa thuận & Xác thực bằng Cổ điển (ECC) ---
    uECC_make_key(public_key_client, private_key_client, curve);
    uECC_make_key(public_key_server, private_key_server, curve);

    // SỬA LỖI 1: Gọi đủ 2 lần tính toán shared secret phía ECC cho đúng thực tế máy trạm và máy chủ
    uECC_shared_secret(public_key_server, private_key_client, shared_secret_ecc_client, curve);
    uECC_shared_secret(public_key_client, private_key_server, shared_secret_ecc_server, curve);

    uECC_sign(auth_sk_server, hash, sizeof(hash), signature, curve);
    uECC_verify(auth_pk_server, hash, sizeof(hash), signature, curve);

    // --- PHA 2: Thêm lớp Thỏa thuận khóa Lượng tử (Kyber) ---
    crypto_kem_keypair(pk, sk);
    crypto_kem_enc(ct, ss_server, pk);
    crypto_kem_dec(ss_client, ct, sk);

    end = get_cycles();
    result_hybrid = end - start;
}

// =========================================================================
// 3. ĐO LƯỜNG KEMTLS (Dùng 100% Kyber, Bỏ hoàn toàn chữ ký số)
// =========================================================================
void benchmark_KEMTLS(void) {
    // Biến cho Ephemeral KEM (Thỏa thuận khóa ngắn hạn)
    static uint8_t ephem_pk[CRYPTO_PUBLICKEYBYTES], ephem_sk[CRYPTO_SECRETKEYBYTES];
    static uint8_t ephem_ct[CRYPTO_CIPHERTEXTBYTES], ephem_ss_server[CRYPTO_BYTES], ephem_ss_client[CRYPTO_BYTES];

    // Biến cho Long-term KEM (Xác thực thực thể bằng KEM - Thay thế Certificate)
    static uint8_t auth_pk[CRYPTO_PUBLICKEYBYTES], auth_sk[CRYPTO_SECRETKEYBYTES];
    static uint8_t auth_ct[CRYPTO_CIPHERTEXTBYTES], auth_ss_server[CRYPTO_BYTES], auth_ss_client[CRYPTO_BYTES];

    // SỬA LỖI 2: Cặp khóa xác thực tĩnh được sinh từ trước (Nằm sẵn trong cấu hình thiết bị)
    crypto_kem_keypair(auth_pk, auth_sk);

    uint32_t start, end;
    start = get_cycles();

    // --- PHA 1: Ephemeral KEM Exchange (Thay thế ECDHE) ---
    crypto_kem_keypair(ephem_pk, ephem_sk);
    crypto_kem_enc(ephem_ct, ephem_ss_server, ephem_pk);
    crypto_kem_dec(ephem_ss_client, ephem_ct, ephem_sk);

    // --- PHA 2: Long-term KEM Auth (Đúng chuẩn KEMTLS) ---
    // SỬA: BỎ HOÀN TOÀN crypto_kem_keypair(auth_pk, auth_sk). Handshake chỉ có Encaps và Decaps
    crypto_kem_enc(auth_ct, auth_ss_client, auth_pk);
    crypto_kem_dec(auth_ss_server, auth_ct, auth_sk);

    end = get_cycles();
    result_kemtls = end - start;
}


// =========================================================================
// 4. ĐO LƯỜNG TOPO-KYBER
// =========================================================================

// Hàm Micro-TDA: Tích hợp ZCA + Takens + Vietoris-Rips Approximation
void run_micro_tda(const float* rssi_in, float* features_out) {
    float points_2d[SAMPLES-1][2];

    // 1. TAKENS EMBEDDING (d=2, tau=1) kết hợp ZCA WHITENING
    for(int i = 0; i < SAMPLES-1; i++) {
        // Center dữ liệu (trừ đi trung bình RSSI thường là -85dBm)
        float raw_x = rssi_in[i] + 85.0f;
        float raw_y = rssi_in[i+1] + 85.0f;

        // Nhân ma trận ZCA để khử tương quan chuỗi thời gian
        points_2d[i][0] = raw_x * ZCA_Matrix[0][0] + raw_y * ZCA_Matrix[0][1];
        points_2d[i][1] = raw_x * ZCA_Matrix[1][0] + raw_y * ZCA_Matrix[1][1];
    }

    // 2. VIETORIS-RIPS PROXY (Tính đặc trưng mật độ khoảng cách)
    for(int k = 0; k < FEAT_LEN; k++) {
        features_out[k] = 0.0f;
        for(int j = 0; j < SAMPLES-1; j++) {
            float dx = points_2d[k][0] - points_2d[j][0];
            float dy = points_2d[k][1] - points_2d[j][1];
            features_out[k] += sqrtf(dx*dx + dy*dy);
        }
        features_out[k] /= (SAMPLES-1); // Đặc trưng hình thái topo
    }
}
void benchmark_Topo_Kyber(void) {
    volatile uint32_t t0, t1;
    volatile uint32_t cyc_alice_total, cyc_bob_total;

    // Các biến định danh và tính toán vật lý (TDA)
    uint8_t id_A[32] = {0x01}, id_B[32] = {0x02};
    uint8_t s_A[32], s_B[32], h_hash[32], sid[32];
    float feat_A[FEATURE_DIM], feat_B[FEATURE_DIM], helper[FEATURE_DIM], r_q_vector[FEATURE_DIM];
    int32_t K_int_A[FEATURE_DIM], K_int_B[FEATURE_DIM];

    // --- CẤU TRÚC 2 CẶP KHÓA THEO ĐÚNG PHẢN BIỆN ---
    // Lớp 1: wrap-KEM
    static uint8_t pk_A_wrap[CRYPTO_PUBLICKEYBYTES], sk_A_wrap[CRYPTO_SECRETKEYBYTES];
    static uint8_t ct_wrap[CRYPTO_CIPHERTEXTBYTES];
    static uint8_t k_seed_A_wrap[CRYPTO_BYTES], k_seed_B_wrap[CRYPTO_BYTES];

    // Lớp 2: main-AKE-KEM
    static uint8_t pk_B_main[CRYPTO_PUBLICKEYBYTES], sk_B_main[CRYPTO_SECRETKEYBYTES];
    static uint8_t ct_main[CRYPTO_CIPHERTEXTBYTES];
    static uint8_t k_seed_A_main[CRYPTO_BYTES], k_seed_B_main[CRYPTO_BYTES];

    // Biến lưu khóa phiên cuối cùng
    uint8_t k_session_A[32], k_session_B[32];

    // Bật bộ đếm xung nhịp phần cứng DWT
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0; DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;

    // ====================================================================
    // 1. PHÍA ALICE (Giai đoạn gửi gói: TDA + Sinh Sketch + wrap-KeyGen)
    // ====================================================================
    t0 = DWT->CYCCNT;

    run_micro_tda(test_rssi_alice, feat_A);

    // SỬA FATAL-2: Sử dụng TRNG phần cứng thay thế hoàn toàn hàm rand() lỗi
    uint32_t rng_val;
    for(int i = 0; i < FEATURE_DIM; i++) {
        HAL_RNG_GenerateRandomNumber(&hrng, &rng_val); // Lấy số ngẫu nhiên thực thể từ chip
        r_q_vector[i] = ((float)rng_val / (float)0xFFFFFFFF) * Q_STEP - (Q_STEP / 2.0f); // Phân phối đều U(-Q/2, Q/2)

        K_int_A[i] = (int32_t)floorf((feat_A[i] + r_q_vector[i]) / Q_STEP);
        helper[i] = (feat_A[i] + r_q_vector[i]) - ((float)K_int_A[i] * Q_STEP);
    }
    sha3_256(s_A, (uint8_t*)K_int_A, FEATURE_DIM * sizeof(int32_t));
    sha3_256(h_hash, (uint8_t*)helper, FEATURE_DIM * sizeof(float));

    // Thao tác KEM 1 của Alice: Sinh cặp khóa bảo vệ (wrap-KEM)
    crypto_kem_keypair(pk_A_wrap, sk_A_wrap);

    // Giả định gói tin (pk_A_wrap, r_q_vector, helper) được truyền sang Bob...
    t1 = DWT->CYCCNT;
    cyc_alice_total = (t1 - t0); // Ghi nhận thời gian phase 1 của Alice

    // ====================================================================
    // 2. PHÍA BOB (Nhận gói: TDA + Khôi phục Sketch + wrap-Encaps + main-KeyGen)
    // ====================================================================
    t0 = DWT->CYCCNT;

    run_micro_tda(test_rssi_bob, feat_B);

    // Khôi phục khóa vật lý dựa trên helper nhận từ Alice
    for(int i = 0; i < FEATURE_DIM; i++) {
        K_int_B[i] = (int32_t)roundf((feat_B[i] + r_q_vector[i] - helper[i]) / Q_STEP);
    }
    sha3_256(s_B, (uint8_t*)K_int_B, FEATURE_DIM * sizeof(int32_t));

    // Thao tác KEM 1 của Bob: Đóng gói khóa lớp ngoài (wrap-Encaps) hướng tới Alice
    crypto_kem_enc(ct_wrap, k_seed_B_wrap, pk_A_wrap);

    // Thao tác KEM 2 của Bob (Yêu cầu phản biện): Tự sinh cặp khóa AKE chính chủ (main-KeyGen)
    crypto_kem_keypair(pk_B_main, sk_B_main);

    // Tính Session ID cho phiên làm việc
    uint8_t sid_buf[64];
    memcpy(sid_buf, id_A, 32); memcpy(sid_buf + 32, id_B, 32);
    sha3_256(sid, sid_buf, 64);

    // Giả định gói tin (ct_wrap, pk_B_main) được truyền trả lại Alice...
    t1 = DWT->CYCCNT;
    cyc_bob_total = (t1 - t0);

    // ====================================================================
    // 3. PHÍA ALICE (Nhận phản hồi: wrap-Decaps + main-Encaps + KDF)
    // ====================================================================
    t0 = DWT->CYCCNT;

    // Thao tác KEM 2 của Alice: Giải gói lớp ngoài để lấy k_seed_wrap
    crypto_kem_dec(k_seed_A_wrap, ct_wrap, sk_A_wrap);

    // Thao tác KEM 3 của Alice (Yêu cầu phản biện): Đóng gói ngược lại khóa lớp trong (main-Encaps) hướng tới Bob
    crypto_kem_enc(ct_main, k_seed_A_main, pk_B_main);

    // Trộn toàn bộ các thành phần (wrap-seed, main-seed, vật lý-seed TDA) vào KDF final của Alice
    uint8_t kdf_buf_A[128];
    memcpy(kdf_buf_A, k_seed_A_wrap, 32);
    memcpy(kdf_buf_A + 32, k_seed_A_main, 32);
    memcpy(kdf_buf_A + 64, s_A, 32);               // Entropy vật lý chứng minh sở hữu kênh truyền
    memcpy(kdf_buf_A + 96, sid, 32);
    sha3_256(k_session_A, kdf_buf_A, 128);

    // Giả định ct_main được gửi nốt cho Bob để chốt phiên...
    t1 = DWT->CYCCNT;
    cyc_alice_total += (t1 - t0); // Cộng dồn tổng chu kỳ xử lý của Alice

    // ====================================================================
    // 4. PHÍA BOB (Nhận gói cuối: main-Decaps + KDF)
    // ====================================================================
    t0 = DWT->CYCCNT;

    // Thao tác KEM 3 của Bob: Giải gói lớp trong cùng để lấy k_seed_main
    crypto_kem_dec(k_seed_B_main, ct_main, sk_B_main);

    // Trộn toàn bộ vào KDF final của Bob
    uint8_t kdf_buf_B[128];
    memcpy(kdf_buf_B, k_seed_B_wrap, 32);
    memcpy(kdf_buf_B + 32, k_seed_B_main, 32);
    memcpy(kdf_buf_B + 64, s_B, 32);               // Entropy vật lý đối sánh
    memcpy(kdf_buf_B + 96, sid, 32);
    sha3_256(k_session_B, kdf_buf_B, 128);

    t1 = DWT->CYCCNT;
    cyc_bob_total += (t1 - t0); // Cộng dồn tổng chu kỳ xử lý của Bob

    // In kết quả trung thực ra màn hình terminal để lấy số liệu chuẩn ghi vào bài báo
    result_topokyber = cyc_alice_total + cyc_bob_total;
    printf("--- KẾT QUẢ ĐO CHU KỲ TOPO-KYBER (ĐÃ SỬA THEO PHẢN BIỆN) ---\n");
    printf("Tổng chu kỳ xử lý của Alice: %lu\n", cyc_alice_total);
    printf("Tổng chu kỳ xử lý của Bob: %lu\n", cyc_bob_total);
    printf("Tổng chu kỳ toàn bộ hệ thống: %lu\n", result_topokyber);
}
// =========================================================================
// 5. ĐO LƯỜNG POST-QUANTUM TLS (Kyber + ML-DSA-44)
// =========================================================================
void benchmark_PQ_TLS(void) {
    // ---- Biến cho Kyber (KEM) ----
    static uint8_t pk_kyber[CRYPTO_PUBLICKEYBYTES];
    static uint8_t sk_kyber[CRYPTO_SECRETKEYBYTES];
    static uint8_t ct_kyber[CRYPTO_CIPHERTEXTBYTES];
    static uint8_t ss_server[CRYPTO_BYTES], ss_client[CRYPTO_BYTES];

    // ---- Biến cho ML-DSA-44 (Chữ ký số) ----
    static uint8_t pk_mldsa[1312];
    static uint8_t sk_mldsa[2560];
    static uint8_t signature[2420 + 32];
    static size_t sig_len;

    static uint8_t message[32] = {0x11, 0x22, 0x33, 0x44};
    static size_t msg_len = 32;
    static uint8_t message_out[32];
    static size_t msg_len_out;

    // SỬA LỖI 3: Khóa chữ ký số tĩnh của Server được sinh trước (Mô phỏng nạp từ Certificate)
    crypto_sign_keypair(pk_mldsa, sk_mldsa);

    uint32_t start, end;
    start = get_cycles();

    // Pha 1: Trao đổi khóa lượng tử (Kyber Ephemeral)
    crypto_kem_keypair(pk_kyber, sk_kyber);
    crypto_kem_enc(ct_kyber, ss_server, pk_kyber);
    crypto_kem_dec(ss_client, ct_kyber, sk_kyber);

    // Pha 2: Chữ ký số Post-Quantum (ML-DSA-44)
    // SỬA: BỎ HOÀN TOÀN crypto_sign_keypair khỏi quá trình đo Handshake!
    crypto_sign(signature, &sig_len, message, msg_len, sk_mldsa);
    crypto_sign_open(message_out, &msg_len_out, signature, sig_len, pk_mldsa);

    end = get_cycles();
    result_pqtls = end - start;
}

/* ============================================================
 * NTN-PQ-AKE+ v4.0 Benchmark
 * Total Handshake (Alice + Bob)
 * ============================================================ */

uint32_t benchmark_NTN_PQ_AKE_v40(void)
{
	// volatile uint32_t start;
	// volatile uint32_t end;
	uint32_t start, end;
    uint32_t cycles = 0;

    /* ==========================================================
       Long-term PSK
       ========================================================== */
    uint8_t psk[32];
    memset(psk, 0x11, sizeof(psk));

    /* ==========================================================
       Alice
       ========================================================== */
    uint8_t pkA[CRYPTO_PUBLICKEYBYTES];
    uint8_t skA[CRYPTO_SECRETKEYBYTES];

    uint8_t nonceA[16];
    uint8_t nonceB[16];

    uint32_t ctrA = 1;
    uint32_t ctrB = 1;

    /* ==========================================================
       Bob
       ========================================================== */
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t ssB[CRYPTO_BYTES];

    /* ==========================================================
       Alice
       ========================================================== */
    uint8_t ssA[CRYPTO_BYTES];

    /* ==========================================================
       Buffers
       ========================================================== */
    uint8_t session_ctx[32];

    uint8_t tokenA[32];

    uint8_t Ktemp_B[32];
    uint8_t Ktemp_A[32];

    uint8_t confirmB[32];
    uint8_t confirmA[32];

    uint8_t session_ready[32];

    uint8_t Ksession_A[32];
    uint8_t Ksession_B[32];

    uint8_t transcript[96];

    size_t offset;

    /************************************************************
     * M1 : Alice -> Bob
     ************************************************************/
    start = DWT->CYCCNT;

    randombytes(nonceA, sizeof(nonceA));

    crypto_kem_keypair(pkA, skA);

    hmac_sha3_256(
        tokenA,
        psk,
        sizeof(psk),
        pkA,
        CRYPTO_PUBLICKEYBYTES);

    end = DWT->CYCCNT;
    cycles += (end - start);

    /************************************************************
     * M2 : Bob -> Alice
     ************************************************************/
    start = DWT->CYCCNT;

    randombytes(nonceB, sizeof(nonceB));

    crypto_kem_enc(
        ct,
        ssB,
        pkA);

    offset = 0;

    memcpy(session_ctx + offset, nonceA, 16);
    offset += 16;

    memcpy(session_ctx + offset, nonceB, 16);
    offset += 16;

    sha3_256(
        session_ctx,
        session_ctx,
        offset);

    hkdf_sha3(
        Ktemp_B,
        ssB,
        CRYPTO_BYTES,
        psk,
        sizeof(psk));

    hmac_sha3_256(
        confirmB,
        Ktemp_B,
        32,
        session_ctx,
        32);

    end = DWT->CYCCNT;
    cycles += (end - start);

    /************************************************************
     * M3 : Alice -> Bob
     ************************************************************/
    start = DWT->CYCCNT;

    crypto_kem_dec(
        ssA,
        ct,
        skA);

    hkdf_sha3(
        Ktemp_A,
        ssA,
        CRYPTO_BYTES,
        psk,
        sizeof(psk));

    uint8_t confirmB_check[32];

    hmac_sha3_256(
        confirmB_check,
        Ktemp_A,
        32,
        session_ctx,
        32);

    if (memcmp(confirmB, confirmB_check, 32) != 0)
    {
        memset(skA,0,sizeof(skA));
        memset(ssA,0,sizeof(ssA));
        memset(ssB,0,sizeof(ssB));
        memset(Ktemp_A,0,sizeof(Ktemp_A));
        memset(Ktemp_B,0,sizeof(Ktemp_B));
        return 0;
    }

    hmac_sha3_256(
        confirmA,
        Ktemp_A,
        32,
        confirmB,
        32);

    memset(skA,0,sizeof(skA));

    end = DWT->CYCCNT;
    cycles += (end - start);

    /************************************************************
     * M4 : Bob Final ACK
     ************************************************************/
    start = DWT->CYCCNT;

    uint8_t confirmA_check[32];

    hmac_sha3_256(
        confirmA_check,
        Ktemp_B,
        32,
        confirmB,
        32);

    if (memcmp(confirmA, confirmA_check, 32) != 0)
    {
        memset(ssA,0,sizeof(ssA));
        memset(ssB,0,sizeof(ssB));
        memset(Ktemp_A,0,sizeof(Ktemp_A));
        memset(Ktemp_B,0,sizeof(Ktemp_B));
        return 0;
    }

    hmac_sha3_256(
        session_ready,
        Ktemp_B,
        32,
        confirmA,
        32);

    end = DWT->CYCCNT;
    cycles += (end - start);

    /************************************************************
     * Final Session Key Derivation
     ************************************************************/
    start = DWT->CYCCNT;

    offset = 0;

    memcpy(transcript + offset, tokenA, 32);
    offset += 32;

    memcpy(transcript + offset, confirmB, 32);
    offset += 32;

    memcpy(transcript + offset, confirmA, 32);
    offset += 32;

    sha3_256(
        transcript,
        transcript,
        offset);

    hkdf_sha3(
        Ksession_A,
        Ktemp_A,
        32,
        transcript,
        32);

    hkdf_sha3(
        Ksession_B,
        Ktemp_B,
        32,
        transcript,
        32);

    end = DWT->CYCCNT;
    cycles += (end - start);

    /************************************************************
     * Secure Cleanup
     ************************************************************/
    memset(skA,0,sizeof(skA));

    memset(ssA,0,sizeof(ssA));
    memset(ssB,0,sizeof(ssB));

    memset(Ktemp_A,0,sizeof(Ktemp_A));
    memset(Ktemp_B,0,sizeof(Ktemp_B));

    memset(session_ctx,0,sizeof(session_ctx));

    memset(confirmA,0,sizeof(confirmA));
    memset(confirmB,0,sizeof(confirmB));

    memset(session_ready,0,sizeof(session_ready));

    memset(Ksession_A,0,sizeof(Ksession_A));
    memset(Ksession_B,0,sizeof(Ksession_B));

    memset(transcript,0,sizeof(transcript));

    (void)ctrA;
    (void)ctrB;

    return cycles;
}

/*
// =========================================================================
// HÀM ĐO TỔNG HỢP TOÀN BỘ 5 GIAO THỨC VÀ PHÂN TÍCH BỘ NHỚ
// =========================================================================
void benchmark_All_Protocols(void) {
    // Tần số hệ thống cấu hình qua PLL là 168 MHz (HCLK = 168000000 Hz)
    const float sys_freq_mhz = 168.0f;

    printf("\n========================================================================\n");
    printf("    STARTING ALL PROTOCOLS BENCHMARK (CYCLES & MEMORY ANALYSIS)       \n");
    printf("========================================================================\n\n");

    // Khởi động/Reset lại bộ đếm xung phần cứng DWT
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;

    // 1. Chạy Classical TLS
    printf("[1/5] Running Classical TLS (ECC secp256r1)... ");
    benchmark_Classical_TLS();
    printf("DONE.\n");

    // 2. Chạy Hybrid TLS
    printf("[2/5] Running Hybrid TLS (ECC + Kyber)... ");
    benchmark_Hybrid_TLS();
    printf("DONE.\n");

    // 3. Chạy KEMTLS
    printf("[3/5] Running KEMTLS (Kyber Only)... ");
    benchmark_KEMTLS();
    printf("DONE.\n");

    // 4. Chạy Topo-Kyber (Hàm này tự reset DWT bên trong nên ta chạy kế cuối)
    printf("[4/5] Running Topo-Kyber (Proposed Physical Auth)... \n");
    benchmark_Topo_Kyber();
    printf("DONE.\n");

    // 5. Chạy PQ-TLS
    printf("[5/5] Running PQ-TLS (Kyber + ML-DSA-44)... ");
    benchmark_PQ_TLS();
    printf("DONE.\n");

    // --- XUẤT BẢNG SỐ LIỆU ĐỂ CHO VÀO BÀI BÁO (BẢNG KẾT QUẢ THỰC NGHIỆM) ---
    printf("\n\n");
    printf("==================================================================================================\n");
    printf("| %-27s | %-15s | %-12s | %-30s |\n", "Protocol Configuration", "Cycles (CPU)", "Time (ms)", "RAM Footprint (Static/Stack)");
    printf("==================================================================================================\n");

    // 1. Classical TLS
    printf("| %-27s | %15lu | %12.3f | %-30s |\n",
           "1. Classical TLS (ECC)",
           result_classical,
           (float)result_classical / (sys_freq_mhz * 1000.0f),
           "448 Bytes (.bss)");

    // 2. Hybrid TLS
    // RAM = ECC (448) + Kyber_Keys (pk=800, sk=1632, ct=768, 2xss=64) = 3712 Bytes
    printf("| %-27s | %15lu | %12.3f | %-30s |\n",
           "2. Hybrid TLS (ECC+Kyber)",
           result_hybrid,
           (float)result_hybrid / (sys_freq_mhz * 1000.0f),
           "3,712 Bytes (~3.63 KB) (.bss)");

    // 3. KEMTLS
    // RAM = 2x Kyber_Keys (Ephemeral + Static Auth) = 3264 * 2 = 6528 Bytes
    printf("| %-27s | %15lu | %12.3f | %-30s |\n",
           "3. KEMTLS (NIST-KEM)",
           result_kemtls,
           (float)result_kemtls / (sys_freq_mhz * 1000.0f),
           "6,528 Bytes (~6.38 KB) (.bss)");

    // 4. Topo-Kyber (Đề xuất)
    // RAM Static = 2x Kyber_Keys (wrap + main) = 6528 Bytes.
    // Thêm các biến xử lý TDA + Vector vật lý trên Stack ~ 432 Bytes
    printf("| %-27s | %15lu | %12.3f | %-30s |\n",
           "4. Topo-Kyber (Proposed)",
           result_topokyber,
           (float)result_topokyber / (sys_freq_mhz * 1000.0f),
           "6,528B (.bss) + 432B (Stack)");

    // 5. PQ-TLS
    // RAM = Kyber (3264) + ML-DSA-44 (pk=1312, sk=2560, sig=2452) = 9588 Bytes
    printf("| %-27s | %15lu | %12.3f | %-30s |\n",
           "5. PQ-TLS (Kyber+ML-DSA)",
           result_pqtls,
           (float)result_pqtls / (sys_freq_mhz * 1000.0f),
           "9,588 Bytes (~9.36 KB) (.bss)");

    printf("==================================================================================================\n");
    printf(" Note: CPU Execution Time calculated at clock rate of %.1f MHz (STM32F407 High-Performance).\n", sys_freq_mhz);
    printf("==================================================================================================\n\n");
}
*/
void benchmark_All_Protocols(void) {
    // const float sys_freq_mhz = 168.0f;

    // 1. Thực thi các giao thức để lấy chu kỳ máy
    benchmark_Classical_TLS();
    benchmark_Hybrid_TLS();
    benchmark_KEMTLS();
    benchmark_Topo_Kyber(); // Hàm này chạy xong sẽ tự cập nhật result_topokyber
    benchmark_PQ_TLS();

    // 2. GÁN GIÁ TRỊ BỘ NHỚ VÀO BIẾN TOÀN CỤC ĐỂ ĐỌC QUA DEBUGGER
    // (Dựa trên kích thước cấu trúc dữ liệu chính xác của các thuật toán)
    ram_classical = 448;                 // 448 Bytes cho các khóa ECC
    ram_hybrid    = 3712;                // ECC (448B) + Kyber-512 Keys (3264B)
    ram_kemtls    = 6528;                // 2 bộ Kyber-512 Keys (Ephemeral + Auth)
    ram_topokyber = 6960;                // 2 bộ Kyber Keys (6528B) + Ma trận TDA trên Stack (432B)
    ram_pqtls     = 9588;                // Kyber-512 Keys (3264B) + ML-DSA-44 Keys/Sig (6324B)

    // Dưới đây là phần in ra Terminal (nếu có mạch chuyển UART)
    printf("\n=== BENCHMARK COPIED TO GLOBAL VARIABLES FOR LIVE EXPRESSIONS ===\n");
}

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_I2C1_Init();
  MX_I2S3_Init();
  MX_RNG_Init();
  MX_SPI1_Init();
  MX_USB_HOST_Init();
  /* USER CODE BEGIN 2 */

  // NHẤN MẠNH 3: BẬT TĂNG TỐC PHẦN CỨNG (ART Accelerator)
  // Nếu không có 3 dòng này, số cycles sẽ bị đội lên rất cao do độ trễ bộ nhớ Flash
  __HAL_FLASH_INSTRUCTION_CACHE_ENABLE();
  __HAL_FLASH_DATA_CACHE_ENABLE();
  __HAL_FLASH_PREFETCH_BUFFER_ENABLE();

  // GỌI LẦN LƯỢT TỪNG HÀM
  // 1. Khởi động bộ đếm phần cứng DWT (Bắt buộc phải bật trước thì get_cycles mới chạy)
  CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
  DWT->CYCCNT = 0;
  DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;

  // 2. GỌI HÀM ĐO LƯỜNG (Mỗi lần nạp chip chỉ mở comment 1 dòng)
  // benchmark_Classical_TLS();

  // benchmark_Hybrid_TLS();
  // benchmark_KEMTLS();
  // benchmark_PQ_TLS();
  // benchmark_Topo_Kyber();
  	 benchmark_NTN_PQ_AKE_v40();

  // Gọi duy nhất hàm benchmark tổng hợp này để lấy kết quả 5 trong 1
  //  benchmark_All_Protocols();
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
    /* USER CODE END WHILE */
    MX_USB_HOST_Process();

    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLM = 8;
  RCC_OscInitStruct.PLL.PLLN = 336;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 7;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV4;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV2;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_5) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief I2C1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_I2C1_Init(void)
{

  /* USER CODE BEGIN I2C1_Init 0 */

  /* USER CODE END I2C1_Init 0 */

  /* USER CODE BEGIN I2C1_Init 1 */

  /* USER CODE END I2C1_Init 1 */
  hi2c1.Instance = I2C1;
  hi2c1.Init.ClockSpeed = 100000;
  hi2c1.Init.DutyCycle = I2C_DUTYCYCLE_2;
  hi2c1.Init.OwnAddress1 = 0;
  hi2c1.Init.AddressingMode = I2C_ADDRESSINGMODE_7BIT;
  hi2c1.Init.DualAddressMode = I2C_DUALADDRESS_DISABLE;
  hi2c1.Init.OwnAddress2 = 0;
  hi2c1.Init.GeneralCallMode = I2C_GENERALCALL_DISABLE;
  hi2c1.Init.NoStretchMode = I2C_NOSTRETCH_DISABLE;
  if (HAL_I2C_Init(&hi2c1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN I2C1_Init 2 */

  /* USER CODE END I2C1_Init 2 */

}

/**
  * @brief I2S3 Initialization Function
  * @param None
  * @retval None
  */
static void MX_I2S3_Init(void)
{

  /* USER CODE BEGIN I2S3_Init 0 */

  /* USER CODE END I2S3_Init 0 */

  /* USER CODE BEGIN I2S3_Init 1 */

  /* USER CODE END I2S3_Init 1 */
  hi2s3.Instance = SPI3;
  hi2s3.Init.Mode = I2S_MODE_MASTER_TX;
  hi2s3.Init.Standard = I2S_STANDARD_PHILIPS;
  hi2s3.Init.DataFormat = I2S_DATAFORMAT_16B;
  hi2s3.Init.MCLKOutput = I2S_MCLKOUTPUT_ENABLE;
  hi2s3.Init.AudioFreq = I2S_AUDIOFREQ_96K;
  hi2s3.Init.CPOL = I2S_CPOL_LOW;
  hi2s3.Init.ClockSource = I2S_CLOCK_PLL;
  hi2s3.Init.FullDuplexMode = I2S_FULLDUPLEXMODE_DISABLE;
  if (HAL_I2S_Init(&hi2s3) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN I2S3_Init 2 */

  /* USER CODE END I2S3_Init 2 */

}

/**
  * @brief RNG Initialization Function
  * @param None
  * @retval None
  */
static void MX_RNG_Init(void)
{

  /* USER CODE BEGIN RNG_Init 0 */

  /* USER CODE END RNG_Init 0 */

  /* USER CODE BEGIN RNG_Init 1 */

  /* USER CODE END RNG_Init 1 */
  hrng.Instance = RNG;
  if (HAL_RNG_Init(&hrng) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN RNG_Init 2 */

  /* USER CODE END RNG_Init 2 */

}

/**
  * @brief SPI1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_SPI1_Init(void)
{

  /* USER CODE BEGIN SPI1_Init 0 */

  /* USER CODE END SPI1_Init 0 */

  /* USER CODE BEGIN SPI1_Init 1 */

  /* USER CODE END SPI1_Init 1 */
  /* SPI1 parameter configuration*/
  hspi1.Instance = SPI1;
  hspi1.Init.Mode = SPI_MODE_MASTER;
  hspi1.Init.Direction = SPI_DIRECTION_2LINES;
  hspi1.Init.DataSize = SPI_DATASIZE_8BIT;
  hspi1.Init.CLKPolarity = SPI_POLARITY_LOW;
  hspi1.Init.CLKPhase = SPI_PHASE_1EDGE;
  hspi1.Init.NSS = SPI_NSS_SOFT;
  hspi1.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_2;
  hspi1.Init.FirstBit = SPI_FIRSTBIT_MSB;
  hspi1.Init.TIMode = SPI_TIMODE_DISABLE;
  hspi1.Init.CRCCalculation = SPI_CRCCALCULATION_DISABLE;
  hspi1.Init.CRCPolynomial = 10;
  if (HAL_SPI_Init(&hspi1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN SPI1_Init 2 */

  /* USER CODE END SPI1_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};
  /* USER CODE BEGIN MX_GPIO_Init_1 */

  /* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOE_CLK_ENABLE();
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOH_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();
  __HAL_RCC_GPIOD_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(CS_I2C_SPI_GPIO_Port, CS_I2C_SPI_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(OTG_FS_PowerSwitchOn_GPIO_Port, OTG_FS_PowerSwitchOn_Pin, GPIO_PIN_SET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOD, LD4_Pin|LD3_Pin|LD5_Pin|LD6_Pin
                          |Audio_RST_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin : CS_I2C_SPI_Pin */
  GPIO_InitStruct.Pin = CS_I2C_SPI_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(CS_I2C_SPI_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : OTG_FS_PowerSwitchOn_Pin */
  GPIO_InitStruct.Pin = OTG_FS_PowerSwitchOn_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(OTG_FS_PowerSwitchOn_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : PDM_OUT_Pin */
  GPIO_InitStruct.Pin = PDM_OUT_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  GPIO_InitStruct.Alternate = GPIO_AF5_SPI2;
  HAL_GPIO_Init(PDM_OUT_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : B1_Pin */
  GPIO_InitStruct.Pin = B1_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_EVT_RISING;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(B1_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : BOOT1_Pin */
  GPIO_InitStruct.Pin = BOOT1_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(BOOT1_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : CLK_IN_Pin */
  GPIO_InitStruct.Pin = CLK_IN_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  GPIO_InitStruct.Alternate = GPIO_AF5_SPI2;
  HAL_GPIO_Init(CLK_IN_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pins : LD4_Pin LD3_Pin LD5_Pin LD6_Pin
                           Audio_RST_Pin */
  GPIO_InitStruct.Pin = LD4_Pin|LD3_Pin|LD5_Pin|LD6_Pin
                          |Audio_RST_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOD, &GPIO_InitStruct);

  /*Configure GPIO pin : OTG_FS_OverCurrent_Pin */
  GPIO_InitStruct.Pin = OTG_FS_OverCurrent_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(OTG_FS_OverCurrent_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pin : MEMS_INT2_Pin */
  GPIO_InitStruct.Pin = MEMS_INT2_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_EVT_RISING;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(MEMS_INT2_GPIO_Port, &GPIO_InitStruct);

  /* USER CODE BEGIN MX_GPIO_Init_2 */

  /* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  * where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
