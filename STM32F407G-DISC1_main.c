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
    // Khai báo biến (sử dụng static để tiết kiệm Stack)
    static uint8_t public_key_client[64], private_key_client[32];
    static uint8_t public_key_server[64], private_key_server[32];
    static uint8_t shared_secret_client[32], shared_secret_server[32];
    static uint8_t hash[32] = {0x12, 0x34}; // Dữ liệu giả định để băm
    static uint8_t signature[64];

    uECC_set_rng(&fake_rng); // Đăng ký hàm RNG cho thư viện micro-ecc
    const struct uECC_Curve_t * curve = uECC_secp256r1();

    uint32_t start, end;
    volatile uint32_t total_cycles_tls13;

    start = get_cycles();

    // --- PHA 1: THỎA THUẬN KHÓA (ECDHE Key Exchange) ---
    // Cả 2 bên tự sinh KeyPair
    uECC_make_key(public_key_client, private_key_client, curve);
    uECC_make_key(public_key_server, private_key_server, curve);
    // Tính toán Shared Secret
    uECC_shared_secret(public_key_server, private_key_client, shared_secret_client, curve);
    uECC_shared_secret(public_key_client, private_key_server, shared_secret_server, curve);

    // --- PHA 2: XÁC THỰC (ECDSA Authentication) ---
    // Server ký vào gói tin
    uECC_sign(private_key_server, hash, sizeof(hash), signature, curve);
    // Client xác minh chữ ký của Server
    uECC_verify(public_key_server, hash, sizeof(hash), signature, curve);

    end = get_cycles();
    result_classical = end - start;
    // total_cycles_tls13 = end - start;
    // ^ Đặt breakpoint tại đây để xem biến total_cycles_tls13
}

// =========================================================================
// 2. ĐO LƯỜNG HYBRID TLS 1.3 (ECC + Kyber)
// =========================================================================
void benchmark_Hybrid_TLS(void) {
    // Biến cho ECC (Cổ điển)
    static uint8_t public_key_client[64], private_key_client[32];
    static uint8_t public_key_server[64], private_key_server[32];
    static uint8_t shared_secret_ecc[32];
    static uint8_t hash[32] = {0x12, 0x34};
    static uint8_t signature[64];

    // Biến cho Kyber (Lượng tử) - Kích thước tùy thuộc vào bạn dùng Kyber512 hay 768
    static uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    static uint8_t sk[CRYPTO_SECRETKEYBYTES];
    static uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    static uint8_t ss_pqc[CRYPTO_BYTES];

    uECC_set_rng(&fake_rng);
    const struct uECC_Curve_t * curve = uECC_secp256r1();

    uint32_t start, end;
    volatile uint32_t total_cycles_hybrid;

    start = get_cycles();

    // --- PHA 1: Thỏa thuận & Xác thực bằng Cổ điển (ECC) ---
    uECC_make_key(public_key_client, private_key_client, curve);
    uECC_make_key(public_key_server, private_key_server, curve);
    uECC_shared_secret(public_key_server, private_key_client, shared_secret_ecc, curve);
    uECC_sign(private_key_server, hash, sizeof(hash), signature, curve);
    uECC_verify(public_key_server, hash, sizeof(hash), signature, curve);

    // --- PHA 2: Thêm lớp Thỏa thuận khóa Lượng tử (Kyber) ---
    crypto_kem_keypair(pk, sk);
    crypto_kem_enc(ct, ss_pqc, pk);
    crypto_kem_dec(ss_pqc, ct, sk);

    end = get_cycles();
    result_hybrid = end - start;
    // total_cycles_hybrid = end - start;
    // ^ Đặt breakpoint tại đây để xem kết quả
}

// =========================================================================
// 3. ĐO LƯỜNG KEMTLS (Dùng 100% Kyber, Bỏ chữ ký số)
// =========================================================================
void benchmark_KEMTLS(void) {
    // Biến cho Ephemeral KEM (Thỏa thuận khóa ngắn hạn)
    static uint8_t ephem_pk[CRYPTO_PUBLICKEYBYTES], ephem_sk[CRYPTO_SECRETKEYBYTES];
    static uint8_t ephem_ct[CRYPTO_CIPHERTEXTBYTES], ephem_ss[CRYPTO_BYTES];

    // Biến cho Long-term KEM (Xác thực danh tính)
    static uint8_t auth_pk[CRYPTO_PUBLICKEYBYTES], auth_sk[CRYPTO_SECRETKEYBYTES];
    static uint8_t auth_ct[CRYPTO_CIPHERTEXTBYTES], auth_ss[CRYPTO_BYTES];

    uint32_t start, end;
    volatile uint32_t total_cycles_kemtls;

    // Reset bộ đếm về 0 trước khi đo cho sạch
    DWT->CYCCNT = 0;
    start = get_cycles();

    // --- PHA 1: Ephemeral KEM Exchange (Thay thế ECDHE) ---
    crypto_kem_keypair(ephem_pk, ephem_sk);
    crypto_kem_enc(ephem_ct, ephem_ss, ephem_pk);
    crypto_kem_dec(ephem_ss, ephem_ct, ephem_sk);

    // --- PHA 2: Long-term KEM Auth (Thay thế ECDSA) ---
    crypto_kem_keypair(auth_pk, auth_sk);
    crypto_kem_enc(auth_ct, auth_ss, auth_pk);
    crypto_kem_dec(auth_ss, auth_ct, auth_sk);

    end = get_cycles();
    // NHẤN MẠNH 2: Lưu vào biến toàn cục
    result_kemtls = end - start;
    // total_cycles_kemtls = end - start;
    // ^ Đặt breakpoint tại đây để xem kết quả
}

/ =========================================================================
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
    volatile uint32_t cyc_tda_A, cyc_tda_B, cyc_ake;

    // Khai báo biến
    uint8_t id_A[32] = {0x01}, id_B[32] = {0x02}, r_A[32], r_B[32];
    uint8_t pk_A[CRYPTO_PUBLICKEYBYTES], sk_A[CRYPTO_SECRETKEYBYTES], ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t s_A[32], s_B[32], k_seed_A[32], k_seed_B[32], k_session_A[32], k_session_B[32];
    uint8_t sid[32], cb[32], t_A[32], t_B[32], h_hash[32];
    float feat_A[FEATURE_DIM], feat_B[FEATURE_DIM], helper[FEATURE_DIM], r_q_vector[FEATURE_DIM];
    int32_t K_int_A[FEATURE_DIM], K_int_B[FEATURE_DIM];

    // Bật DWT
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0; DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;

    // ====================================================================
    // PHASE 1 & 2: ALICE (TDA + Secure Sketch Generation)
    // ====================================================================
    t0 = DWT->CYCCNT;
    run_micro_tda(test_rssi_alice, feat_A);

    for(int i=0; i<FEATURE_DIM; i++) {
        r_q_vector[i] = ((float)(rand() % 100) / 100.0f) - 0.5f; // Alice sinh r_q
        K_int_A[i] = (int32_t)floorf((feat_A[i] + r_q_vector[i]) / Q_STEP); // K = floor((v+r)/Q)
        helper[i] = (feat_A[i] + r_q_vector[i]) - ((float)K_int_A[i] * Q_STEP); // h = (v+r) mod Q
    }
    sha3_256(s_A, (uint8_t*)K_int_A, FEATURE_DIM * sizeof(int32_t));
    sha3_256(h_hash, (uint8_t*)helper, FEATURE_DIM * sizeof(float));

    randombytes(r_A, 32);
    crypto_kem_keypair(pk_A, sk_A); // ML-KEM KeyGen
    t1 = DWT->CYCCNT;
    cyc_tda_A = t1 - t0;

    // ====================================================================
    // PHASE 1 & 2: BOB (TDA + Secure Sketch Recovery)
    // ====================================================================
    t0 = DWT->CYCCNT;
    run_micro_tda(test_rssi_bob, feat_B);

    // Bob nhận r_q_vector và helper từ Alice để khôi phục s_B
    for(int i=0; i<FEATURE_DIM; i++) {
        K_int_B[i] = (int32_t)roundf((feat_B[i] + r_q_vector[i] - helper[i]) / Q_STEP);
    }
    sha3_256(s_B, (uint8_t*)K_int_B, FEATURE_DIM * sizeof(int32_t));

    // AKE Bob
    randombytes(r_B, 32);
    crypto_kem_enc(ct, k_seed_B, pk_A); // ML-KEM Encaps

    // Session ID & KDF (Bob)
    uint8_t sid_buf[128];
    memcpy(sid_buf, id_A, 32); memcpy(sid_buf+32, id_B, 32);
    memcpy(sid_buf+64, r_A, 32); memcpy(sid_buf+96, r_B, 32);
    sha3_256(sid, sid_buf, 128);

    uint8_t kdf_buf_B[160];
    memcpy(kdf_buf_B, k_seed_B, 32); memcpy(kdf_buf_B+32, s_B, 32); // s_B là seed vật lý
    memcpy(kdf_buf_B+64, sid, 32); memcpy(kdf_buf_B+96, h_hash, 32);
    sha3_256(k_session_B, kdf_buf_B, 160);

    t1 = DWT->CYCCNT;
    cyc_tda_B = t1 - t0;

    // ====================================================================
    // PHASE 3: ALICE (Decaps & Final KDF)
    // ====================================================================
    t0 = DWT->CYCCNT;
    crypto_kem_dec(k_seed_A, ct, sk_A); // ML-KEM Decaps

    uint8_t kdf_buf_A[160];
    memcpy(kdf_buf_A, k_seed_A, 32); memcpy(kdf_buf_A+32, s_A, 32); // s_A là seed vật lý
    memcpy(kdf_buf_A+64, sid, 32); memcpy(kdf_buf_A+96, h_hash, 32);
    sha3_256(k_session_A, kdf_buf_A, 160);

    t1 = DWT->CYCCNT;
    cyc_ake = t1 - t0;

    // In kết quả
    printf("Total Cycles: %lu\n", cyc_tda_A + cyc_tda_B + cyc_ake);
}
// =========================================================================
// 5. ĐO LƯỜNG POST-QUANTUM TLS (Kyber + ML-DSA-44)
// =========================================================================
void benchmark_PQ_TLS(void) {
    // ---- 1. Biến cho Kyber ----
    static uint8_t pk_kyber[CRYPTO_PUBLICKEYBYTES];
    static uint8_t sk_kyber[CRYPTO_SECRETKEYBYTES];
    static uint8_t ct_kyber[CRYPTO_CIPHERTEXTBYTES];
    static uint8_t ss_server[CRYPTO_BYTES], ss_client[CRYPTO_BYTES];

    // ---- 2. Biến cho ML-DSA-44 ----
    // Mình dùng số cứng để không bị xung đột với biến của Kyber
    static uint8_t pk_mldsa[1312];
    static uint8_t sk_mldsa[2560];
    static uint8_t signature[2420 + 32];
    static size_t sig_len;

    static uint8_t message[32] = {0x11, 0x22, 0x33, 0x44};
    static size_t msg_len = 32;
    static uint8_t message_out[32];
    static size_t msg_len_out;

    uint32_t start, end;

    DWT->CYCCNT = 0;
    start = get_cycles();

    // Pha 1: Trao đổi khóa (Kyber)
    crypto_kem_keypair(pk_kyber, sk_kyber);
    crypto_kem_enc(ct_kyber, ss_server, pk_kyber);
    crypto_kem_dec(ss_client, ct_kyber, sk_kyber);

    // Pha 2: Chữ ký số (ML-DSA-44)
    // Giờ file main.c đã có mldsa_api.h, nó sẽ tự hiểu các lệnh này!
    crypto_sign_keypair(pk_mldsa, sk_mldsa);
    crypto_sign(signature, &sig_len, message, msg_len, sk_mldsa);
    crypto_sign_open(message_out, &msg_len_out, signature, sig_len, pk_mldsa);

    end = get_cycles();

    // Ghi nhận tổng thời gian vào biến toàn cục
    result_pqtls = end - start;
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
     benchmark_Topo_Kyber();
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
  *         where the assert_param error has occurred.
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
