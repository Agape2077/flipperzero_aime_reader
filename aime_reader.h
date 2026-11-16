#pragma once

#include <furi.h>
#include <furi_hal.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 高波特率模式 (837-15396 / 115200) 参数
#define AIME_HIGH_BAUDRATE   115200
#define AIME_HIGH_FW_VERSION "\x94"
#define AIME_HIGH_FW_LEN     1
#define AIME_HIGH_HW_VERSION "837-15396"
#define AIME_HIGH_HW_LEN     9
#define AIME_HIGH_LED_INFO   "000-00000\xFF\x11\x40"
#define AIME_HIGH_LED_LEN    12

// 低波特率模式 (TN32MSEC003S / 38400) 参数
#define AIME_LOW_BAUDRATE   38400
#define AIME_LOW_FW_VERSION "TN32MSEC003S F/W Ver1.2"
#define AIME_LOW_FW_LEN     23
#define AIME_LOW_HW_VERSION "TN32MSEC003S H/W Ver3.0"
#define AIME_LOW_HW_LEN     23
#define AIME_LOW_LED_INFO   "15084\xFF\x10\x00\x12"
#define AIME_LOW_LED_LEN    9

// SEGA SG 串口协议命令码
typedef enum {
    CMD_GET_FW_VERSION = 0x30,
    CMD_GET_HW_VERSION = 0x32,
    // Card read
    CMD_START_POLLING = 0x40,
    CMD_STOP_POLLING = 0x41,
    CMD_CARD_DETECT = 0x42,
    CMD_CARD_SELECT = 0x43,
    CMD_CARD_HALT = 0x44,
    // MIFARE
    CMD_MIFARE_KEY_SET_A = 0x50,
    CMD_MIFARE_AUTHORIZE_A = 0x51,
    CMD_MIFARE_READ = 0x52,
    CMD_MIFARE_KEY_SET_B = 0x54,
    CMD_MIFARE_AUTHORIZE_B = 0x55,
    // Boot, update
    CMD_TO_UPDATER_MODE = 0x60,
    CMD_SEND_HEX_DATA = 0x61,
    CMD_TO_NORMAL_MODE = 0x62,
    CMD_SEND_BINDATA_INIT = 0x63,
    CMD_SEND_BINDATA_EXEC = 0x64,
    // FeliCa
    CMD_FELICA_THROUGH = 0x71,
    // LED board
    CMD_EXT_BOARD_LED = 0x80,
    CMD_EXT_BOARD_LED_RGB = 0x81,
    CMD_EXT_BOARD_LED_RGB_UNKNOWN = 0x82,
    CMD_EXT_BOARD_INFO = 0xf0,
    CMD_EXT_FIRM_SUM = 0xf2,
    CMD_EXT_SEND_HEX_DATA = 0xf3,
    CMD_EXT_TO_BOOT_MODE = 0xf4,
    CMD_EXT_TO_NORMAL_MODE = 0xf5,
} AimeCmd;

// 响应状态码
typedef enum {
    STATUS_OK = 0x00,
    STATUS_CARD_ERROR = 0x01,
    STATUS_NOT_ACCEPT = 0x02,
    STATUS_INVALID_COMMAND = 0x03,
    STATUS_INVALID_DATA = 0x04,
    STATUS_SUM_ERROR = 0x05,
    STATUS_INTERNAL_ERROR = 0x06,
    STATUS_INVALID_FIRM_DATA = 0x07,
    STATUS_FIRM_UPDATE_SUCCESS = 0x08,
    STATUS_COMP_DUMMY_2ND = 0x10,
    STATUS_COMP_DUMMY_3RD = 0x20,
} AimeStatus;

#pragma pack(push, 1)
typedef union {
    uint8_t bytes[128];
    struct {
        uint8_t frame_len;
        uint8_t addr;
        uint8_t seq_no;
        uint8_t cmd;
        uint8_t payload_len;
        union {
            uint8_t key[6];
            uint8_t color_payload[3];
            struct {
                uint8_t uid[4];
                uint8_t block_no;
            };
            uint8_t raw_payload[120];
        };
    };
} AimePacketRequest;

typedef union {
    uint8_t bytes[128];
    struct {
        uint8_t frame_len;
        uint8_t addr;
        uint8_t seq_no;
        uint8_t cmd;
        uint8_t status;
        uint8_t payload_len;
        union {
            uint8_t version[32];
            uint8_t block[16];
            struct {
                uint8_t count;
                uint8_t type;
                uint8_t id_len;
                union {
                    uint8_t mifare_uid[7];
                    struct {
                        uint8_t IDm[8];
                        uint8_t PMm[8];
                    };
                };
            };
        };
    };
} AimePacketResponse;
#pragma pack(pop)

typedef struct {
    bool high_baudrate;
    // true: AIC Lite/Lite-S -> virtual MIFARE; false: native FeliCa IDm + PMm
    bool aic_as_mifare;
    bool usb_connected;
    bool is_polling;
    uint8_t led_r;
    uint8_t led_g;
    uint8_t led_b;
    uint32_t rx_packets;
    char card_type[24];
    char card_id[32];
    char access_code[32];
} AimeReaderState;

typedef struct AimeReader AimeReader;

AimeReader* aime_reader_alloc(void);
void aime_reader_free(AimeReader* instance);
void aime_reader_get_state(AimeReader* instance, AimeReaderState* out_state);
void aime_reader_set_baudrate(AimeReader* instance, bool high_baudrate);
// Selects only the output mode for FeliCa AIC cards; physical MIFARE polling is unchanged.
void aime_reader_set_aic_as_mifare(AimeReader* instance, bool enable);

#ifdef __cplusplus
}
#endif
