#include "aime_reader.h"
#include <cli/cli_vcp.h>
#include <furi_hal_usb.h>
#include <furi_hal_usb_cdc.h>
#include <furi_hal_nfc.h>
#include <nfc/nfc.h>
#include <nfc/nfc_poller.h>
#include <nfc/protocols/felica/felica.h>
#include <nfc/protocols/felica/felica_poller.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a_poller.h>
#include <nfc/protocols/mf_classic/mf_classic.h>
#include <nfc/protocols/mf_classic/mf_classic_poller.h>
#include <notification/notification_messages.h>
#include <stdio.h>
#include <string.h>

#define CDC_IF_NUM 0

typedef enum {
    CardPresentNone = 0,
    CardPresentMifare = 0x10,
    CardPresentFelica = 0x20,
} CardPresentType;

struct AimeReader {
    NotificationApp* notifications;
    FuriStreamBuffer* rx_stream;
    FuriThread* worker_thread;
    FuriThread* nfc_thread;
    FuriMutex* state_mutex;
    FuriSemaphore* nfc_done_sem;
    FuriSemaphore* mifare_read_sem;
    CdcCallbacks cdc_callbacks;
    volatile bool running;

    // 当前 FeliCa Poller，供回调中 nfc_poller_get_data 使用
    NfcPoller* current_poller;

    // 837-15396 串口协议解析状态机
    AimePacketRequest req;
    AimePacketResponse res;
    uint8_t rx_len;
    uint8_t rx_checksum;
    bool rx_escape;

    // 卡片状态缓存
    volatile CardPresentType card_present;
    uint8_t cached_uid[7];
    uint8_t cached_uid_len;
    uint8_t cached_idm[8];
    uint8_t cached_pmm[8];

    // MIFARE 读块同步
    volatile bool mifare_read_req;
    volatile uint8_t mifare_read_block;
    uint8_t mifare_read_out[16];
    volatile bool mifare_read_ok;

    // MIFARE 密钥缓存
    uint8_t key_a[6];
    uint8_t key_b[6];
    bool auth_a_ready;
    bool auth_b_ready;

    // UI 状态
    AimeReaderState state;
    uint8_t last_r;
    uint8_t last_g;
    uint8_t last_b;
};

// --- 1. RGB LED 控制 ---
static void aime_set_led(AimeReader* instance, uint8_t r, uint8_t g, uint8_t b, bool force) {
    if(!instance) return;
    if(!force && r == instance->last_r && g == instance->last_g && b == instance->last_b) {
        return;
    }
    instance->last_r = r;
    instance->last_g = g;
    instance->last_b = b;

    if(instance->state_mutex) {
        furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
        instance->state.led_r = r;
        instance->state.led_g = g;
        instance->state.led_b = b;
        furi_mutex_release(instance->state_mutex);
    }

    if(!instance->notifications) return;

    static NotificationMessage msg_r = {.type = NotificationMessageTypeLedRed};
    static NotificationMessage msg_g = {.type = NotificationMessageTypeLedGreen};
    static NotificationMessage msg_b = {.type = NotificationMessageTypeLedBlue};
    static const NotificationSequence seq = {
        &msg_r,
        &msg_g,
        &msg_b,
        &message_do_not_reset,
        NULL,
    };

    msg_r.data.led.value = r;
    msg_g.data.led.value = g;
    msg_b.data.led.value = b;

    notification_message(instance->notifications, &seq);
}

// --- 2. 串口封包发送 ---
static void aime_packet_write(AimeReader* instance) {
    if(instance->res.cmd == 0) return;

    uint8_t tx_buf[260];
    size_t tx_idx = 0;
    uint8_t checksum = 0;
    uint8_t len = 0;

    tx_buf[tx_idx++] = 0xE0;

    while(len <= instance->res.frame_len) {
        uint8_t w;
        if(len == instance->res.frame_len) {
            w = checksum;
        } else {
            w = instance->res.bytes[len];
            checksum += w;
        }

        if(w == 0xE0 || w == 0xD0) {
            tx_buf[tx_idx++] = 0xD0;
            tx_buf[tx_idx++] = (uint8_t)(w - 1);
        } else {
            tx_buf[tx_idx++] = w;
        }
        len++;
    }

    furi_hal_cdc_send(CDC_IF_NUM, tx_buf, tx_idx);
    instance->res.cmd = 0;
}

static void aime_res_init(AimeReader* instance, uint8_t payload_len) {
    instance->res.frame_len = 6 + payload_len;
    instance->res.addr = instance->req.addr;
    instance->res.seq_no = instance->req.seq_no;
    instance->res.cmd = instance->req.cmd;
    instance->res.status = STATUS_OK;
    instance->res.payload_len = payload_len;
}

// --- 3. 后台 NFC 线程 ---
typedef struct {
    AimeReader* app;
    bool got_card;
    uint8_t idm[8];
    uint8_t pmm[8];
} PollSyncCtx;

static NfcCommand iso3a_poll_cb(NfcGenericEvent event, void* context) {
    PollSyncCtx* ctx = context;
    if(!ctx || !ctx->app->running) {
        if(ctx) furi_semaphore_release(ctx->app->nfc_done_sem);
        return NfcCommandStop;
    }
    if(event.protocol == NfcProtocolIso14443_3a && event.event_data) {
        const Iso14443_3aPollerEvent* ev = event.event_data;
        if(ev->type == Iso14443_3aPollerEventTypeReady) {
            ctx->got_card = true;
            furi_semaphore_release(ctx->app->nfc_done_sem);
            return NfcCommandStop;
        } else if(ev->type == Iso14443_3aPollerEventTypeError) {
            furi_semaphore_release(ctx->app->nfc_done_sem);
            return NfcCommandStop;
        }
    }
    return NfcCommandContinue;
}

// FeliCa 回调：只做 Polling，不进入 Lite-S 读块/dump 流程。
// 在 RequestAuthContext 事件中直接 Stop —— 此时 idm/pmm 已由 Poller 填好，
// 从 nfc_poller_get_data 拷贝即可，无需认证、无需读块，也就不会触发死机路径。
static NfcCommand felica_poll_cb(NfcGenericEvent event, void* context) {
    PollSyncCtx* ctx = context;
    if(!ctx || !ctx->app->running) {
        if(ctx) furi_semaphore_release(ctx->app->nfc_done_sem);
        return NfcCommandStop;
    }
    if(event.protocol == NfcProtocolFelica && event.event_data) {
        const FelicaPollerEvent* ev = event.event_data;
        if(ev->type == FelicaPollerEventTypeReady ||
           ev->type == FelicaPollerEventTypeRequestAuthContext) {
            const FelicaData* f_data = nfc_poller_get_data(ctx->app->current_poller);
            if(f_data) {
                memcpy(ctx->idm, f_data->idm.data, 8);
                memcpy(ctx->pmm, f_data->pmm.data, 8);
                ctx->got_card = true;
            }
            furi_semaphore_release(ctx->app->nfc_done_sem);
            return NfcCommandStop;
        } else if(ev->type == FelicaPollerEventTypeIncomplete) {
            // 保持安全继续，但正常不会走到这里（RequestAuthContext 已 Stop）
            return NfcCommandContinue;
        } else if(ev->type == FelicaPollerEventTypeError) {
            furi_semaphore_release(ctx->app->nfc_done_sem);
            return NfcCommandStop;
        }
    }
    return NfcCommandContinue;
}

static NfcCommand mf_read_poll_cb(NfcGenericEvent event, void* context) {
    PollSyncCtx* ctx = context;
    if(!ctx || !ctx->app->running) {
        if(ctx) furi_semaphore_release(ctx->app->nfc_done_sem);
        return NfcCommandStop;
    }
    AimeReader* instance = ctx->app;
    if(event.protocol == NfcProtocolMfClassic && event.event_data) {
        const MfClassicPollerEvent* mf_event = event.event_data;
        if(mf_event->type == MfClassicPollerEventTypeRequestMode) {
            mf_event->data->poller_mode.mode = MfClassicPollerModeRead;
            return NfcCommandContinue;
        } else if(mf_event->type == MfClassicPollerEventTypeRequestReadSector) {
            uint8_t sector = mf_classic_get_sector_by_block(instance->mifare_read_block);
            bool use_b = instance->auth_b_ready && !instance->auth_a_ready;
            mf_event->data->read_sector_request_data.sector_num = sector;
            memcpy(
                mf_event->data->read_sector_request_data.key.data,
                use_b ? instance->key_b : instance->key_a,
                6);
            mf_event->data->read_sector_request_data.key_type =
                use_b ? MfClassicKeyTypeB : MfClassicKeyTypeA;
            mf_event->data->read_sector_request_data.key_provided = true;
            return NfcCommandContinue;
        } else if(mf_event->type == MfClassicPollerEventTypeSuccess) {
            ctx->got_card = true;
            furi_semaphore_release(instance->nfc_done_sem);
            return NfcCommandStop;
        } else if(mf_event->type == MfClassicPollerEventTypeFail) {
            furi_semaphore_release(instance->nfc_done_sem);
            return NfcCommandStop;
        }
    }
    return NfcCommandContinue;
}

static int32_t aime_nfc_thread(void* context) {
    AimeReader* instance = context;
    bool scan_felica_turn = false;
    uint8_t miss_count = 0;

    while(instance->running) {
        // 1. MIFARE 读块请求（最高优先级）
        if(instance->mifare_read_req) {
            PollSyncCtx ctx = {.app = instance, .got_card = false};
            while(furi_semaphore_acquire(instance->nfc_done_sem, 0) == FuriStatusOk) {
            }

            Nfc* nfc = nfc_alloc();
            if(nfc) {
                NfcPoller* poller = nfc_poller_alloc(nfc, NfcProtocolMfClassic);
                if(poller) {
                    nfc_poller_start(poller, mf_read_poll_cb, &ctx);
                    furi_semaphore_acquire(instance->nfc_done_sem, 400);
                    nfc_poller_stop(poller);

                    const MfClassicData* data = nfc_poller_get_data(poller);
                    if(data && mf_classic_is_block_read(data, instance->mifare_read_block)) {
                        memcpy(
                            instance->mifare_read_out,
                            data->block[instance->mifare_read_block].data,
                            16);
                        instance->mifare_read_ok = true;
                    }
                    nfc_poller_free(poller);
                }
                nfc_free(nfc);
            }
            instance->mifare_read_req = false;
            furi_semaphore_release(instance->mifare_read_sem);
            furi_delay_ms(35);
            continue;
        }

        // 2. 主机 Polling 开关检查
        furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
        bool polling = instance->state.is_polling;
        furi_mutex_release(instance->state_mutex);

        if(!polling) {
            instance->card_present = CardPresentNone;
            furi_delay_ms(40);
            continue;
        }

        PollSyncCtx ctx = {.app = instance, .got_card = false};
        while(furi_semaphore_acquire(instance->nfc_done_sem, 0) == FuriStatusOk) {
        }

        if(!scan_felica_turn) {
            // --- 周期 A: ISO14443-3A (MIFARE Aime / Banapassport) ---
            Nfc* nfc = nfc_alloc();
            if(nfc) {
                NfcPoller* poller = nfc_poller_alloc(nfc, NfcProtocolIso14443_3a);
                if(poller) {
                    nfc_poller_start(poller, iso3a_poll_cb, &ctx);
                    furi_semaphore_acquire(instance->nfc_done_sem, 55);
                    nfc_poller_stop(poller);

                    if(ctx.got_card) {
                        const Iso14443_3aData* iso_data = nfc_poller_get_data(poller);
                        if(iso_data && iso_data->uid_len > 0 && iso_data->uid_len <= 7) {
                            furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
                            memcpy(instance->cached_uid, iso_data->uid, iso_data->uid_len);
                            instance->cached_uid_len = iso_data->uid_len;
                            instance->card_present = CardPresentMifare;
                            snprintf(
                                instance->state.card_type,
                                sizeof(instance->state.card_type),
                                "MIFARE Classic");
                            snprintf(
                                instance->state.card_id,
                                sizeof(instance->state.card_id),
                                "UID: %02X %02X %02X %02X",
                                iso_data->uid[0],
                                iso_data->uid[1],
                                iso_data->uid[2],
                                iso_data->uid[3]);
                            furi_mutex_release(instance->state_mutex);
                            miss_count = 0;
                        }
                    }
                    nfc_poller_free(poller);
                }
                nfc_free(nfc);
            }
        } else {
            // --- 周期 B: FeliCa (Poller 只做 Polling，不进入 dump) ---
            Nfc* nfc = nfc_alloc();
            if(nfc) {
                NfcPoller* poller = nfc_poller_alloc(nfc, NfcProtocolFelica);
                if(poller) {
                    instance->current_poller = poller;
                    nfc_poller_start(poller, felica_poll_cb, &ctx);
                    furi_semaphore_acquire(instance->nfc_done_sem, 200);
                    nfc_poller_stop(poller);
                    furi_delay_ms(5); // 让回调线程安全退出
                    nfc_poller_free(poller);
                    instance->current_poller = NULL;

                    if(ctx.got_card) {
                        furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
                        memcpy(instance->cached_idm, ctx.idm, 8);
                        memcpy(instance->cached_pmm, ctx.pmm, 8);
                        instance->card_present = CardPresentFelica;
                        snprintf(
                            instance->state.card_type,
                            sizeof(instance->state.card_type),
                            "FeliCa (AIC)");
                        snprintf(
                            instance->state.card_id,
                            sizeof(instance->state.card_id),
                            "IDm:%02X%02X%02X%02X%02X%02X%02X%02X",
                            ctx.idm[0],
                            ctx.idm[1],
                            ctx.idm[2],
                            ctx.idm[3],
                            ctx.idm[4],
                            ctx.idm[5],
                            ctx.idm[6],
                            ctx.idm[7]);
                        snprintf(
                            instance->state.access_code,
                            sizeof(instance->state.access_code),
                            "PMm:%02X%02X%02X%02X%02X%02X%02X%02X",
                            ctx.pmm[0],
                            ctx.pmm[1],
                            ctx.pmm[2],
                            ctx.pmm[3],
                            ctx.pmm[4],
                            ctx.pmm[5],
                            ctx.pmm[6],
                            ctx.pmm[7]);
                        furi_mutex_release(instance->state_mutex);
                        miss_count = 0;
                    }
                }
                nfc_free(nfc);
            }
        }

        if(!ctx.got_card) {
            if(++miss_count >= 3) {
                instance->card_present = CardPresentNone;
            }
            scan_felica_turn = !scan_felica_turn;
        }

        furi_delay_ms(35);
    }
    return 0;
}

// --- 4. 串口指令响应层 ---
static void aime_handle_card_detect(AimeReader* instance) {
    furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
    CardPresentType type = instance->card_present;

    if(type == CardPresentMifare) {
        aime_res_init(instance, instance->cached_uid_len + 3);
        instance->res.count = 1;
        instance->res.type = 0x10;
        instance->res.id_len = instance->cached_uid_len;
        memcpy(instance->res.mifare_uid, instance->cached_uid, instance->cached_uid_len);
    } else if(type == CardPresentFelica) {
        aime_res_init(instance, 0x13);
        instance->res.count = 1;
        instance->res.type = 0x20;
        instance->res.id_len = 0x10;
        memcpy(instance->res.IDm, instance->cached_idm, 8);
        memcpy(instance->res.PMm, instance->cached_pmm, 8);
    } else {
        aime_res_init(instance, 1);
        instance->res.count = 0;
    }
    furi_mutex_release(instance->state_mutex);
}

static void aime_handle_mifare_read(AimeReader* instance) {
    while(furi_semaphore_acquire(instance->mifare_read_sem, 0) == FuriStatusOk) {
    }
    instance->mifare_read_block = instance->req.block_no;
    instance->mifare_read_ok = false;
    instance->mifare_read_req = true;

    furi_semaphore_release(instance->nfc_done_sem);
    furi_semaphore_acquire(instance->mifare_read_sem, 450);

    if(instance->mifare_read_ok) {
        aime_res_init(instance, 0x10);
        memcpy(instance->res.block, instance->mifare_read_out, 16);

        if(instance->mifare_read_block == 2) {
            furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
            snprintf(
                instance->state.access_code,
                sizeof(instance->state.access_code),
                "%02X%02X %02X%02X %02X%02X %02X%02X %02X%02X",
                instance->mifare_read_out[6],
                instance->mifare_read_out[7],
                instance->mifare_read_out[8],
                instance->mifare_read_out[9],
                instance->mifare_read_out[10],
                instance->mifare_read_out[11],
                instance->mifare_read_out[12],
                instance->mifare_read_out[13],
                instance->mifare_read_out[14],
                instance->mifare_read_out[15]);
            furi_mutex_release(instance->state_mutex);
        }
    } else {
        aime_res_init(instance, 0);
        instance->res.status = STATUS_CARD_ERROR;
    }
}

// --- 5. SEGA 837-15396 命令分发 ---
static void aime_dispatch_command(AimeReader* instance, uint8_t cmd_status) {
    furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
    instance->state.rx_packets++;
    bool is_high = instance->state.high_baudrate;
    furi_mutex_release(instance->state_mutex);

    switch(cmd_status) {
    case CMD_TO_NORMAL_MODE:
        aime_res_init(instance, 0);
        instance->res.status = STATUS_INVALID_COMMAND;
        break;

    case CMD_GET_FW_VERSION:
        if(is_high) {
            aime_res_init(instance, AIME_HIGH_FW_LEN);
            memcpy(instance->res.version, AIME_HIGH_FW_VERSION, AIME_HIGH_FW_LEN);
        } else {
            aime_res_init(instance, AIME_LOW_FW_LEN);
            memcpy(instance->res.version, AIME_LOW_FW_VERSION, AIME_LOW_FW_LEN);
        }
        break;

    case CMD_GET_HW_VERSION:
        if(is_high) {
            aime_res_init(instance, AIME_HIGH_HW_LEN);
            memcpy(instance->res.version, AIME_HIGH_HW_VERSION, AIME_HIGH_HW_LEN);
        } else {
            aime_res_init(instance, AIME_LOW_HW_LEN);
            memcpy(instance->res.version, AIME_LOW_HW_VERSION, AIME_LOW_HW_LEN);
        }
        break;

    case CMD_START_POLLING:
        aime_res_init(instance, 0);
        furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
        instance->state.is_polling = true;
        furi_mutex_release(instance->state_mutex);
        break;

    case CMD_STOP_POLLING:
        aime_res_init(instance, 0);
        furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
        instance->state.is_polling = false;
        instance->card_present = CardPresentNone;
        furi_mutex_release(instance->state_mutex);
        break;

    case CMD_CARD_DETECT:
        aime_handle_card_detect(instance);
        break;

    case CMD_MIFARE_KEY_SET_A:
        memcpy(instance->key_a, instance->req.key, 6);
        aime_res_init(instance, 0);
        break;

    case CMD_MIFARE_KEY_SET_B:
        memcpy(instance->key_b, instance->req.key, 6);
        aime_res_init(instance, 0);
        break;

    case CMD_MIFARE_AUTHORIZE_A:
        instance->auth_a_ready = true;
        instance->auth_b_ready = false;
        aime_res_init(instance, 0);
        break;

    case CMD_MIFARE_AUTHORIZE_B:
        instance->auth_b_ready = true;
        instance->auth_a_ready = false;
        aime_res_init(instance, 0);
        break;

    case CMD_MIFARE_READ:
        aime_handle_mifare_read(instance);
        break;

    case CMD_EXT_BOARD_LED_RGB:
        aime_set_led(
            instance,
            instance->req.color_payload[0],
            instance->req.color_payload[1],
            instance->req.color_payload[2],
            false);
        return;

    case CMD_EXT_BOARD_INFO:
        if(is_high) {
            aime_res_init(instance, AIME_HIGH_LED_LEN);
            memcpy(instance->res.version, AIME_HIGH_LED_INFO, AIME_HIGH_LED_LEN);
        } else {
            aime_res_init(instance, AIME_LOW_LED_LEN);
            memcpy(instance->res.version, AIME_LOW_LED_INFO, AIME_LOW_LED_LEN);
        }
        break;

    case CMD_EXT_BOARD_LED_RGB_UNKNOWN:
        return;

    case CMD_CARD_SELECT:
    case CMD_CARD_HALT:
    case CMD_EXT_TO_NORMAL_MODE:
    case CMD_TO_UPDATER_MODE:
    case CMD_SEND_BINDATA_INIT:
        aime_res_init(instance, 0);
        break;

    case CMD_SEND_BINDATA_EXEC:
        aime_res_init(instance, 0);
        instance->res.status = STATUS_FIRM_UPDATE_SUCCESS;
        break;

    case CMD_SEND_HEX_DATA:
        aime_res_init(instance, 0);
        instance->res.status = is_high ? STATUS_COMP_DUMMY_3RD : STATUS_OK;
        break;

    case STATUS_SUM_ERROR:
        aime_res_init(instance, 0);
        instance->res.status = STATUS_SUM_ERROR;
        break;

    default:
        aime_res_init(instance, 0);
        instance->res.status = STATUS_INVALID_COMMAND;
        break;
    }

    aime_packet_write(instance);
}

// --- 6. 串口逐字节解包 ---
static void aime_process_byte(AimeReader* instance, uint8_t r) {
    if(r == 0xE0) {
        instance->req.frame_len = 0xFF;
        instance->rx_escape = false;
        return;
    }
    if(instance->req.frame_len == 0xFF) {
        instance->req.frame_len = r;
        instance->rx_len = 0;
        instance->rx_checksum = r;
        return;
    }
    if(r == 0xD0) {
        instance->rx_escape = true;
        return;
    }
    if(instance->rx_escape) {
        r++;
        instance->rx_escape = false;
    }

    if((size_t)(instance->rx_len + 1) < sizeof(instance->req.bytes)) {
        instance->req.bytes[++instance->rx_len] = r;
    }

    if(instance->rx_len == instance->req.frame_len) {
        uint8_t status;
        if(instance->req.cmd == CMD_SEND_BINDATA_EXEC) {
            status = instance->req.cmd;
        } else {
            status = (instance->rx_checksum == r) ? instance->req.cmd : STATUS_SUM_ERROR;
        }
        aime_dispatch_command(instance, status);
        return;
    }

    instance->rx_checksum += r;
}

// --- 7. USB CDC 回调与线程管理 ---
static void cdc_rx_callback(void* context) {
    AimeReader* instance = context;
    if(!instance || !instance->rx_stream) return;
    instance->state.usb_connected = true;
    uint8_t buf[64];
    int32_t len = furi_hal_cdc_receive(CDC_IF_NUM, buf, sizeof(buf));
    if(len > 0) {
        furi_stream_buffer_send(instance->rx_stream, buf, len, 0);
    }
}

static void cdc_tx_callback(void* context) {
    UNUSED(context);
}

static void cdc_state_callback(void* context, CdcState state) {
    AimeReader* instance = context;
    if(!instance) return;
    instance->state.usb_connected = (state == CdcStateConnected);
}

static void cdc_ctrl_line_callback(void* context, uint8_t state) {
    UNUSED(context);
    UNUSED(state);
}

static void cdc_config_callback(void* context, struct usb_cdc_line_coding* config) {
    UNUSED(context);
    UNUSED(config);
}

static int32_t aime_worker_thread(void* context) {
    AimeReader* instance = context;
    uint8_t byte;

    while(instance->running) {
        if(furi_stream_buffer_receive(instance->rx_stream, &byte, 1, 50) == 1) {
            aime_process_byte(instance, byte);
        }
    }
    return 0;
}

AimeReader* aime_reader_alloc(void) {
    AimeReader* instance = malloc(sizeof(AimeReader));
    memset(instance, 0, sizeof(AimeReader));

    instance->notifications = furi_record_open(RECORD_NOTIFICATION);
    instance->rx_stream = furi_stream_buffer_alloc(512, 1);
    instance->state_mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    instance->nfc_done_sem = furi_semaphore_alloc(1, 0);
    instance->mifare_read_sem = furi_semaphore_alloc(1, 0);

    instance->state.high_baudrate = true;
    instance->state.usb_connected = false;
    snprintf(instance->state.card_type, sizeof(instance->state.card_type), "Waiting for card...");
    snprintf(instance->state.card_id, sizeof(instance->state.card_id), "Tap Aime / AIC / Phone");
    instance->state.access_code[0] = '\0';

    instance->running = true;
    instance->worker_thread = furi_thread_alloc_ex("AimeWorker", 4096, aime_worker_thread, instance);
    instance->nfc_thread = furi_thread_alloc_ex("AimeNfc", 8192, aime_nfc_thread, instance);
    furi_thread_start(instance->worker_thread);
    furi_thread_start(instance->nfc_thread);

    instance->cdc_callbacks.rx_ep_callback = cdc_rx_callback;
    instance->cdc_callbacks.tx_ep_callback = cdc_tx_callback;
    instance->cdc_callbacks.state_callback = cdc_state_callback;
    instance->cdc_callbacks.ctrl_line_callback = cdc_ctrl_line_callback;
    instance->cdc_callbacks.config_callback = cdc_config_callback;

    CliVcp* cli_vcp = furi_record_open(RECORD_CLI_VCP);
    cli_vcp_disable(cli_vcp);
    furi_record_close(RECORD_CLI_VCP);

    furi_hal_usb_unlock();
    furi_hal_usb_set_config(&usb_cdc_single, NULL);
    furi_delay_ms(50);

    furi_stream_buffer_reset(instance->rx_stream);
    furi_hal_cdc_set_callbacks(CDC_IF_NUM, &instance->cdc_callbacks, instance);

    aime_set_led(instance, 0x00, 0x00, 0xFF, true);

    return instance;
}

void aime_reader_free(AimeReader* instance) {
    if(!instance) return;

    furi_hal_cdc_set_callbacks(CDC_IF_NUM, NULL, NULL);

    instance->running = false;
    furi_semaphore_release(instance->nfc_done_sem);
    furi_semaphore_release(instance->mifare_read_sem);

    furi_thread_join(instance->worker_thread);
    furi_thread_free(instance->worker_thread);

    furi_thread_join(instance->nfc_thread);
    furi_thread_free(instance->nfc_thread);

    aime_set_led(instance, 0x00, 0x00, 0x00, true);
    CliVcp* cli_vcp = furi_record_open(RECORD_CLI_VCP);
    cli_vcp_enable(cli_vcp);
    furi_record_close(RECORD_CLI_VCP);

    furi_record_close(RECORD_NOTIFICATION);
    furi_stream_buffer_free(instance->rx_stream);
    furi_mutex_free(instance->state_mutex);
    furi_semaphore_free(instance->nfc_done_sem);
    furi_semaphore_free(instance->mifare_read_sem);
    free(instance);
}

void aime_reader_get_state(AimeReader* instance, AimeReaderState* out_state) {
    if(!instance || !out_state) return;
    furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
    memcpy(out_state, &instance->state, sizeof(AimeReaderState));
    furi_mutex_release(instance->state_mutex);
}

void aime_reader_toggle_baudrate(AimeReader* instance) {
    if(!instance) return;
    furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
    instance->state.high_baudrate = !instance->state.high_baudrate;
    bool is_high = instance->state.high_baudrate;
    furi_mutex_release(instance->state_mutex);

    if(is_high) {
        aime_set_led(instance, 0x00, 0x00, 0xFF, true);
    } else {
        aime_set_led(instance, 0x00, 0xFF, 0x00, true);
    }
}