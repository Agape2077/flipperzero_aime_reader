#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>
#include <stdio.h>
#include "aime_reader.h"

typedef struct {
    Gui* gui;
    ViewPort* view_port;
    FuriMessageQueue* event_queue;
    AimeReader* reader;
    bool running;
} FlipAimeApp;

static void render_callback(Canvas* canvas, void* ctx) {
    FlipAimeApp* app = ctx;
    AimeReaderState state;
    aime_reader_get_state(app->reader, &state);

    canvas_clear(canvas);

    // 顶部标题栏 (11px 高)
    canvas_draw_box(canvas, 0, 0, 128, 11);
    canvas_invert_color(canvas);
    canvas_set_font(canvas, FontPrimary);
    if(state.high_baudrate) {
        canvas_draw_str(canvas, 3, 9, "837-15396 (115200)");
    } else {
        canvas_draw_str(canvas, 3, 9, "TN32MSEC (38400)");
    }
    canvas_invert_color(canvas);

    canvas_set_font(canvas, FontSecondary);

    // 第 1 行：通信与灯光状态
    char line1[44];
    snprintf(
        line1,
        sizeof(line1),
        "Poll:%s LED:#%02X%02X%02X P:%lu",
        state.is_polling ? "ON" : "OFF",
        state.led_r,
        state.led_g,
        state.led_b,
        state.rx_packets);
    canvas_draw_str(canvas, 2, 21, line1);

    // 分割线
    canvas_draw_line(canvas, 0, 24, 128, 24);

    // 第 2 行：卡片类型 (FeliCa AIC / MIFARE Classic)
    canvas_draw_str(canvas, 2, 35, state.card_type);

    // 第 3 行：IDm 或 UID
    canvas_draw_str(canvas, 2, 47, state.card_id);

    // 第 4 行：20位 Access Code 或 PMm
    canvas_draw_str(canvas, 2, 59, state.access_code);
}

static void input_callback(InputEvent* input_event, void* ctx) {
    FlipAimeApp* app = ctx;
    if(input_event->type == InputTypeShort) {
        if(input_event->key == InputKeyBack || input_event->key == InputKeyOk) {
            furi_message_queue_put(app->event_queue, input_event, 0);
        }
    }
}

int32_t flip_aime_reader_app(void* p) {
    UNUSED(p);

    FlipAimeApp* app = malloc(sizeof(FlipAimeApp));
    app->event_queue = furi_message_queue_alloc(8, sizeof(InputEvent));
    app->running = true;

    // 启动核心读卡器服务
    app->reader = aime_reader_alloc();

    // 初始化 GUI ViewPort
    app->view_port = view_port_alloc();
    view_port_draw_callback_set(app->view_port, render_callback, app);
    view_port_input_callback_set(app->view_port, input_callback, app);

    app->gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(app->gui, app->view_port, GuiLayerFullscreen);

    InputEvent event;
    while(app->running) {
        if(furi_message_queue_get(app->event_queue, &event, 150) == FuriStatusOk) {
            if(event.type == InputTypeShort) {
                if(event.key == InputKeyBack) {
                    app->running = false;
                } else if(event.key == InputKeyOk) {
                    aime_reader_toggle_baudrate(app->reader);
                }
            }
        }
        view_port_update(app->view_port);
    }

    // 清理资源
    gui_remove_view_port(app->gui, app->view_port);
    view_port_free(app->view_port);
    furi_record_close(RECORD_GUI);

    aime_reader_free(app->reader);
    furi_message_queue_free(app->event_queue);
    free(app);

    return 0;
}