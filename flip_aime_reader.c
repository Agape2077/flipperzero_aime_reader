#include <furi.h>
#include <gui/gui.h>
#include <gui/view.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/variable_item_list.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aime_reader.h"

typedef enum {
    AimeViewMain = 0,
    AimeViewSettings = 1,
} AimeViewId;

typedef struct {
    Gui* gui;
    ViewDispatcher* view_dispatcher;
    View* main_view;
    VariableItemList* settings_list;
    FuriTimer* refresh_timer;
    AimeReader* reader;
} FlipAimeApp;

// --- 1. 主界面渲染与按键处理 ---
static void main_view_draw_callback(Canvas* canvas, void* model) {
    FlipAimeApp* app = *(FlipAimeApp**)model;
    if(!app || !app->reader) return;

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

    // 第 1 行：通信、AIC模式与灯光状态
    char line1[44];
    snprintf(
        line1,
        sizeof(line1),
        "P:%s AIC:%s PKT:%lu",
        state.is_polling ? "ON" : "OFF",
        state.aic_as_mifare ? "MF" : "RAW",
        (unsigned long)state.rx_packets);
    canvas_draw_str(canvas, 2, 20, line1);

    // 分割线
    canvas_draw_line(canvas, 0, 23, 128, 23);

    // 第 2 行：卡片类型
    canvas_draw_str(canvas, 2, 33, state.card_type);

    // 第 3 行：IDm 或 UID
    canvas_draw_str(canvas, 2, 43, state.card_id);

    // 第 4 行：20位 Access Code 或 PMm
    canvas_draw_str(canvas, 2, 53, state.access_code);

    // 底部操作提示
    canvas_draw_str_aligned(canvas, 126, 63, AlignRight, AlignBottom, "[OK] Settings");
}

static bool main_view_input_callback(InputEvent* event, void* context) {
    FlipAimeApp* app = context;
    if(event->type == InputTypeShort && event->key == InputKeyOk) {
        view_dispatcher_switch_to_view(app->view_dispatcher, AimeViewSettings);
        return true;
    }
    return false;
}

static uint32_t main_view_exit_callback(void* context) {
    UNUSED(context);
    return VIEW_NONE; // 返回 VIEW_NONE 使 view_dispatcher_run 退出
}

// --- 2. 二级设置菜单回调 ---
static uint32_t settings_view_exit_callback(void* context) {
    UNUSED(context);
    return AimeViewMain; // 按 Back 返回主界面
}

static void baudrate_change_callback(VariableItem* item) {
    FlipAimeApp* app = variable_item_get_context(item);
    uint8_t index = variable_item_get_current_value_index(item);
    bool is_high = (index == 0);
    variable_item_set_current_value_text(item, is_high ? "115200" : "38400");
    aime_reader_set_baudrate(app->reader, is_high);
}

static void aic_mode_change_callback(VariableItem* item) {
    FlipAimeApp* app = variable_item_get_context(item);
    uint8_t index = variable_item_get_current_value_index(item);
    bool emu_mifare = (index == 0);
    variable_item_set_current_value_text(item, emu_mifare ? "MIFARE Emu" : "Native FeliCa");
    aime_reader_set_aic_as_mifare(app->reader, emu_mifare);
}

// 定时刷新主视图
static void refresh_timer_callback(void* context) {
    FlipAimeApp* app = context;
    if(app && app->main_view) {
        view_commit_model(app->main_view, true);
    }
}

int32_t flip_aime_reader_app(void* p) {
    UNUSED(p);

    FlipAimeApp* app = malloc(sizeof(FlipAimeApp));
    if(!app) return 1;
    memset(app, 0, sizeof(FlipAimeApp));
    app->reader = aime_reader_alloc();
    if(!app->reader) {
        free(app);
        return 1;
    }

    AimeReaderState init_state;
    aime_reader_get_state(app->reader, &init_state);

    app->gui = furi_record_open(RECORD_GUI);
    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);

    // 初始化主视图
    app->main_view = view_alloc();
    view_allocate_model(app->main_view, ViewModelTypeLockFree, sizeof(FlipAimeApp*));
    *(FlipAimeApp**)view_get_model(app->main_view) = app;
    view_set_context(app->main_view, app);
    view_set_draw_callback(app->main_view, main_view_draw_callback);
    view_set_input_callback(app->main_view, main_view_input_callback);
    view_set_previous_callback(app->main_view, main_view_exit_callback);
    view_dispatcher_add_view(app->view_dispatcher, AimeViewMain, app->main_view);

    // 初始化二级设置菜单 (VariableItemList)
    app->settings_list = variable_item_list_alloc();
    View* settings_view = variable_item_list_get_view(app->settings_list);
    view_set_previous_callback(settings_view, settings_view_exit_callback);

    // 设置项 1: 波特率
    VariableItem* baud_item =
        variable_item_list_add(app->settings_list, "Baudrate", 2, baudrate_change_callback, app);
    variable_item_set_current_value_index(baud_item, init_state.high_baudrate ? 0 : 1);
    variable_item_set_current_value_text(baud_item, init_state.high_baudrate ? "115200" : "38400");

    // 设置项 2: AIC 转换模式开关
    VariableItem* aic_item =
        variable_item_list_add(app->settings_list, "AIC Mode", 2, aic_mode_change_callback, app);
    variable_item_set_current_value_index(aic_item, init_state.aic_as_mifare ? 0 : 1);
    variable_item_set_current_value_text(
        aic_item, init_state.aic_as_mifare ? "MIFARE Emu" : "Native FeliCa");

    view_dispatcher_add_view(app->view_dispatcher, AimeViewSettings, settings_view);

    // 启动定时刷新主界面 (每 150ms)
    app->refresh_timer = furi_timer_alloc(refresh_timer_callback, FuriTimerTypePeriodic, app);
    furi_timer_start(app->refresh_timer, 150);

    // 切换到主视图并进入事件循环
    view_dispatcher_switch_to_view(app->view_dispatcher, AimeViewMain);
    view_dispatcher_run(app->view_dispatcher);

    // 清理资源
    furi_timer_stop(app->refresh_timer);
    furi_timer_free(app->refresh_timer);

    view_dispatcher_remove_view(app->view_dispatcher, AimeViewMain);
    view_dispatcher_remove_view(app->view_dispatcher, AimeViewSettings);
    view_free(app->main_view);
    variable_item_list_free(app->settings_list);
    view_dispatcher_free(app->view_dispatcher);
    furi_record_close(RECORD_GUI);

    aime_reader_free(app->reader);
    free(app);

    return 0;
}
