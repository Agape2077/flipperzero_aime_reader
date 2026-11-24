#include <furi.h>
#include <gui/gui.h>
#include <gui/view.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/variable_item_list.h>
#include <gui/modules/file_browser.h>
#include <gui/modules/widget.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aime_reader.h"

typedef enum {
    AimeViewMain = 0,
    AimeViewSettings = 1,
    AimeViewFileBrowser = 2,
    AimeViewResultWidget = 3,
} AimeViewId;

#define AIME_EVENT_UPDATE_FILE_ITEM 1U
#define AIME_EVENT_CLOSE_RESULT     2U
#define AIME_RESULT_AUTO_CLOSE_MS   3000U

typedef struct {
    Gui* gui;
    ViewDispatcher* view_dispatcher;
    View* main_view;
    VariableItemList* settings_list;
    VariableItem* file_item;
    FileBrowser* file_browser;
    Widget* result_widget;
    FuriString* file_path;
    FuriTimer* refresh_timer;
    FuriTimer* result_timer;
    bool result_dialog_open;
    AimeReader* reader;
    bool file_browser_started;
    // 供刷新线程比较、避免跨线程直接改 GUI 控件
    bool ui_file_active;
    char ui_file_name[48];
} FlipAimeApp;

// Flipper 的 FileBrowser 会把自己的实例设为 View context，无法直接取到 App。
// 本应用只有一个实例，这里保存一份供 View 生命周期回调使用。
static FlipAimeApp* app_instance = NULL;

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
        state.is_polling ? "on" : "off",
        state.aic_as_mifare ? "emulate" : "native",
        (unsigned long)state.rx_packets);
    canvas_draw_str(canvas, 2, 20, line1);

    // 分割线
    canvas_draw_line(canvas, 0, 23, 128, 23);

    // 第 2 行：卡片类型（若模拟文件卡，带文件名提示）
    if(state.file_virtual_active) {
        char file_title[64];
        snprintf(file_title, sizeof(file_title), "[FILE] %s", state.file_virtual_name);
        canvas_draw_str(canvas, 2, 33, file_title);
    } else {
        canvas_draw_str(canvas, 2, 33, state.card_type);
    }

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

static void refresh_file_item_display(FlipAimeApp* app) {
    if(!app || !app->file_item || !app->reader) return;
    AimeReaderState state;
    aime_reader_get_state(app->reader, &state);
    variable_item_set_current_value_text(
        app->file_item, state.file_virtual_active ? state.file_virtual_name : "None");
}

static void close_result_dialog(FlipAimeApp* app) {
    if(!app) return;
    app->result_dialog_open = false;
    if(app->result_timer) {
        furi_timer_stop(app->result_timer);
    }
    if(app->view_dispatcher) {
        view_dispatcher_switch_to_view(app->view_dispatcher, AimeViewSettings);
    }
}

static void result_auto_close_timer_callback(void* context) {
    FlipAimeApp* app = context;
    if(app && app->view_dispatcher) {
        // timer 线程只发事件，真正切视图在 GUI 线程完成
        view_dispatcher_send_custom_event(app->view_dispatcher, AIME_EVENT_CLOSE_RESULT);
    }
}

static bool custom_event_callback(void* context, uint32_t event) {
    FlipAimeApp* app = context;
    if(!app) return false;
    if(event == AIME_EVENT_UPDATE_FILE_ITEM) {
        refresh_file_item_display(app);
        return true;
    }
    if(event == AIME_EVENT_CLOSE_RESULT) {
        if(app->result_dialog_open) {
            close_result_dialog(app);
        }
        return true;
    }
    return false;
}

static void result_widget_button_callback(GuiButtonType result, InputType type, void* context) {
    UNUSED(result);
    FlipAimeApp* app = context;
    if(!app) return;

    // 某些固件/输入路径只上报 Press/Long，这里一并处理，确保按 OK 必定返回
    if(type == InputTypePress || type == InputTypeShort || type == InputTypeLong) {
        close_result_dialog(app);
    }
}

static void show_result_dialog(FlipAimeApp* app, const char* title, const char* text) {
    widget_reset(app->result_widget);
    widget_add_string_element(
        app->result_widget, 64, 4, AlignCenter, AlignTop, FontPrimary, title);
    widget_add_string_multiline_element(
        app->result_widget, 64, 20, AlignCenter, AlignTop, FontSecondary, text);
    widget_add_button_element(
        app->result_widget, GuiButtonTypeCenter, "OK", result_widget_button_callback, app);

    app->result_dialog_open = true;
    if(app->result_timer) {
        furi_timer_stop(app->result_timer);
        furi_timer_start(
            app->result_timer, furi_ms_to_ticks(AIME_RESULT_AUTO_CLOSE_MS));
    }

    view_dispatcher_switch_to_view(app->view_dispatcher, AimeViewResultWidget);
}

static uint32_t browser_view_previous_callback(void* context) {
    UNUSED(context);
    FlipAimeApp* app = app_instance;
    if(app && app->file_browser_started) {
        file_browser_stop(app->file_browser);
        app->file_browser_started = false;
    }
    return AimeViewSettings;
}

static void stop_file_browser(FlipAimeApp* app) {
    if(app && app->file_browser_started) {
        file_browser_stop(app->file_browser);
        app->file_browser_started = false;
    }
}

static uint32_t result_widget_exit_callback(void* context) {
    UNUSED(context);
    return AimeViewSettings;
}

static void result_widget_view_exit_callback(void* context) {
    UNUSED(context);
    FlipAimeApp* app = app_instance;
    if(app) {
        app->result_dialog_open = false;
        if(app->result_timer) {
            furi_timer_stop(app->result_timer);
        }
    }
}

static void file_browser_callback(void* context) {
    FlipAimeApp* app = context;
    if(!app || !app->file_path) return;

    // 选择文件后立即结束浏览器 worker，避免重复 start 时泄漏
    stop_file_browser(app);

    if(furi_string_size(app->file_path) > 0) {
        VirtualCardResult res = aime_reader_load_virtual_card(
            app->reader, furi_string_get_cstr(app->file_path));

        AimeReaderState state;
        switch(res) {
        case VirtualCardResultOk: {
            aime_reader_get_state(app->reader, &state);
            refresh_file_item_display(app);
            aime_reader_arm_virtual_card_timer(app->reader);
            char info_buf[160];
            snprintf(
                info_buf,
                sizeof(info_buf),
                "Loaded:\n%s\n%s\nAuto unmount 5s",
                state.file_virtual_name,
                state.card_type);
            show_result_dialog(app, "Virtual Card", info_buf);
            break;
        }
        case VirtualCardResultNotAimeCard:
            show_result_dialog(
                app, "Rejected", "Not an Aime/Banapass card!\n(KeyB signature mismatch)");
            break;
        case VirtualCardResultMissingBlocks:
            show_result_dialog(
                app, "Rejected", "Missing/unread key blocks\nin dump file (contains unread bytes)");
            break;
        case VirtualCardResultFileNotFound:
            show_result_dialog(
                app, "File Error", "Cannot open NFC file.");
            break;
        case VirtualCardResultParseFail:
        default:
            show_result_dialog(
                app, "Parse Error", "Invalid NFC dump format.");
            break;
        }
    } else {
        view_dispatcher_switch_to_view(app->view_dispatcher, AimeViewSettings);
    }
}

static void settings_item_enter_callback(void* context, uint32_t index) {
    FlipAimeApp* app = context;
    if(!app) return;

    // index 2: 虚拟卡文件设置项
    if(index == 2) {
        AimeReaderState state;
        aime_reader_get_state(app->reader, &state);

        if(state.file_virtual_active) {
            // 已有激活虚拟卡，按下可卸载
            aime_reader_clear_virtual_card(app->reader);
            refresh_file_item_display(app);
            show_result_dialog(app, "Virtual Card", "Virtual card cleared.\nNFC polling resumed.");
        } else {
            // 启动 FileBrowser View
            stop_file_browser(app);
            FuriString* nfc_dir = furi_string_alloc_set("/ext/nfc");
            file_browser_start(app->file_browser, nfc_dir);
            app->file_browser_started = true;
            furi_string_free(nfc_dir);
            view_dispatcher_switch_to_view(app->view_dispatcher, AimeViewFileBrowser);
        }
    }
}

static void settings_view_enter_callback(void* context) {
    UNUSED(context);
    FlipAimeApp* app = app_instance;
    if(app) refresh_file_item_display(app);
}

// 定时刷新主视图；GUI 控件只在 GUI 线程里更新
static void refresh_timer_callback(void* context) {
    FlipAimeApp* app = context;
    if(!app) return;

    if(app->main_view) {
        view_commit_model(app->main_view, true);
    }

    if(app->file_item && app->reader) {
        AimeReaderState state;
        aime_reader_get_state(app->reader, &state);

        bool active = state.file_virtual_active;
        bool changed = (active != app->ui_file_active) ||
                       (active &&
                        strncmp(app->ui_file_name, state.file_virtual_name,
                                sizeof(app->ui_file_name)) != 0);
        if(changed) {
            app->ui_file_active = active;
            snprintf(app->ui_file_name, sizeof(app->ui_file_name), "%s", state.file_virtual_name);
            // 不能在 timer 线程直接改 VariableItem，交给 GUI 线程处理
            view_dispatcher_send_custom_event(
                app->view_dispatcher, AIME_EVENT_UPDATE_FILE_ITEM);
        }
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
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_custom_event_callback(app->view_dispatcher, custom_event_callback);
    app_instance = app;

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
    view_set_enter_callback(settings_view, settings_view_enter_callback);

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

    // 设置项 3: 文件虚拟卡选择/卸载 (按下 OK 加载 .nfc 或卸载已加载虚拟卡)
    app->file_item = variable_item_list_add(app->settings_list, "File Card", 1, NULL, app);
    variable_item_set_current_value_text(
        app->file_item, init_state.file_virtual_active ? init_state.file_virtual_name : "None");

    variable_item_list_set_enter_callback(app->settings_list, settings_item_enter_callback, app);
    view_dispatcher_add_view(app->view_dispatcher, AimeViewSettings, settings_view);

    // 初始化 FileBrowser 视图
    app->file_path = furi_string_alloc();
    app->file_browser = file_browser_alloc(app->file_path);
    file_browser_configure(app->file_browser, ".nfc", "/ext/nfc", true, true, NULL, true);
    file_browser_set_callback(app->file_browser, file_browser_callback, app);
    View* browser_view = file_browser_get_view(app->file_browser);
    view_set_previous_callback(browser_view, browser_view_previous_callback);
    view_dispatcher_add_view(app->view_dispatcher, AimeViewFileBrowser, browser_view);

    // 初始化 Result Widget 提示弹窗视图
    app->result_widget = widget_alloc();
    View* widget_view = widget_get_view(app->result_widget);
    view_set_previous_callback(widget_view, result_widget_exit_callback);
    view_set_exit_callback(widget_view, result_widget_view_exit_callback);
    view_dispatcher_add_view(app->view_dispatcher, AimeViewResultWidget, widget_view);

    // 加载完成弹窗 3 秒后自动关闭
    app->result_timer =
        furi_timer_alloc(result_auto_close_timer_callback, FuriTimerTypeOnce, app);

    // 启动定时刷新主界面 (每 150ms)
    app->refresh_timer = furi_timer_alloc(refresh_timer_callback, FuriTimerTypePeriodic, app);
    furi_timer_start(app->refresh_timer, 150);

    // 切换到主视图并进入事件循环
    view_dispatcher_switch_to_view(app->view_dispatcher, AimeViewMain);
    view_dispatcher_run(app->view_dispatcher);

    // 清理资源
    furi_timer_stop(app->refresh_timer);
    furi_timer_free(app->refresh_timer);

    if(app->result_timer) {
        furi_timer_stop(app->result_timer);
        furi_timer_free(app->result_timer);
    }

    if(app->file_browser_started) {
        file_browser_stop(app->file_browser);
        app->file_browser_started = false;
    }

    view_dispatcher_remove_view(app->view_dispatcher, AimeViewMain);

    view_dispatcher_remove_view(app->view_dispatcher, AimeViewSettings);
    view_dispatcher_remove_view(app->view_dispatcher, AimeViewFileBrowser);
    view_dispatcher_remove_view(app->view_dispatcher, AimeViewResultWidget);

    view_free(app->main_view);
    variable_item_list_free(app->settings_list);
    file_browser_free(app->file_browser);
    widget_free(app->result_widget);
    furi_string_free(app->file_path);

    view_dispatcher_free(app->view_dispatcher);
    furi_record_close(RECORD_GUI);

    aime_reader_free(app->reader);
    app_instance = NULL;
    free(app);

    return 0;
}
