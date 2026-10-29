#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winerror.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include "scanner.c"

#if USE_APPNOTIFICATIONS
# include "appnotifications.c"
#endif

#if USE_API_HOOKS
# include "dynamic.c"
#endif

#define ID_TIMER_GUI            2
#define ID_TIMER_SCAN_UPDATE    3

// Logging enabled for main thread.
static BOOL logging_enabled = FALSE;

static HANDLE scanThread = NULL;
static BOOL scanning = FALSE;
static BOOL hovering = FALSE;
static BOOL pressed = FALSE;
static BOOL countingFiles = FALSE;
static int frame = 0;

static DWORD scanStartTime = 0;
static uint64_t scannedFiles = 0;
static uint64_t totalFiles = 0;
static uint64_t maliciousFiles = 0;
static char **maliciousPaths;

static char *rootDir = "C:";

static RECT getButtonRect(const RECT *rect)
{
    int width = rect->right - rect->left;
    int height = rect->bottom - rect->top;
    int diameter = width < height ? width / 5 : height / 5;

    if (diameter > 160)
        diameter = 160;
    if (diameter > width - 20)
        diameter = width - 20;
    if (diameter > height - 20)
        diameter = height - 20;
    if (diameter < 1)
        diameter = 1;

    int x = rect->left + (width - diameter) / 2;
    int y = rect->top + (height - diameter) / 2;

    RECT result = { x, y, x + diameter, y + diameter };
    return result;
}

static BOOL pointInButton(POINT point, const RECT *rect)
{
    return PtInRect(rect, point);
}

static void drawGradient(HDC hdc, const RECT *rect)
{
    int height = rect->bottom - rect->top;
    int width = rect->right - rect->left;

    if (height <= 0 || width <= 0)
        return;

    for (int y = 0; y < height; ++y) {
        double t = (double)y / (height > 1 ? height - 1 : 1);
        int r = (int)(255 - 8 * t);
        int g = (int)(240 - 25 * t);
        int b = (int)(247 - 10 * t);

        HPEN pen = CreatePen(PS_SOLID, 1, RGB(r, g, b));
        if (!pen)
            continue;

        HPEN oldPen = (HPEN)SelectObject(hdc, pen);
        MoveToEx(hdc, rect->left, rect->top + y, NULL);
        LineTo(hdc, rect->right, rect->top + y);
        SelectObject(hdc, oldPen);
        DeleteObject(pen);
    }
}

static void drawTitle(HDC hdc, const RECT *rect)
{
    HFONT font = CreateFontA(
        34, 0, 0, 0, FW_BOLD,
        FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI"
    );
    if (!font)
        return;

    HFONT oldFont = (HFONT)SelectObject(hdc, font);
    RECT titleRect = { 20, 35, rect->right - 20, 85 };

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(40, 45, 65));
    DrawTextA(hdc, "Hedda Defender", -1, &titleRect,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    SelectObject(hdc, oldFont);
    DeleteObject(font);
}

static void drawSpinner(HDC hdc, int cx, int cy, int currentFrame)
{
    const int dots = 12;
    const int radius = 24;
    const int dotSize = 7;
    HPEN nullPen = (HPEN)GetStockObject(NULL_PEN);

    for (int i = 0; i < dots; ++i) {
        double angle = (i + currentFrame) * 6.28318530718 / dots;
        int x = cx + (int)(cos(angle) * radius);
        int y = cy + (int)(sin(angle) * radius);
        int brightness = 70 + i * 185 / dots;

        HBRUSH brush = CreateSolidBrush(RGB(40, brightness, 255));
        if (!brush)
            continue;

        HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, brush);
        HPEN oldPen = (HPEN)SelectObject(hdc, nullPen);
        Ellipse(hdc, x - dotSize / 2, y - dotSize / 2,
                x + dotSize / 2, y + dotSize / 2);
        SelectObject(hdc, oldBrush);
        SelectObject(hdc, oldPen);
        DeleteObject(brush);
    }
}

static void formatTime(DWORD seconds, char *buffer, size_t size)
{
    unsigned long hours = (unsigned long)(seconds / 3600);
    unsigned long minutes = (unsigned long)((seconds % 3600) / 60);
    unsigned long remaining = (unsigned long)(seconds % 60);
    if (hours > 0)
        _snprintf_s(buffer, size, _TRUNCATE, "%lu:%02lu:%02lu", hours, minutes, remaining);
    else
        _snprintf_s(buffer, size, _TRUNCATE, "%lu:%02lu", minutes, remaining);
}

static void drawScanStatus(HDC hdc, const RECT *rect)
{
    int cx = (rect->left + rect->right) / 2;
    int cy = (rect->top + rect->bottom) / 2;
    DWORD elapsedSeconds = (GetTickCount() - scanStartTime) / 1000;

    int percentage = 0;
    DWORD remainingSeconds = 0;

    if (totalFiles > 0) {
        double rawPercentage = (double)scannedFiles * 100.0 / (double)totalFiles;
        if (rawPercentage > 100.0)
            rawPercentage = 100.0;
        percentage = (int)rawPercentage;

        if (scannedFiles > 0 && scannedFiles < totalFiles) {
            double estimate = ((double)elapsedSeconds / (double)scannedFiles)
                            * (double)(totalFiles - scannedFiles);
            if (estimate > 4294967295.0)
                estimate = 4294967295.0;
            if (estimate > 0.0)
                remainingSeconds = (DWORD)estimate;
        }
    }

    drawSpinner(hdc, cx, cy - 35, frame);

    HFONT percentFont = CreateFontA(
        20, 0, 0, 0, FW_BOLD,
        FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI"
    );

    if (percentFont) {
        HFONT oldFont = (HFONT)SelectObject(hdc, percentFont);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(40, 45, 65));

        char percentText[16];
        if (countingFiles || totalFiles == 0) {
            lstrcpyA(percentText, "...");
        } else {
            _snprintf_s(percentText, sizeof(percentText), _TRUNCATE,
                        "%d%%", percentage);
        }

        RECT percentRect = { cx - 50, cy - 10, cx + 50, cy + 20 };
        DrawTextA(hdc, percentText, -1, &percentRect,
                  DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        SelectObject(hdc, oldFont);
        DeleteObject(percentFont);
    }

    HFONT font = CreateFontA(
        15, 0, 0, 0, FW_SEMIBOLD,
        FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI"
    );
    if (!font)
        return;

    HFONT oldFont = (HFONT)SelectObject(hdc, font);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(40, 45, 65));

    RECT statusRect = { cx - 180, cy + 28, cx + 180, cy + 53 };
    const char *statusText = countingFiles ? "Counting files..." : "Scanning...";
    DrawTextA(hdc, statusText, -1, &statusRect,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    char elapsedText[32];
    char remainingText[32];
    char timeText[128];
    formatTime(elapsedSeconds, elapsedText, sizeof(elapsedText));

    if (!countingFiles && totalFiles > 0 && scannedFiles > 0) {
        formatTime(remainingSeconds, remainingText, sizeof(remainingText));
    } else {
        lstrcpyA(remainingText, "--:--");
    }

    _snprintf_s(timeText, sizeof(timeText), _TRUNCATE,
                "Elapsed: %s    Remaining: %s", elapsedText, remainingText);
    RECT timeRect = { cx - 200, cy + 55, cx + 200, cy + 82 };
    DrawTextA(hdc, timeText, -1, &timeRect,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    char filesText[96];
    if (totalFiles > 0) {
        _snprintf_s(filesText, sizeof(filesText), _TRUNCATE,
                    "%llu / %llu files",
                    (unsigned long long)scannedFiles,
                    (unsigned long long)totalFiles);
    } else {
        lstrcpyA(filesText, "Preparing file count...");
    }
    RECT filesRect = { cx - 200, cy + 82, cx + 200, cy + 106 };
    DrawTextA(hdc, filesText, -1, &filesRect,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    SelectObject(hdc, oldFont);
    DeleteObject(font);
}

static void drawStartButton(HDC hdc, const RECT *rect)
{
    RECT r = getButtonRect(rect);
    int width = r.right - r.left;
    int height = r.bottom - r.top;
    int cx = (r.left + r.right) / 2;
    int cy = (r.top + r.bottom) / 2;

    COLORREF color = RGB(0, 190, 85);
    if (pressed)
        color = RGB(0, 140, 65);
    else if (hovering)
        color = RGB(0, 220, 100);

    POINT triangle[3] = {
        { r.left + width / 8, r.top + height / 10 },
        { r.left + width / 8, r.bottom - height / 10 },
        { r.right - width / 10, cy }
    };

    HBRUSH brush = CreateSolidBrush(color);
    HPEN pen = CreatePen(PS_NULL, 0, color);
    if (brush && pen) {
        HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, brush);
        HPEN oldPen = (HPEN)SelectObject(hdc, pen);
        Polygon(hdc, triangle, 3);
        SelectObject(hdc, oldBrush);
        SelectObject(hdc, oldPen);
    }
    if (brush)
        DeleteObject(brush);
    if (pen)
        DeleteObject(pen);

    HFONT font = CreateFontA(
        24, 0, 0, 0, FW_BOLD,
        FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI"
    );
    if (!font)
        return;

    HFONT oldFont = (HFONT)SelectObject(hdc, font);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(0, 0, 0));

    RECT textRect = { cx - width / 3, cy - 15, cx + width / 3, cy + 15 };
    DrawTextA(hdc, "Start", -1, &textRect,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    SelectObject(hdc, oldFont);
    DeleteObject(font);
}

static void showScanStartError(HWND wind)
{
    MessageBoxA(wind, "Could not start the scanner.",
                "Hedda Defender", MB_OK | MB_ICONERROR);
}

static LRESULT CALLBACK windProc(HWND wind, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CLOSE:
        DestroyWindow(wind);
        return 0;

    case WM_DESTROY:
        KillTimer(wind, ID_TIMER_GUI);
        KillTimer(wind, ID_TIMER_SCAN_UPDATE);
        if (scanThread != NULL) {
            CloseHandle(scanThread);
            scanThread = NULL;
        }
        PostQuitMessage(0);
        return 0;

    case WM_ERASEBKGND:
        return 1;

    case WM_MOUSEMOVE:
        if (!scanning) {
            TRACKMOUSEEVENT track = { sizeof(TRACKMOUSEEVENT), TME_LEAVE, wind, 0 };
            TrackMouseEvent(&track);

            RECT rect;
            GetClientRect(wind, &rect);
            POINT point = { (short)LOWORD(lp), (short)HIWORD(lp) };
            RECT buttonRect = getButtonRect(&rect);
            BOOL newHover = pointInButton(point, &buttonRect);

            if (newHover != hovering) {
                hovering = newHover;
                InvalidateRect(wind, NULL, FALSE);
            }
        }
        return 0;

    case WM_MOUSELEAVE:
        hovering = FALSE;
        if (!pressed)
            InvalidateRect(wind, NULL, FALSE);
        return 0;

    case WM_LBUTTONDOWN:
        if (!scanning) {
            RECT rect;
            GetClientRect(wind, &rect);
            POINT point = { (short)LOWORD(lp), (short)HIWORD(lp) };
            RECT buttonRect = getButtonRect(&rect);

            if (PtInRect(&buttonRect, point)) {
                pressed = TRUE;
                SetCapture(wind);
                InvalidateRect(wind, NULL, FALSE);
                return 0;
            }
        }
        break;

    case WM_LBUTTONUP:
        if (pressed) {
            RECT rect;
            GetClientRect(wind, &rect);
            POINT point = { (short)LOWORD(lp), (short)HIWORD(lp) };
            RECT buttonRect = getButtonRect(&rect);

            pressed = FALSE;
            ReleaseCapture();

            if (PtInRect(&buttonRect, point) && !scanning) {
                if (scanThread != NULL) {
                    InvalidateRect(wind, NULL, FALSE);
                    return 0;
                }

                if (scan_result_mutex == NULL) {
                    showScanStartError(wind);
                    return 0;
                }

                scannedFiles = 0;
                totalFiles = 0;
                maliciousFiles = 0;
                countingFiles = TRUE;
                scanStartTime = GetTickCount();
                frame = 0;

                scanThread = create_scan_thread(rootDir, logging_enabled);
                if (scanThread == NULL) {
                    scanning = FALSE;
                    countingFiles = FALSE;
                    showScanStartError(wind);
                    InvalidateRect(wind, NULL, FALSE);
                    return 0;
                }

                scanning = TRUE;
                SetTimer(wind, ID_TIMER_GUI, 60, NULL);
                SetTimer(wind, ID_TIMER_SCAN_UPDATE, 500, NULL);
            }

            InvalidateRect(wind, NULL, FALSE);
            return 0;
        }
        break;

    case WM_TIMER:
        if (wp == ID_TIMER_GUI && scanning) {
            ++frame;
            InvalidateRect(wind, NULL, FALSE);
            return 0;
        }

        if (wp == ID_TIMER_SCAN_UPDATE && scanning) {
            DWORD waitResult = WaitForSingleObject(scan_result_mutex, INFINITE);
            if (waitResult == WAIT_OBJECT_0 || waitResult == WAIT_ABANDONED) {
                scanning = scan_result.is_scanning;
                countingFiles = scan_result.is_counting_files;
                totalFiles = scan_result.n_total;
                scannedFiles = scan_result.n_scanned;

                uint64_t maliciousFilesPrev = maliciousFiles;
                maliciousFiles = scan_result.n_malicious;
                if (maliciousFiles != maliciousFilesPrev) {
                    maliciousPaths = realloc(maliciousPaths, maliciousFiles * sizeof(char *));

                    for (uint64_t i = maliciousFilesPrev; i < maliciousFiles; i++) {
                        const char *path = scan_result.malicious_infos[i].path;
                        size_t pathSize = strlen(path) + 1;
                        maliciousPaths[i] = malloc(pathSize);
                        memcpy(maliciousPaths[i], path, pathSize);
#ifdef USE_APPNOTIFICATIONS
                        send_threat_found_notification(maliciousPaths[i]);
#endif
                    }
                    InvalidateRect(wind, NULL, FALSE);
                }

                ReleaseMutex(scan_result_mutex);

                if (!scanning) {
                    KillTimer(wind, ID_TIMER_GUI);
                    KillTimer(wind, ID_TIMER_SCAN_UPDATE);
                    if (scanThread != NULL) {
                        CloseHandle(scanThread);
                        scanThread = NULL;
                    }
                    countingFiles = FALSE;
                    MessageBoxA(wind, "Scanning complete.",
                                "Hedda Defender", MB_OK | MB_ICONINFORMATION);
                    InvalidateRect(wind, NULL, FALSE);
                }
            }
            return 0;
        }
        break;

    case WM_SIZE:
        InvalidateRect(wind, NULL, FALSE);
        return 0;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(wind, &ps);
        RECT rect;
        GetClientRect(wind, &rect);

        int width = rect.right - rect.left;
        int height = rect.bottom - rect.top;
        HDC memDC = CreateCompatibleDC(hdc);
        HBITMAP backBuffer = NULL;
        HBITMAP oldBitmap = NULL;
        HDC paintDC = hdc;

        if (memDC && width > 0 && height > 0) {
            backBuffer = CreateCompatibleBitmap(hdc, width, height);
            if (backBuffer) {
                oldBitmap = (HBITMAP)SelectObject(memDC, backBuffer);
                paintDC = memDC;
            }
        }

        drawGradient(paintDC, &rect);
        drawTitle(paintDC, &rect);

        RECT maliciousRect = { rect.right - 16 - 128, rect.bottom - 16 - 64, rect.right - 16, rect.bottom - 16 };
        for (uint64_t i = 0; i < maliciousFiles; i++) {
            DrawTextA(paintDC, "Threat found:", -1, &maliciousRect, DT_TOP | DT_CENTER);
            DrawTextA(paintDC, maliciousPaths[i], -1, &maliciousRect, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
            maliciousRect.top -= 64 + 16;
            maliciousRect.bottom -= 64 + 16;
        }

        if (scanning) {
            drawScanStatus(paintDC, &rect);
        } else {
            HFONT font = CreateFontA(
                24, 0, 0, 0, FW_NORMAL,
                FALSE, FALSE, FALSE,
                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI"
            );

            if (font) {
                HFONT oldFont = (HFONT)SelectObject(paintDC, font);
                SetBkMode(paintDC, TRANSPARENT);
                SetTextColor(paintDC, RGB(85, 90, 110));

                RECT subtitleRect = { 20, 88, rect.right - 20, 120 };
                DrawTextA(paintDC, "A simple security scan for your PC", -1,
                          &subtitleRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

                SelectObject(paintDC, oldFont);
                DeleteObject(font);
            }
            drawStartButton(paintDC, &rect);
        }

        if (paintDC == memDC && backBuffer) {
            BitBlt(hdc, 0, 0, width, height, memDC, 0, 0, SRCCOPY);
            SelectObject(memDC, oldBitmap);
        }

        if (backBuffer)
            DeleteObject(backBuffer);
        if (memDC)
            DeleteDC(memDC);
        EndPaint(wind, &ps);
        return 0;
    }

    default:
        return DefWindowProcA(wind, msg, wp, lp);
    }

    return DefWindowProcA(wind, msg, wp, lp);
}

static BOOL parse_args(int argc, char **argv)
{
    const char *usage =
        "USAGE: hedda-defender.exe [options]\n"
        "\n"
        "OPTIONS:\n"
        "  -v\t\t- verbose (i.e. enable logging to stdout)\n"
        "  -r path...\t- root directory for scanning (default is 'C:')";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            LOG_PUTS(usage);
            return FALSE;
        } else if (strcmp(argv[i], "-v") == 0) {
            logging_enabled = TRUE;
        } else if (strcmp(argv[i], "-r") == 0) {
            if (++i >= argc) {
                LOG_PUTS(usage);
                return FALSE;
            }
            rootDir = argv[i];
        }
    }
    return TRUE;
}

int main(int argc, char **argv)
{
    if (!parse_args(argc, argv))
        return 1;

    if (!init_scanner()) {
        LOG_PUTS("Failed to initialize scanner.");
        return 1;
    }

#ifdef USE_APPNOTIFICATIONS
    HRESULT result = init_appnotifications(logging_enabled);
    if (!SUCCEEDED(result)) return result;
#endif

    maliciousPaths = malloc(1);

    WNDCLASSA wc = {0};
    wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "HeddaDefenderWindow";
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = windProc;

    if (!RegisterClassA(&wc)) {
        LOG_PUTS("Failed to register window class.");
        CloseHandle(scan_result_mutex);
        return 1;
    }

    HWND wind = CreateWindowExA(
        0, wc.lpszClassName, "Hedda Defender", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 900, 600,
        NULL, NULL, wc.hInstance, NULL
    );

    if (!wind) {
        LOG_PUTS("Failed to create window.");
        CloseHandle(scan_result_mutex);
        return 1;
    }

#ifdef USE_API_HOOKS
    HANDLE hookerThread = create_dynamic_hook_injector_thread(logging_enabled);
#endif

    ShowWindow(wind, SW_SHOW);
    UpdateWindow(wind);

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    if (scan_result_mutex != NULL) {
        CloseHandle(scan_result_mutex);
        scan_result_mutex = NULL;
    }

    for (uint64_t i = 0; i < maliciousFiles; i++)
        free(maliciousPaths[i]);
    free(maliciousPaths);

#ifdef USE_API_HOOKS
    free(hookerThread);
#endif
#ifdef USE_APPNOTIFICATIONS
    uninit_appnotifications();
#endif

    return (int)msg.wParam;
}

// vim: tabstop=4 shiftwidth=4 expandtab
