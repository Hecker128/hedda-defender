#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <math.h>

#define ID_BUTTON 1
#define ID_TIMER  2
#define SCAN_DURATION 35000

static HWND button = NULL;
static BOOL scanning = FALSE;
static int frame = 0;
static DWORD scanStart = 0;

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

        Ellipse(hdc,
                x - dotSize / 2, y - dotSize / 2,
                x + dotSize / 2, y + dotSize / 2);

        SelectObject(hdc, oldBrush);
        SelectObject(hdc, oldPen);
        DeleteObject(brush);
    }
}

static void drawTitle(HDC hdc, const RECT *rect)
{
    HFONT titleFont = CreateFontA(
        34, 0, 0, 0, FW_BOLD,
        FALSE, FALSE, FALSE,
        DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE,
        "Segoe UI"
    );

    if (!titleFont)
        return;

    HFONT oldFont = (HFONT)SelectObject(hdc, titleFont);
    RECT titleRect = { 20, 35, rect->right - 20, 85 };

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(40, 45, 65));
    DrawTextA(hdc, "Hedda Defender", -1, &titleRect,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    SelectObject(hdc, oldFont);
    DeleteObject(titleFont);
}

static void drawScanStatus(HDC hdc, const RECT *rect)
{
    int cx = (rect->left + rect->right) / 2;
    int cy = (rect->top + rect->bottom) / 2;

    drawSpinner(hdc, cx, cy - 25, frame);

    HFONT statusFont = CreateFontA(
        20, 0, 0, 0, FW_SEMIBOLD,
        FALSE, FALSE, FALSE,
        DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE,
        "Segoe UI"
    );

    HFONT oldFont = NULL;
    if (statusFont)
        oldFont = (HFONT)SelectObject(hdc, statusFont);

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(40, 45, 65));

    RECT textRect = { cx - 140, cy + 20, cx + 140, cy + 55 };
    DrawTextA(hdc, "Scanning...", -1, &textRect,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    if (statusFont) {
        SelectObject(hdc, oldFont);
        DeleteObject(statusFont);
    }
}

static void drawOwnerButton(const DRAWITEMSTRUCT *dis)
{
    HDC hdc = dis->hDC;
    RECT r = dis->rcItem;
    COLORREF color = RGB(0, 160, 80);

    if (dis->itemState & ODS_SELECTED)
        color = RGB(0, 115, 60);
    else if (dis->itemState & ODS_HOTLIGHT)
        color = RGB(0, 185, 90);

    HBRUSH brush = CreateSolidBrush(color);
    HPEN pen = CreatePen(PS_SOLID, 1, color);

    if (brush && pen) {
        HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, brush);
        HPEN oldPen = (HPEN)SelectObject(hdc, pen);

        RoundRect(hdc, r.left, r.top, r.right, r.bottom, 12, 12);

        SelectObject(hdc, oldBrush);
        SelectObject(hdc, oldPen);
    }

    if (brush)
        DeleteObject(brush);
    if (pen)
        DeleteObject(pen);

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(255, 255, 255));

    HFONT buttonFont = CreateFontA(
        17, 0, 0, 0, FW_SEMIBOLD,
        FALSE, FALSE, FALSE,
        DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS,
        CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE,
        "Segoe UI"
    );

    HFONT oldFont = NULL;
    if (buttonFont)
        oldFont = (HFONT)SelectObject(hdc, buttonFont);

    /* Draw a white play triangle, similar to a Run button. */
    int centerY = (r.top + r.bottom) / 2;
    int triangleX = r.left + 22;
    int triangleSize = 9;

    POINT triangle[] = {
        { triangleX, centerY - triangleSize },
        { triangleX, centerY + triangleSize },
        { triangleX + triangleSize * 2, centerY }
    };

    HBRUSH whiteBrush = CreateSolidBrush(RGB(255, 255, 255));
    HPEN whitePen = CreatePen(PS_SOLID, 1, RGB(255, 255, 255));

    if (whiteBrush && whitePen) {
        HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, whiteBrush);
        HPEN oldPen = (HPEN)SelectObject(hdc, whitePen);

        Polygon(hdc, triangle, 3);

        SelectObject(hdc, oldBrush);
        SelectObject(hdc, oldPen);
    }

    if (whiteBrush)
        DeleteObject(whiteBrush);
    if (whitePen)
        DeleteObject(whitePen);

    RECT textRect = r;
    textRect.left += 42;
    DrawTextA(hdc, "Start Scan", -1, &textRect,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    if (dis->itemState & ODS_FOCUS) {
        RECT focusRect = r;
        InflateRect(&focusRect, -5, -5);
        DrawFocusRect(hdc, &focusRect);
    }

    if (buttonFont) {
        SelectObject(hdc, oldFont);
        DeleteObject(buttonFont);
    }
}

static LRESULT CALLBACK windProc(HWND wind, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CLOSE:
        DestroyWindow(wind);
        return 0;

    case WM_DESTROY:
        KillTimer(wind, ID_TIMER);
        PostQuitMessage(0);
        return 0;

    case WM_COMMAND:
        if (LOWORD(wp) == ID_BUTTON &&
            HIWORD(wp) == BN_CLICKED &&
            !scanning) {
            scanning = TRUE;
            frame = 0;
            scanStart = GetTickCount();

            ShowWindow(button, SW_HIDE);
            SetTimer(wind, ID_TIMER, 60, NULL);
            InvalidateRect(wind, NULL, TRUE);
        }
        return 0;

    case WM_TIMER:
        if (wp == ID_TIMER && scanning) {
            if (GetTickCount() - scanStart >= SCAN_DURATION) {
                scanning = FALSE;
                KillTimer(wind, ID_TIMER);
                ShowWindow(button, SW_SHOW);
                InvalidateRect(button, NULL, TRUE);
                InvalidateRect(wind, NULL, FALSE);
            } else {
                ++frame;
                InvalidateRect(wind, NULL, FALSE);
            }
        }
        return 0;

    case WM_ERASEBKGND:
        /* WM_PAINT draws the complete client area. */
        return 1;

    case WM_DRAWITEM:
        if (wp == ID_BUTTON && lp != 0) {
            drawOwnerButton((const DRAWITEMSTRUCT *)lp);
            return TRUE;
        }
        break;

    case WM_SIZE: {
        int width = LOWORD(lp);
        int height = HIWORD(lp);
        int buttonWidth = width / 4;
        int buttonHeight = height / 10;

        if (buttonWidth < 160)
            buttonWidth = 160;
        if (buttonHeight < 46)
            buttonHeight = 46;
        if (buttonWidth > width)
            buttonWidth = width;
        if (buttonHeight > height)
            buttonHeight = height;

        int x = (width - buttonWidth) / 2;
        int y = height / 2 + 65;
        if (y + buttonHeight > height)
            y = height - buttonHeight;
        if (y < 0)
            y = 0;

        if (button)
            MoveWindow(button, x, y, buttonWidth, buttonHeight, TRUE);

        InvalidateRect(wind, NULL, FALSE);
        return 0;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(wind, &ps);
        RECT rect;

        GetClientRect(wind, &rect);
        drawGradient(hdc, &rect);
        drawTitle(hdc, &rect);

        if (scanning) {
            drawScanStatus(hdc, &rect);
        } else {
            HFONT font = CreateFontA(
                16, 0, 0, 0, FW_NORMAL,
                FALSE, FALSE, FALSE,
                DEFAULT_CHARSET,
                OUT_DEFAULT_PRECIS,
                CLIP_DEFAULT_PRECIS,
                CLEARTYPE_QUALITY,
                DEFAULT_PITCH | FF_DONTCARE,
                "Segoe UI"
            );

            HFONT oldFont = NULL;
            if (font)
                oldFont = (HFONT)SelectObject(hdc, font);

            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(85, 90, 110));

            RECT subtitleRect = { 20, 88, rect.right - 20, 120 };
            DrawTextA(hdc, "A simple security scan for your PC", -1,
                      &subtitleRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

            if (font) {
                SelectObject(hdc, oldFont);
                DeleteObject(font);
            }
        }

        EndPaint(wind, &ps);
        return 0;
    }

    default:
        return DefWindowProcA(wind, msg, wp, lp);
    }

    return DefWindowProcA(wind, msg, wp, lp);
}

int main(void)
{
    WNDCLASSA wc = {0};

    wc.hCursor = LoadCursorA(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "HeddaDefenderWindow";
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = windProc;

    if (!RegisterClassA(&wc))
        return 1;

    HWND wind = CreateWindowExA(
        0,
        wc.lpszClassName,
        "Hedda Defender",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        900, 600,
        NULL, NULL,
        wc.hInstance,
        NULL
    );

    if (!wind)
        return 1;

    button = CreateWindowExA(
        0,
        "Button",
        "Start Scan",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
        0, 0, 160, 46,
        wind,
        (HMENU)(INT_PTR)ID_BUTTON,
        wc.hInstance,
        NULL
    );

    if (!button) {
        DestroyWindow(wind);
        return 1;
    }

    ShowWindow(wind, SW_SHOW);
    UpdateWindow(wind);

    RECT rect;
    GetClientRect(wind, &rect);
    SendMessageA(wind, WM_SIZE, 0, MAKELPARAM(rect.right, rect.bottom));

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    return (int)msg.wParam;
}
