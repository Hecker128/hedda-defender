#include <windows.h>
#include <winuser.h>
#include <commctrl.h>
#include <math.h>

#define ID_BUTTON 1
#define ID_TIMER 2
#define IDLE_ID_TIMER 3
#define IDLE_SAVER_TIME 4
#define SCAN_DURATION 35000
HWND button = NULL;
BOOL scanning = FALSE;
int frame = 0;
DWORD scanStart = 0;
DWORD lastActivity = 0;
DWORD saverStart = 0;

BOOL screensaver = FALSE;

int dvdX = 40, dvdY = 40;
int dvdDX = 3, dvdDY = 3;
int dvdWidth = 90, dvdHeight = 45;

void drawDVD(HDC hdc)
{
    RECT r = {
        dvdX, dvdY,
        dvdX + dvdWidth, dvdY + dvdHeight
    };

    HBRUSH brush = CreateSolidBrush(RGB(255, 255, 255));
    HPEN pen = CreatePen(PS_SOLID, 3, RGB(40, 100, 255));

    HBRUSH oldBrush = SelectObject(hdc, brush);
    HPEN oldPen = SelectObject(hdc, pen);

    RoundRect(hdc, r.left, r.top, r.right, r.bottom, 18, 18);

    SelectObject(hdc, oldBrush);
    SelectObject(hdc, oldPen);

    DeleteObject(brush);
    DeleteObject(pen);

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(30, 80, 220));

    DrawTextA(hdc, "DVD", -1, &r,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

void resetScreensaver(HWND wind) {
    screensaver = FALSE;
    KillTimer(wind, IDLE_SAVER_TIME);
    dvdX = 40;
    dvdY = 40;
    dvdDX = 3;
    dvdDY = 3;
    lastActivity = GetTickCount();
    ShowWindow(button, SW_SHOW);
    InvalidateRect(wind, NULL, TRUE);
}

void drawGradient(HDC hdc, RECT rect) {
    int height = rect.bottom - rect.top;
    int width = rect.right - rect.left;

    for (int y = 0; y < height; y++) {
        double t = (double)y / (height > 1 ? height - 1: 1);
        int r = (int)(255 - 8 * t);
        int g = (int)(240 - 25 * t);
        int b = (int)(247 - 10 * t);
        HPEN pen = CreatePen(
            PS_SOLID, 1, RGB(r, g, b)
        );
        HPEN oldPen = SelectObject(hdc, pen);
        MoveToEx(hdc, rect.left, rect.top + y, NULL);
        LineTo(hdc, rect.left + width, rect.top + y);
        SelectObject(hdc, oldPen);
        DeleteObject(pen);
    }
}

void drawSpinner(HDC hdc, int cx, int cy, int frame) {
    const int dots = 12;
    const int radius = 24;
    const int dotSize = 7;

    for (int i = 0; i < dots; i++) {
        double angle = (i + frame) * 6.28318530718 / dots;
        int x = cx + (int)(cos(angle) * radius);
        int y = cy + (int)(sin(angle) * radius);
        int brightness = 70 + i * 185 / dots;
        HBRUSH brush = CreateSolidBrush(RGB(40, brightness, 255));
        HBRUSH oldBrush = SelectObject(hdc, brush);
        HPEN oldPen = SelectObject(hdc, GetStockObject(NULL_PEN));
        Ellipse(
            hdc,
            x - dotSize / 2, y - dotSize / 2,
            x + dotSize / 2, y + dotSize / 2
        );
        SelectObject(hdc, oldBrush);
        SelectObject(hdc, oldPen);
        DeleteObject(brush);
    }
}

typedef struct {
    BOOL running;
}WindowAnti;

WindowAnti windowAnti = {
    .running = TRUE
};

LRESULT windProc(HWND wind, UINT msg, WPARAM wp, LPARAM lp)  {

    LRESULT rez = 0;

    switch (msg) {
        case WM_CLOSE:
            DestroyWindow(wind);
            break;

        case WM_DESTROY:
            KillTimer(wind, ID_TIMER);
            KillTimer(wind, IDLE_ID_TIMER);
            KillTimer(wind, IDLE_SAVER_TIME);
            windowAnti.running = FALSE;
            PostQuitMessage(0);
            return 0;
        case WM_COMMAND:
            lastActivity = GetTickCount();
            if (LOWORD(wp) == ID_BUTTON && HIWORD(wp) == BN_CLICKED && !scanning) {
                scanning = TRUE;
                frame = 0;
                scanStart = GetTickCount();
                ShowWindow(button, SW_HIDE);
                SetTimer(wind, ID_TIMER, 60, NULL);
                InvalidateRect(wind, NULL, TRUE);
            }
        break;
        case WM_TIMER:
            if (wp == ID_TIMER && scanning) {
                if (GetTickCount() - scanStart >= SCAN_DURATION) {
                    scanning = FALSE;
                    KillTimer(wind, ID_TIMER);
                    ShowWindow(button, SW_SHOW);
                    SetWindowTextA(button, "Start");
                    InvalidateRect(wind, NULL, TRUE);
                } else {
                    frame++;
                    InvalidateRect(wind, NULL, FALSE);
                }
                return 0;
            }

            if (wp == IDLE_ID_TIMER) {
                if (!screensaver &&
                    !scanning &&
                    GetTickCount() - lastActivity >= 45000) {

                    screensaver = TRUE;
                saverStart = GetTickCount();

                dvdX = 40;
                dvdY = 40;
                dvdDX = 3;
                dvdDY = 3;

                ShowWindow(button, SW_HIDE);
                SetTimer(wind, IDLE_SAVER_TIME, 16, NULL);
                InvalidateRect(wind, NULL, TRUE);
                    }
                    return 0;
            }

            if (wp == IDLE_SAVER_TIME && screensaver) {
                DWORD elapsed = GetTickCount() - saverStart;
                int speed = elapsed >= 10000 ? 6 : 3;

                RECT r;
                GetClientRect(wind, &r);

                dvdX += dvdDX < 0 ? -speed : speed;
                dvdY += dvdDY < 0 ? -speed : speed;

                if (dvdX <= 0 || dvdX + dvdWidth >= r.right)
                    dvdDX = -dvdDX;
                if (dvdY <= 0 || dvdY + dvdHeight >= r.bottom)
                    dvdDY = -dvdDY;
                if (dvdX < 0) dvdX = 0;
                if (dvdY < 0) dvdY = 0;
                if (r.right < dvdWidth)
                    dvdX = 0;
                else if (dvdX + dvdWidth > r.right)
                    dvdX = r.right - dvdWidth;
                if (r.bottom < dvdHeight)
                    dvdY = 0;
                else if (dvdY + dvdHeight > r.bottom)
                    dvdY = r.bottom - dvdHeight;
                InvalidateRect(wind, NULL, TRUE);
                return 0;
            }
            return 0;
        case WM_ACTIVATE:
            if (LOWORD(wp) != WA_INACTIVE && screensaver) {
                resetScreensaver(wind);
            }
            return 0;

        case WM_MOUSEMOVE:
        case WM_KEYDOWN:
        case WM_LBUTTONDOWN:
        case WM_RBUTTONDOWN:
            if (screensaver) {
                resetScreensaver(wind);
            } else {
                lastActivity = GetTickCount();
            }
        break;
        case WM_DRAWITEM: {
            LPDRAWITEMSTRUCT dis = (LPDRAWITEMSTRUCT)lp;

            if (dis->CtlID == ID_BUTTON) {
                HDC hdc = dis->hDC;
                RECT r = dis->rcItem;

                HBRUSH brush = CreateSolidBrush(RGB(0, 160, 80));
                FillRect(hdc, &r, brush);
                DeleteObject(brush);

                SetBkMode(hdc, TRANSPARENT);
                SetTextColor(hdc, RGB(255, 255, 255));

                DrawTextA(
                    hdc,
                    scanning ? "Scanning..." : "Start",
                    -1,
                    &r,
                    DT_CENTER | DT_VCENTER | DT_SINGLELINE
                );

                return TRUE;
            }
            break;
        }
        case WM_SIZE: {
            int width = LOWORD(lp);
            int height = HIWORD(lp);
            int buttonWidth = width / 4;
            int buttonHeight = height / 10;

            if (buttonWidth < 120) buttonWidth = 120;
            if (buttonHeight < 35) buttonHeight = 35;

            if (buttonWidth > width) buttonWidth = width;
            if (buttonHeight > height) buttonHeight = height;

            int x = (width - buttonWidth) / 2;
            int y = (height - buttonHeight) / 2;


            if (button != NULL) {
                MoveWindow(
                    button,
                    x, y,
                    buttonWidth, buttonHeight,
                    TRUE
                );
            }
            return 0;
        }
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(wind, &ps);

            RECT rect;
            GetClientRect(wind, &rect);

            drawGradient(hdc, rect);

            if (screensaver) {
                drawDVD(hdc);
            }

            if (scanning) {
                int cx = (rect.left + rect.right) / 2;
                int cy = (rect.top + rect.bottom) / 2;

                drawSpinner(hdc, cx, cy - 25, frame);

                RECT textRect = {
                    cx - 100, cy + 20,
                    cx + 100, cy + 55
                };

                SetBkMode(hdc, TRANSPARENT);

                DrawTextA(
                    hdc,
                    "Scanning...",
                    -1,
                    &textRect,
                    DT_CENTER | DT_VCENTER | DT_SINGLELINE
                );
            }

            EndPaint(wind, &ps);
            return 0;
        }
        default:
            rez = DefWindowProc(wind, msg, wp, lp);
        break;
    }
    return rez;
}

int main() {
    INITCOMMONCONTROLSEX icc = {
        sizeof(INITCOMMONCONTROLSEX),
        ICC_STANDARD_CLASSES
    };
    InitCommonControlsEx(&icc);
    WNDCLASS wc = {0};

    wc.hCursor = LoadCursor(0, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hInstance = GetModuleHandle(0);
    wc.lpszClassName = "Venus";
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = windProc;

    if (!RegisterClass(&wc)) { return 0; };

    HWND wind = CreateWindowExA(
        0,
        wc.lpszClassName,
        "Hedda Defender",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        0, 0, GetModuleHandle(0),0
    );

    if (wind == NULL) {
        return 1;
    }

    button = CreateWindowExA(
        0,
        "Button",
        "Start",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
        0, 0, 120, 35,
        wind,
        (HMENU)(INT_PTR)ID_BUTTON,
        GetModuleHandle(NULL),
        NULL
    );

    lastActivity = GetTickCount();
    SetTimer(wind, IDLE_ID_TIMER, 500, NULL);

    RECT rect;
    GetClientRect(wind, &rect);

    SendMessage(
        wind,
        WM_SIZE,
        0,
        MAKELPARAM(
            rect.right - rect.left,
            rect.bottom - rect.top
        )
    );

    MSG msg;

    while (GetMessage(&msg, NULL, 0, 0) > 0 ){
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}
