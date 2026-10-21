#include <windows.h>
#include <winuser.h>
#include <uxtheme.h>
#include <math.h>
#define ID_BUTTON 1
#define ID_TIMER 2
HWND button = NULL;
BOOL scanning = FALSE;
int frame = 0;

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
            windowAnti.running = FALSE;
            PostQuitMessage(0);
            return 0;
        case WM_COMMAND:
            if (LOWORD(wp) == ID_BUTTON && HIWORD(wp) == BN_CLICKED && !scanning) {
                scanning = TRUE;
                frame = 0;
                EnableWindow(button, FALSE);
                SetWindowText(button, "Scanning...");
                SetTimer(wind, ID_TIMER, 60, NULL);
                InvalidateRect(wind, NULL, TRUE);
            }
        break;
        case WM_TIMER:
            if (wp == ID_TIMER && scanning) {
                frame++;
                InvalidateRect(wind, NULL, FALSE);
            }
            return 0;
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

            FillRect(
                hdc,
                &rect,
                (HBRUSH)(COLOR_WINDOW + 1)
            );

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
    WNDCLASS wc = {sizeof(WNDCLASS)};

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
        "Scan System",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        0, 0, 120, 35,
        wind,
        (HMENU)(INT_PTR)ID_BUTTON,
        GetModuleHandle(NULL),
        NULL
    );

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
