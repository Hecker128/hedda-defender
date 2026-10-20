#include <windows.h>
#include <winuser.h>

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
            windowAnti.running = FALSE;
        break;

        default:
            rez = DefWindowProc(wind, msg, wp, lp);
        break;
    }
    return rez;
}

int main() {
    WNDCLASS wc = {sizeof(WNDCLASS)};

    wc.hCursor = LoadCursor(0, IDC_ARROW);
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

    while (windowAnti.running) {
        MSG msg = {};
        while (PeekMessage(&msg, wind, 0, 0, PM_REMOVE) > 0) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);

        }
    }
}
