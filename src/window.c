#include <windows.h>
#include <winuser.h>
#define ID_BUTTON 1

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
            windowAnti.running = FALSE;
            PostQuitMessage(0);
            break;
        case WM_COMMAND:
            if (LOWORD(wp) == ID_BUTTON){
                MessageBoxA(wind, "System scan started!",
                            "Hedda Defender", MB_OK | MB_ICONINFORMATION);
            }
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

    HWND button = CreateWindowExA(
        0,
        "Button",
        "Scan System",
        WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        20, 20, 120, 35,
        wind,
        (HMENU)(INT_PTR)ID_BUTTON,
        GetModuleHandle(0),
        NULL
    );

    while (windowAnti.running) {
        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0) > 0 ){
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
}
