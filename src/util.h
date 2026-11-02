#pragma once

#include <stdint.h>
#include <stdio.h>
#include <windows.h>

/// Macros for using I/O functions conditionally based on logging_enabled,
/// which should be defined locally or per-file (so different threads don't
/// access the same logging_enabled).
#define LOG_PUTS(msg) if (logging_enabled) { puts(msg); }
#define LOG_PRINTF(fmt, ...) if (logging_enabled) { printf(fmt __VA_OPT__(,) __VA_ARGS__); }
#define LOG_PUTCHAR(msg) if (logging_enabled) { putchar(msg); }
#define LOG_PRINT_WIN_ERR(err, fmt, ...) if (logging_enabled) { print_win_err(err, fmt __VA_OPT__(,) __VA_ARGS__); }
#define LOG_PRINT_HRESULT(result, fmt, ...) (logging_enabled ? print_hresult(result, fmt __VA_OPT__(,) __VA_ARGS__) : result)
#define LOG_PRINT_HEX_DELTA(a, b, size) if (logging_enabled) { print_hex_delta(a, b, size); }

void print_win_err(uint32_t err, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
HRESULT print_hresult(HRESULT result, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void print_hex_delta(const uint8_t *a, const uint8_t *b, size_t size);
