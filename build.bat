clang src\gui.c -o bin\hedda-defender.exe -Wall -Wextra -Werror=return-type -fsanitize=address -luser32 -lgdi32 -lcomctl32 -lmsi -ladvapi32 -lcrypt32
