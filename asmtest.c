int main() {
    asm(
            "cmpl 40(%rsp), $0x40\n"
            "jz dont\n"
            "jmp *(%rip)\n"
            "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
            "dont: call *(%rip)\n"
            "nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n"
       );
}
