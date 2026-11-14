    .text
    .globl _resolved_impl
_resolved_impl:
    movl $42, %eax
    ret
    .globl _resolved
    .symbol_resolver _resolved
    leaq _resolved_impl(%rip), %rax
    ret
