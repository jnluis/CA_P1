//void AES_128_Key_Expansion(const unsigned char* userkey,
// unsigned char* key_schedule);
.align 16,0x90
.globl AES_128_Key_Expansion
AES_128_Key_Expansion:
# parameter 1: %rdi
# parameter 2: %rsi
movl $10, 240(%rsi)
movdqu (%rdi), %xmm1
movdqa %xmm1, (%rsi)
ASSISTS:
aeskeygenassist $1, %xmm1, %xmm2
call PREPARE_ROUNDKEY_128
movdqa %xmm1, 16(%rsi)
aeskeygenassist $2, %xmm1, %xmm2
call PREPARE_ROUNDKEY_128
movdqa %xmm1, 32(%rsi)
aeskeygenassist $4, %xmm1, %xmm2
call PREPARE_ROUNDKEY_128
movdqa %xmm1, 48(%rsi)
aeskeygenassist $8, %xmm1, %xmm2
call PREPARE_ROUNDKEY_128
movdqa %xmm1, 64(%rsi)
aeskeygenassist $16, %xmm1, %xmm2
call PREPARE_ROUNDKEY_128
movdqa %xmm1, 80(%rsi)
aeskeygenassist $32, %xmm1, %xmm2
call PREPARE_ROUNDKEY_128
movdqa %xmm1, 96(%rsi)
aeskeygenassist $64, %xmm1, %xmm2
call PREPARE_ROUNDKEY_128
movdqa %xmm1, 112(%rsi)
aeskeygenassist $0x80, %xmm1, %xmm2
call PREPARE_ROUNDKEY_128
movdqa %xmm1, 128(%rsi)
aeskeygenassist $0x1b, %xmm1, %xmm2
call PREPARE_ROUNDKEY_128
movdqa %xmm1, 144(%rsi)
aeskeygenassist $0x36, %xmm1, %xmm2
call PREPARE_ROUNDKEY_128
movdqa %xmm1, 160(%rsi)
ret

PREPARE_ROUNDKEY_128:
pshufd $255, %xmm2, %xmm2
movdqa %xmm1, %xmm3
pslldq $4, %xmm3
pxor %xmm3, %xmm1
pslldq $4, %xmm3
pxor %xmm3, %xmm1
pslldq $4, %xmm3
pxor %xmm3, %xmm1
pxor %xmm2, %xmm1
ret
