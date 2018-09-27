/*
 *    Stack-less Just-In-Time compiler
 *
 *    Copyright Zoltan Herczeg (hzmester@freemail.hu). All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 *   1. Redistributions of source code must retain the above copyright notice, this list of
 *      conditions and the following disclaimer.
 *
 *   2. Redistributions in binary form must reproduce the above copyright notice, this list
 *      of conditions and the following disclaimer in the documentation and/or other materials
 *      provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER(S) AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE COPYRIGHT HOLDER(S) OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

SLJIT_API_FUNC_ATTRIBUTE const char* sljit_get_platform_name(void)
{
	return "s390x" SLJIT_CPUINFO;
}

typedef sljit_uw sljit_ins; // instruction
typedef sljit_uw sljit_gpr; // general purpose register [0-15]
typedef sljit_uw sljit_fpr; // floating-point register [0-15]

// general purpose registers
const sljit_gpr r0 = 0; // 0 in address calculations; reserved
const sljit_gpr r1 = 1; // reserved
const sljit_gpr r2 = 2; // 1st argument
const sljit_gpr r3 = 3; // 2nd argument
const sljit_gpr r4 = 4; // 3rd argument
const sljit_gpr r5 = 5; // 4th argument
const sljit_gpr r6 = 6; // 5th argument; 1st saved register
const sljit_gpr r7 = 7;
const sljit_gpr r8 = 8;
const sljit_gpr r9 = 9;
const sljit_gpr r10 = 10;
const sljit_gpr r11 = 11;
const sljit_gpr r12 = 12;
const sljit_gpr r13 = 13;
const sljit_gpr r14 = 14; // return address
const sljit_gpr r15 = 15; // stack pointer

static const sljit_gpr reg_map[SLJIT_NUMBER_OF_REGISTERS + 1] = {
	2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15
};

static sljit_gpr gpr(sljit_s32 r)
{
	SLJIT_ASSERT(r != SLJIT_UNUSED);
	r -= SLJIT_R0; // normalize
	SLJIT_ASSERT(r < (sizeof(reg_map) / sizeof(reg_map[0])));
	return reg_map[r];
}

static sljit_uw sizeof_ins(sljit_ins ins)
{
	if (ins == 0) return 2; // keep faulting instructions
	if ((ins&0x00000000ffff) == ins) return 2;
	if ((ins&0x0000ffffffff) == ins) return 4;
	if ((ins&0xffffffffffff) == ins) return 6;
	abort();
}

static sljit_s32 push_inst(struct sljit_compiler *compiler, sljit_ins ins)
{
	sljit_ins *ibuf = (sljit_ins *)ensure_buf(compiler, sizeof(sljit_ins));
	FAIL_IF(!ibuf);
	*ibuf = ins;
	compiler->size++;
	return SLJIT_SUCCESS;
}

static sljit_s32 encode_inst(void **ptr, sljit_ins ins)
{
	sljit_u16 *ibuf = (sljit_u16 *)*ptr;
	sljit_uw size = sizeof_ins(ins);
	SLJIT_ASSERT((size&6) == size);
	switch (size) {
	case 6: *ibuf++ = (sljit_u16)(ins >> 32);
	case 4: *ibuf++ = (sljit_u16)(ins >> 16);
	case 2: *ibuf++ = (sljit_u16)(ins);
	}
	*ptr = (void*)ibuf;
	return SLJIT_SUCCESS;
}

#define SLJIT_S390X_INSTRUCTION(op, ...) \
static sljit_ins op(__VA_ARGS__)

static sljit_uw disp_s20(sljit_s32 d)
{
	if (d >> 20 != 0 && d >> 20 != -1) {
		abort(); // out of range
	}
	sljit_uw dh = (d >> 12) & 0xff;
	sljit_uw dl = (d << 8) & 0xfff00;
	return dh | dl;
}

SLJIT_S390X_INSTRUCTION(lgr, sljit_gpr dst, sljit_gpr src)
{
	return 0xb9040000 | dst << 4 | src;
}

SLJIT_S390X_INSTRUCTION(lghi, sljit_gpr dst, sljit_s16 imm)
{
	return 0xa7090000 | dst << 20 | (imm&0xffff);
}

SLJIT_S390X_INSTRUCTION(aghi, sljit_gpr dst, sljit_s16 imm)
{
	return 0xa70b0000 | dst << 20 | (imm&0xffff);
}

SLJIT_S390X_INSTRUCTION(stmg, sljit_gpr start, sljit_gpr end, sljit_s32 d, sljit_gpr b)
{
	return 0xeb0000000024 | start << 36 | end << 32 | b << 28 | disp_s20(d) << 8;
}

SLJIT_S390X_INSTRUCTION(lmg, sljit_gpr start, sljit_gpr end, sljit_s32 d, sljit_gpr b)
{
	return 0xeb0000000004 | start << 36 | end << 32 | b << 28 | disp_s20(d) << 8;
}

SLJIT_S390X_INSTRUCTION(br, sljit_gpr target)
{
	return 0x07f0 | target;
}

#undef SLJIT_S390X_INSTRUCTION

SLJIT_API_FUNC_ATTRIBUTE void* sljit_generate_code(struct sljit_compiler *compiler)
{
	CHECK_ERROR_PTR();
	// TODO(mundaym): re-enable checks
	//CHECK_PTR(check_sljit_generate_code(compiler));

	// calculate the size of the code
	sljit_uw ins_size = 0;
	for (struct sljit_memory_fragment *buf = compiler->buf; buf != NULL; buf = buf->next) {
		sljit_uw len = buf->used_size / sizeof(sljit_ins);
		sljit_ins *ibuf = (sljit_ins *)buf->memory;
		for (sljit_uw i = 0; i < len; ++i) {
			// TODO(mundaym): labels, jumps, constants...
			ins_size += sizeof_ins(ibuf[i]);
		}
	}

	// allocate target buffer
	void *code = SLJIT_MALLOC_EXEC(ins_size);
	PTR_FAIL_WITH_EXEC_IF(code);
	void *code_ptr = code;

	// emit the code
	for (struct sljit_memory_fragment *buf = compiler->buf; buf != NULL; buf = buf->next) {
		sljit_uw len = buf->used_size / sizeof(sljit_ins);
		sljit_ins *ibuf = (sljit_ins *)buf->memory;
		for (sljit_uw i = 0; i < len; ++i) {
			// TODO(mundaym): labels, jumps, constants...
			encode_inst(&code_ptr, ibuf[i]);
		}
	}
	SLJIT_ASSERT(code + ins_size == code_ptr);

	compiler->error = SLJIT_ERR_COMPILED;
	compiler->executable_offset = SLJIT_EXEC_OFFSET(code);
	compiler->executable_size = ins_size;

	code = SLJIT_ADD_EXEC_OFFSET(code, executable_offset);
	code_ptr = SLJIT_ADD_EXEC_OFFSET(code_ptr, executable_offset);
	SLJIT_CACHE_FLUSH(code, code_ptr);
#if 0
	reverse_buf(compiler);

	code = (sljit_ins*)SLJIT_MALLOC_EXEC(compiler->size * sizeof(sljit_ins));
	PTR_FAIL_WITH_EXEC_IF(code);
	buf = compiler->buf;

	code_ptr = code;
	word_count = 0;
	executable_offset = SLJIT_EXEC_OFFSET(code);

	label = compiler->labels;
	jump = compiler->jumps;
	const_ = compiler->consts;

	do {
		buf_ptr = (sljit_ins*)buf->memory;
		buf_end = buf_ptr + (buf->used_size >> 2);
		do {
			*code_ptr = *buf_ptr++;
			/* These structures are ordered by their address. */
			SLJIT_ASSERT(!label || label->size >= word_count);
			SLJIT_ASSERT(!jump || jump->addr >= word_count);
			SLJIT_ASSERT(!const_ || const_->addr >= word_count);
			if (label && label->size == word_count) {
				label->addr = (sljit_uw)SLJIT_ADD_EXEC_OFFSET(code_ptr, executable_offset);
	SLJIT_CACHE_FLUSH(code, code_ptr)
				label->size = code_ptr - code;
				label = label->next;
			}
			if (jump && jump->addr == word_count) {
					jump->addr = (sljit_uw)(code_ptr - 4);
					code_ptr -= detect_jump_type(jump, code_ptr, code, executable_offset);
					jump = jump->next;
			}
			if (const_ && const_->addr == word_count) {
				const_->addr = (sljit_uw)code_ptr;
				const_ = const_->next;
			}
			code_ptr ++;
			word_count ++;
		} while (buf_ptr < buf_end);

		buf = buf->next;
	} while (buf);

	if (label && label->size == word_count) {
		label->addr = (sljit_uw)SLJIT_ADD_EXEC_OFFSET(code_ptr, executable_offset);
		label->size = code_ptr - code;
		label = label->next;
	}

	SLJIT_ASSERT(!label);
	SLJIT_ASSERT(!jump);
	SLJIT_ASSERT(!const_);
	SLJIT_ASSERT(code_ptr - code <= (sljit_sw)compiler->size);

	jump = compiler->jumps;
	while (jump) {
		do {
			addr = (jump->flags & JUMP_LABEL) ? jump->u.label->addr : jump->u.target;
			buf_ptr = (sljit_ins *)jump->addr;

			if (jump->flags & PATCH_B) {
				addr = (sljit_sw)(addr - (sljit_uw)SLJIT_ADD_EXEC_OFFSET(buf_ptr, executable_offset)) >> 2;
				SLJIT_ASSERT((sljit_sw)addr <= 0x1ffffff && (sljit_sw)addr >= -0x2000000);
				buf_ptr[0] = ((jump->flags & IS_BL) ? BL : B) | (addr & 0x3ffffff);
				if (jump->flags & IS_COND)
					buf_ptr[-1] -= (4 << 5);
				break;
			}
			if (jump->flags & PATCH_COND) {
				addr = (sljit_sw)(addr - (sljit_uw)SLJIT_ADD_EXEC_OFFSET(buf_ptr, executable_offset)) >> 2;
				SLJIT_ASSERT((sljit_sw)addr <= 0x3ffff && (sljit_sw)addr >= -0x40000);
				buf_ptr[0] = (buf_ptr[0] & ~0xffffe0) | ((addr & 0x7ffff) << 5);
				break;
			}

			SLJIT_ASSERT((jump->flags & (PATCH_ABS48 | PATCH_ABS64)) || addr <= 0xffffffffl);
			SLJIT_ASSERT((jump->flags & PATCH_ABS64) || addr <= 0xffffffffffffl);

			dst = buf_ptr[0] & 0x1f;
			buf_ptr[0] = MOVZ | dst | ((addr & 0xffff) << 5);
			buf_ptr[1] = MOVK | dst | (((addr >> 16) & 0xffff) << 5) | (1 << 21);
			if (jump->flags & (PATCH_ABS48 | PATCH_ABS64))
				buf_ptr[2] = MOVK | dst | (((addr >> 32) & 0xffff) << 5) | (2 << 21);
			if (jump->flags & PATCH_ABS64)
				buf_ptr[3] = MOVK | dst | (((addr >> 48) & 0xffff) << 5) | (3 << 21);
		} while (0);
		jump = jump->next;
	}

	compiler->error = SLJIT_ERR_COMPILED;
	compiler->executable_offset = executable_offset;
	compiler->executable_size = (code_ptr - code) * sizeof(sljit_ins);

	code = (sljit_ins *)SLJIT_ADD_EXEC_OFFSET(code, executable_offset);
	code_ptr = (sljit_ins *)SLJIT_ADD_EXEC_OFFSET(code_ptr, executable_offset);
#endif
	SLJIT_CACHE_FLUSH(code, code_ptr);
	return code;
}

SLJIT_API_FUNC_ATTRIBUTE sljit_s32 sljit_has_cpu_feature(sljit_s32 feature_type)
{
	abort();
}

/* --------------------------------------------------------------------- */
/*  Entry, exit                                                          */
/* --------------------------------------------------------------------- */

SLJIT_API_FUNC_ATTRIBUTE sljit_s32 sljit_emit_enter(struct sljit_compiler *compiler,
	sljit_s32 options, sljit_s32 arg_types, sljit_s32 scratches, sljit_s32 saveds,
	sljit_s32 fscratches, sljit_s32 fsaveds, sljit_s32 local_size)
{
	sljit_s32 args, i, tmp, offs, prev, saved_regs_size;

	CHECK_ERROR();
	CHECK(check_sljit_emit_enter(compiler, options, arg_types, scratches, saveds, fscratches, fsaveds, local_size));
	set_emit_enter(compiler, options, arg_types, scratches, saveds, fscratches, fsaveds, local_size);

	// saved registers go in callee allocated save area
	compiler->local_size = (local_size+0xf)&~0xf;

	FAIL_IF(push_inst(compiler, stmg(r6, r15, 48, r15))); // save registers TODO(MGM): optimize
	if (local_size != 0)
		FAIL_IF(push_inst(compiler, aghi(r15, -((sljit_s16)local_size))));

	args = get_arg_count(arg_types);

	if (args >= 1)
		FAIL_IF(push_inst(compiler, lgr(gpr(SLJIT_S0), gpr(SLJIT_R0))));
	if (args >= 2)
		FAIL_IF(push_inst(compiler, lgr(gpr(SLJIT_S1), gpr(SLJIT_R1))));
	if (args >= 3)
		FAIL_IF(push_inst(compiler, lgr(gpr(SLJIT_S2), gpr(SLJIT_R2))));
	SLJIT_ASSERT(args < 4);

	return SLJIT_SUCCESS;
}

SLJIT_API_FUNC_ATTRIBUTE sljit_s32 sljit_set_context(struct sljit_compiler *compiler,
	sljit_s32 options, sljit_s32 arg_types, sljit_s32 scratches, sljit_s32 saveds,
	sljit_s32 fscratches, sljit_s32 fsaveds, sljit_s32 local_size)
{
	abort();
}

SLJIT_API_FUNC_ATTRIBUTE sljit_s32 sljit_emit_return(struct sljit_compiler *compiler, sljit_s32 op, sljit_s32 src, sljit_sw srcw)
{
	sljit_s32 local_size;
	sljit_s32 i, tmp, offs, prev, saved_regs_size;

	CHECK_ERROR();
	CHECK(check_sljit_emit_return(compiler, op, src, srcw));

	FAIL_IF(emit_mov_before_return(compiler, op, src, srcw));

	FAIL_IF(push_inst(compiler, lmg(r6, r15, 48 + compiler->local_size, r15))); // restore registers TODO(MGM): optimize
	FAIL_IF(push_inst(compiler, br(r14))); // return

	return SLJIT_SUCCESS;
}

/* --------------------------------------------------------------------- */
/*  Operators                                                            */
/* --------------------------------------------------------------------- */

SLJIT_API_FUNC_ATTRIBUTE sljit_s32 sljit_emit_op0(struct sljit_compiler *compiler, sljit_s32 op)
{
	abort();
}

SLJIT_API_FUNC_ATTRIBUTE sljit_s32 sljit_emit_op1(struct sljit_compiler *compiler, sljit_s32 op,
        sljit_s32 dst, sljit_sw dstw,
        sljit_s32 src, sljit_sw srcw)
{
	sljit_s32 dst_r, flags, mem_flags;
	sljit_s32 op_flags = GET_ALL_FLAGS(op);

	CHECK_ERROR();
	CHECK(check_sljit_emit_op1(compiler, op, dst, dstw, src, srcw));
	//TODO(mundaym): re-enable
	//ADJUST_LOCAL_OFFSET(dst, dstw);
	//ADJUST_LOCAL_OFFSET(src, srcw);

	if (dst == SLJIT_UNUSED && !HAS_FLAGS(op)) {
		// TODO(mundaym): prefetch
		abort();
	}

	op = GET_OPCODE(op);
	if (op >= SLJIT_MOV && op <= SLJIT_MOV_P) {
		/* Both operands are registers. */
		if (FAST_IS_REG(src) && FAST_IS_REG(dst)) {
			// TODO(mundaym): sign/zero extension
			return push_inst(compiler, lgr(gpr(dst), gpr(src)));
		}
		abort();
	}
	abort();
}

SLJIT_API_FUNC_ATTRIBUTE sljit_s32 sljit_emit_op2(struct sljit_compiler *compiler, sljit_s32 op,
	sljit_s32 dst, sljit_sw dstw,
	sljit_s32 src1, sljit_sw src1w,
	sljit_s32 src2, sljit_sw src2w)
{
	abort();
}

SLJIT_API_FUNC_ATTRIBUTE sljit_s32 sljit_get_register_index(sljit_s32 reg)
{
	abort();
}

SLJIT_API_FUNC_ATTRIBUTE sljit_s32 sljit_get_float_register_index(sljit_s32 reg)
{
	abort();
}

SLJIT_API_FUNC_ATTRIBUTE sljit_s32 sljit_emit_op_custom(struct sljit_compiler *compiler,
	void *instruction, sljit_s32 size)
{
	abort();
}

/* --------------------------------------------------------------------- */
/*  Floating point operators                                             */
/* --------------------------------------------------------------------- */

SLJIT_API_FUNC_ATTRIBUTE sljit_s32 sljit_emit_fop1(struct sljit_compiler *compiler, sljit_s32 op,
	sljit_s32 dst, sljit_sw dstw,
	sljit_s32 src, sljit_sw srcw)
{
	abort();
}

SLJIT_API_FUNC_ATTRIBUTE sljit_s32 sljit_emit_fop2(struct sljit_compiler *compiler, sljit_s32 op,
	sljit_s32 dst, sljit_sw dstw,
	sljit_s32 src1, sljit_sw src1w,
	sljit_s32 src2, sljit_sw src2w)
{
	abort();
}

/* --------------------------------------------------------------------- */
/*  Other instructions                                                   */
/* --------------------------------------------------------------------- */

SLJIT_API_FUNC_ATTRIBUTE sljit_s32 sljit_emit_fast_enter(struct sljit_compiler *compiler, sljit_s32 dst, sljit_sw dstw)
{
	abort();
}

SLJIT_API_FUNC_ATTRIBUTE sljit_s32 sljit_emit_fast_return(struct sljit_compiler *compiler, sljit_s32 src, sljit_sw srcw)
{
	abort();
}

/* --------------------------------------------------------------------- */
/*  Conditional instructions                                             */
/* --------------------------------------------------------------------- */

SLJIT_API_FUNC_ATTRIBUTE struct sljit_label* sljit_emit_label(struct sljit_compiler *compiler)
{
	abort();
}

SLJIT_API_FUNC_ATTRIBUTE struct sljit_jump* sljit_emit_jump(struct sljit_compiler *compiler, sljit_s32 type)
{
	abort();
}

SLJIT_API_FUNC_ATTRIBUTE struct sljit_jump* sljit_emit_call(struct sljit_compiler *compiler, sljit_s32 type,
	sljit_s32 arg_types)
{
	abort();
}

SLJIT_API_FUNC_ATTRIBUTE sljit_s32 sljit_emit_ijump(struct sljit_compiler *compiler, sljit_s32 type, sljit_s32 src, sljit_sw srcw)
{
	abort();
}

SLJIT_API_FUNC_ATTRIBUTE sljit_s32 sljit_emit_icall(struct sljit_compiler *compiler, sljit_s32 type,
	sljit_s32 arg_types,
	sljit_s32 src, sljit_sw srcw)
{
	abort();
}

SLJIT_API_FUNC_ATTRIBUTE sljit_s32 sljit_emit_op_flags(struct sljit_compiler *compiler, sljit_s32 op,
	sljit_s32 dst, sljit_sw dstw,
	sljit_s32 type)
{
	abort();
}

SLJIT_API_FUNC_ATTRIBUTE sljit_s32 sljit_emit_cmov(struct sljit_compiler *compiler, sljit_s32 type,
	sljit_s32 dst_reg,
	sljit_s32 src, sljit_sw srcw)
{
	abort();
}

SLJIT_API_FUNC_ATTRIBUTE struct sljit_const* sljit_emit_const(struct sljit_compiler *compiler, sljit_s32 dst, sljit_sw dstw, sljit_sw init_value)
{
	abort();
}

SLJIT_API_FUNC_ATTRIBUTE void sljit_set_jump_addr(sljit_uw addr, sljit_uw new_target, sljit_sw executable_offset)
{
	abort();
}

SLJIT_API_FUNC_ATTRIBUTE void sljit_set_const(sljit_uw addr, sljit_sw new_constant, sljit_sw executable_offset)
{
	abort();
}
