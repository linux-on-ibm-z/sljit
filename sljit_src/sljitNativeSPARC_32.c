/*
 *    Stack-less Just-In-Time compiler
 *
 *    Copyright 2009-2012 Zoltan Herczeg (hzmester@freemail.hu). All rights reserved.
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

static int load_immediate(struct sljit_compiler *compiler, int dst, sljit_w imm)
{
	if (imm <= SIMM_MAX && imm >= SIMM_MIN)
		return push_inst(compiler, OR | D(dst) | S1(0) | IMM(imm), DR(dst));

	FAIL_IF(push_inst(compiler, SETHI | D(dst) | ((imm >> 10) & 0x3fffff), DR(dst)));
	return (imm & 0x3ff) ? push_inst(compiler, OR | D(dst) | S1(dst) | IMM_ARG | (imm & 0x3ff), DR(dst)) : SLJIT_SUCCESS;
}

#define ARG2(flags, src2) ((flags & SRC2_IMM) ? IMM(src2) : S2(src2))

static SLJIT_INLINE int emit_single_op(struct sljit_compiler *compiler, int op, int flags,
	int dst, int src1, sljit_w src2)
{
	switch (op) {
	case SLJIT_MOV:
	case SLJIT_MOV_UI:
	case SLJIT_MOV_SI:
		SLJIT_ASSERT(src1 == TMP_REG1 && !(flags & SRC2_IMM));
		if (dst != src2)
			return push_inst(compiler, OR | D(dst) | S1(0) | S2(src2), DR(dst));
		return SLJIT_SUCCESS;

	case SLJIT_MOV_UB:
	case SLJIT_MOV_SB:
		SLJIT_ASSERT(src1 == TMP_REG1 && !(flags & SRC2_IMM));
		if ((flags & (REG_DEST | REG2_SOURCE)) == (REG_DEST | REG2_SOURCE)) {
			if (op == SLJIT_MOV_UB)
				return push_inst(compiler, AND | D(dst) | S1(src2) | IMM(0xff), DR(dst));
			FAIL_IF(push_inst(compiler, SLL | D(dst) | S1(src2) | IMM(24), DR(dst)));
			return push_inst(compiler, SRA | D(dst) | S1(src2) | IMM(24), DR(dst));
		}
		else if (dst != src2)
			SLJIT_ASSERT_STOP();
		return SLJIT_SUCCESS;

	case SLJIT_MOV_UH:
	case SLJIT_MOV_SH:
		SLJIT_ASSERT(src1 == TMP_REG1 && !(flags & SRC2_IMM));
		if ((flags & (REG_DEST | REG2_SOURCE)) == (REG_DEST | REG2_SOURCE)) {
			FAIL_IF(push_inst(compiler, SLL | D(dst) | S1(src2) | IMM(16), DR(dst)));
			return push_inst(compiler, (op == SLJIT_MOV_SH ? SRA : SRL) | D(dst) | S1(src2) | IMM(16), DR(dst));
		}
		else if (dst != src2)
			SLJIT_ASSERT_STOP();
		return SLJIT_SUCCESS;

	case SLJIT_NOT:
		SLJIT_ASSERT(src1 == TMP_REG1 && !(flags & SRC2_IMM));
		return push_inst(compiler, XNOR | (flags & SET_FLAGS) | D(dst) | S1(0) | S2(src2), DR(dst));

	case SLJIT_CLZ:
		SLJIT_ASSERT(src1 == TMP_REG1 && !(flags & SRC2_IMM));
		SLJIT_ASSERT_STOP();
		return SLJIT_SUCCESS;

	case SLJIT_ADD:
		return push_inst(compiler, ADD | (flags & SET_FLAGS) | D(dst) | S1(src1) | ARG2(flags, src2), DR(dst));

	case SLJIT_ADDC:
		return push_inst(compiler, ADDC | (flags & SET_FLAGS) | D(dst) | S1(src1) | ARG2(flags, src2), DR(dst));

	case SLJIT_SUB:
		return push_inst(compiler, SUB | (flags & SET_FLAGS) | D(dst) | S1(src1) | ARG2(flags, src2), DR(dst));

	case SLJIT_SUBC:
		return push_inst(compiler, SUBC | (flags & SET_FLAGS) | D(dst) | S1(src1) | ARG2(flags, src2), DR(dst));

	case SLJIT_MUL:
		return push_inst(compiler, SMUL | (flags & SET_FLAGS) | D(dst) | S1(src1) | ARG2(flags, src2), DR(dst));

	case SLJIT_AND:
		return push_inst(compiler, AND | (flags & SET_FLAGS) | D(dst) | S1(src1) | ARG2(flags, src2), DR(dst));

	case SLJIT_OR:
		return push_inst(compiler, OR | (flags & SET_FLAGS) | D(dst) | S1(src1) | ARG2(flags, src2), DR(dst));

	case SLJIT_XOR:
		return push_inst(compiler, XOR | (flags & SET_FLAGS) | D(dst) | S1(src1) | ARG2(flags, src2), DR(dst));

	case SLJIT_SHL:
		return push_inst(compiler, SLL | (flags & SET_FLAGS) | D(dst) | S1(src1) | ARG2(flags, src2), DR(dst));

	case SLJIT_LSHR:
		return push_inst(compiler, SRL | (flags & SET_FLAGS) | D(dst) | S1(src1) | ARG2(flags, src2), DR(dst));

	case SLJIT_ASHR:
		return push_inst(compiler, SRA | (flags & SET_FLAGS) | D(dst) | S1(src1) | ARG2(flags, src2), DR(dst));
	}

	SLJIT_ASSERT_STOP();
	return SLJIT_SUCCESS;
}

static SLJIT_INLINE int emit_const(struct sljit_compiler *compiler, int dst, sljit_w init_value)
{
	FAIL_IF(push_inst(compiler, SETHI | D(dst) | ((init_value >> 10) & 0x3fffff), DR(dst)));
	return push_inst(compiler, OR | D(dst) | S1(dst) | IMM_ARG | (init_value & 0x3ff), DR(dst));
}

SLJIT_API_FUNC_ATTRIBUTE void sljit_set_jump_addr(sljit_uw addr, sljit_uw new_addr)
{
	sljit_ins *inst = (sljit_ins*)addr;

	inst[0] = (inst[0] & 0xffff0000) | ((new_addr >> 16) & 0xffff);
	inst[1] = (inst[1] & 0xffff0000) | (new_addr & 0xffff);
	SLJIT_CACHE_FLUSH(inst, inst + 2);
}

SLJIT_API_FUNC_ATTRIBUTE void sljit_set_const(sljit_uw addr, sljit_w new_constant)
{
	sljit_ins *inst = (sljit_ins*)addr;

	inst[0] = (inst[0] & 0xffff0000) | ((new_constant >> 16) & 0xffff);
	inst[1] = (inst[1] & 0xffff0000) | (new_constant & 0xffff);
	SLJIT_CACHE_FLUSH(inst, inst + 2);
}
