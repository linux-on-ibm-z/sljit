/*
 *    Stack-less Just-In-Time compiler
 *    Copyright (c) Zoltan Herczeg
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU Lesser General Public License as
 *   published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 */

// Last register + 1
#define TMP_REG1	(SLJIT_GENERAL_REG3 + 1)
#define TMP_REG2	(SLJIT_GENERAL_REG3 + 2)
#define TMP_REG3	(SLJIT_GENERAL_REG3 + 3)
#define TMP_PC		(SLJIT_GENERAL_REG3 + 4)

static sljit_ub reg_map[SLJIT_NO_REGISTERS + 5] = {
   0, 0, 1, 2, 4, 5, 6, 3, 7, 8, 15
};

static int push_cpool(struct sljit_compiler *compiler)
{
	sljit_uw* inst;
	sljit_uw* cpool_ptr;
	sljit_uw* cpool_end;

	SLJIT_ASSERT(compiler->cpool_fill > 0);
	inst = (sljit_uw*)ensure_buf(compiler, sizeof(sljit_uw));
	if (!inst) {
		compiler->error = SLJIT_MEMORY_ERROR;
		return 1;
	}
	compiler->size++;
	*inst = 0xff000000 | compiler->cpool_fill;

	cpool_ptr = compiler->cpool;
	cpool_end = cpool_ptr + compiler->cpool_fill;
	while (cpool_ptr < cpool_end) {
		inst = (sljit_uw*)ensure_buf(compiler, sizeof(sljit_uw));
		if (!inst) {
			compiler->error = SLJIT_MEMORY_ERROR;
			return 1;
		}
		compiler->size++;
		*inst = *cpool_ptr++;
	}
	compiler->cpool_diff = 0xffffffff;
	compiler->cpool_fill = 0;
	return 0;
}

// if last_ins_imm == 0, that means the constant can be changed later
static int push_inst(struct sljit_compiler *compiler)
{
	sljit_uw* inst;
	sljit_uw* cpool_ptr;
	sljit_uw* cpool_end;

	if (compiler->last_type == LIT_INS) {
		// Test wheter the constant pool must be copied
		if (compiler->cpool_diff != 0xffffffff && compiler->size - compiler->cpool_diff >= (4092 / sizeof(sljit_w)))
			if (push_cpool(compiler))
				return compiler->error;

		inst = (sljit_uw*)ensure_buf(compiler, sizeof(sljit_uw));
		if (!inst) {
			compiler->error = SLJIT_MEMORY_ERROR;
			return SLJIT_MEMORY_ERROR;
		}
		*inst = compiler->last_ins;
		compiler->last_type = LIT_NONE;
		compiler->size++;
	}
	else if (compiler->last_type >= LIT_CINS) {
		// Test wheter the constant pool must be copied
		compiler->cpool_index = CPOOL_SIZE;
		if (compiler->cpool_diff != 0xffffffff && compiler->size - compiler->cpool_diff >= (4092 / sizeof(sljit_w))) {
			if (push_cpool(compiler))
				return compiler->error;
		}
		else if (compiler->last_type == LIT_CINS && compiler->cpool_fill > 0) {
			cpool_ptr = compiler->cpool;
			cpool_end = cpool_ptr + compiler->cpool_fill;
			do {
				if (*cpool_ptr == compiler->last_imm) {
					compiler->cpool_index = cpool_ptr - compiler->cpool;
					break;
				}
				cpool_ptr++;
			} while (cpool_ptr < cpool_end);
		}

		if (compiler->cpool_index == CPOOL_SIZE) {
			// Must allocate a new place
			if (compiler->cpool_fill < CPOOL_SIZE) {
				compiler->cpool_index = compiler->cpool_fill;
				compiler->cpool_fill++;
			}
			else {
				if (push_cpool(compiler))
					return compiler->error;
				compiler->cpool_index = 0;
				compiler->cpool_fill = 1;
			}
		}

		inst = (sljit_uw*)ensure_buf(compiler, sizeof(sljit_uw));
		if (!inst) {
			compiler->error = SLJIT_MEMORY_ERROR;
			return compiler->error;
		}
		compiler->cpool[compiler->cpool_index] = compiler->last_imm;
		*inst = compiler->last_ins | (compiler->cpool_index << 2);
		compiler->last_type = LIT_NONE;
		compiler->size++;
		if (compiler->cpool_diff == 0xffffffff)
			compiler->cpool_diff = compiler->size;
	}

	return SLJIT_NO_ERROR;
}

static int emit_mov_ln_pc(struct sljit_compiler *compiler)
{
	sljit_uw last_type = compiler->last_type;
	sljit_uw last_ins = compiler->last_ins;

	if (compiler->last_type == LIT_INS) {
		// Test wheter the constant pool must be copied
		if (compiler->cpool_diff != 0xffffffff && compiler->size - compiler->cpool_diff >= (4088 / sizeof(sljit_w)))
			if (push_cpool(compiler))
				return compiler->error;
	}
	else if (compiler->last_type >= LIT_CINS) {
		// Test wheter the constant pool must be copied
		if (compiler->cpool_diff != 0xffffffff && compiler->size - compiler->cpool_diff >= (4088 / sizeof(sljit_w))) {
			if (push_cpool(compiler))
				return compiler->error;
		}
		else if (compiler->cpool_fill >= CPOOL_SIZE) {
			if (push_cpool(compiler))
				return compiler->error;
		}
	}

	// Must be immediately before the "mov/ldr pc, ..." instruction
	compiler->last_type = LIT_INS;
	compiler->last_ins = 0xe1a0e00f; // mov lr, pc

	if (push_inst(compiler))
		return compiler->error;

	compiler->last_type = last_type;
	compiler->last_ins = last_ins;

	return SLJIT_NO_ERROR;
}

static INLINE void patch_pc_rel(sljit_uw *last_pc_patch, sljit_uw *code_ptr)
{
	sljit_uw diff;

	while (last_pc_patch < code_ptr) {
		if ((*last_pc_patch & 0x0c0f0000) == 0x040f0000) {
			diff = code_ptr - last_pc_patch;
			SLJIT_ASSERT((*last_pc_patch & 0x3) == 0 && (*last_pc_patch & (1 << 25)) == 0);
			if (diff >= 2 || (*last_pc_patch & 0xfff) > 0) {
				diff = (diff - 2) << 2;
				SLJIT_ASSERT((*last_pc_patch & 0xfff) + diff <= 0xfff);
				*last_pc_patch += diff;
			}
			else {
				// In practice, this should never happen
				SLJIT_ASSERT(diff == 1);
				*last_pc_patch |= 0x004;
				*last_pc_patch &= ~(1 << 23);
			}
		}
		last_pc_patch++;
	}
}

static INLINE int optimize_jump(struct sljit_jump *jump, sljit_uw *code_ptr, sljit_uw *code)
{
	sljit_w diff;

	if (jump->flags & SLJIT_LONG_JUMP)
		return 0;

	if (jump->flags & IS_BL)
		code_ptr--;

	if (jump->flags & IS_FIXED)
		diff = ((sljit_w)jump->target - (sljit_w)(code_ptr + 2)) >> 2;
	else {
		SLJIT_ASSERT(jump->flags & JUMP_LABEL);
		diff = ((sljit_w)(code + jump->label->size) - (sljit_w)(code_ptr + 2)) >> 2;
	}

	if (jump->flags & IS_BL) {
		if (diff <= 0x01ffffff && diff >= -0x02000000) {
			*code_ptr = 0x0b000000 | (*(code_ptr + 1) & 0xf0000000);
			jump->flags |= PATCH_B;
			return 1;
		}
	}
	else {
		if (diff <= 0x01ffffff && diff >= -0x02000000) {
			*code_ptr = 0x0a000000 | (*code_ptr & 0xf0000000);
			jump->flags |= PATCH_B;
		}
	}
	return 0;
}

void* sljit_generate_code(struct sljit_compiler *compiler)
{
	struct sljit_memory_fragment *buf;
	sljit_uw *code;
	sljit_uw *code_ptr;
	sljit_uw *last_pc_patch;
	sljit_uw *buf_ptr;
	sljit_uw *buf_end;
	sljit_uw size;
	sljit_uw word_count;
	sljit_uw copy;

	struct sljit_label *label;
	struct sljit_jump *jump;
	struct sljit_const *const_;

	FUNCTION_ENTRY();

	if (compiler->last_type != LIT_NONE)
		if (push_inst(compiler))
			return NULL;

	SLJIT_ASSERT(compiler->size > 0);
	reverse_buf(compiler);

	// Second code generation pass
	size = compiler->size + compiler->cpool_fill + (compiler->patches << 1);
	code = SLJIT_MALLOC_EXEC(size * sizeof(sljit_uw));
	if (!code) {
		compiler->error = SLJIT_MEMORY_ERROR;
		return NULL;
	}
	buf = compiler->buf;

	code_ptr = code;
	last_pc_patch = code;
	copy = 0;
	word_count = 0;
	label = compiler->labels;
	jump = compiler->jumps;
	const_ = compiler->consts;
	do {
		buf_ptr = (sljit_uw*)buf->memory;
		buf_end = buf_ptr + (buf->used_size >> 2);
		while (buf_ptr < buf_end) {
			if (copy > 0) {
				*code_ptr++ = *buf_ptr++;
				if (--copy == 0)
					last_pc_patch = code_ptr;
			}
			else if ((*buf_ptr & 0xf0000000) != 0xf0000000) {
				*code_ptr = *buf_ptr++;
				// These structures are ordered by their address
				if (label && label->size == word_count) {
					label->addr = (sljit_uw)code_ptr;
					label->size = code_ptr - code;
					label = label->next;
				}
				if (jump && jump->addr == word_count) {
					if (optimize_jump(jump, code_ptr, code))
						code_ptr--;

					jump->addr = (sljit_uw)code_ptr;
					jump = jump->next;
				}
				if (const_ && const_->addr == word_count) {
					const_->addr = (sljit_uw)code_ptr;
					const_ = const_->next;
				}
				code_ptr++;
			}
			else if ((*buf_ptr & 0x0f000000) == 0x0f000000) {
				// Fortunately, no need to shift
				copy = *buf_ptr++ & 0x00ffffff;
				SLJIT_ASSERT(copy > 0);
				// unconditional branch
				*code_ptr++ = 0xea000000 | ((copy - 1) & 0x00ffffff);
				patch_pc_rel(last_pc_patch, code_ptr);
			}
			else {
				SLJIT_ASSERT_IMPOSSIBLE();
			}
			word_count ++;
		}
		buf = buf->next;
	} while (buf != NULL);

	SLJIT_ASSERT(label == NULL);
	SLJIT_ASSERT(jump == NULL);
	SLJIT_ASSERT(const_ == NULL);
	SLJIT_ASSERT(copy == 0);

	if (compiler->cpool_fill > 0) {
		patch_pc_rel(last_pc_patch, code_ptr);

		buf_ptr = compiler->cpool;
		buf_end = buf_ptr + compiler->cpool_fill;
		while (buf_ptr < buf_end)
			*code_ptr++ = *buf_ptr++;
	}

	jump = compiler->jumps;
	while (jump) {
		buf_ptr = (sljit_uw*)jump->addr;
		jump->addr = (sljit_uw)code_ptr;

		if (!(jump->flags & SLJIT_LONG_JUMP)) {
			if (jump->flags & PATCH_B) {
				if (!(jump->flags & IS_FIXED)) {
					SLJIT_ASSERT(jump->flags & JUMP_LABEL);
					SLJIT_ASSERT(((sljit_w)jump->label->addr - (sljit_w)(buf_ptr + 2)) <= 0x01ffffff && ((sljit_w)jump->label->addr - (sljit_w)(buf_ptr + 2)) >= -0x02000000);
					*buf_ptr |= (((sljit_w)jump->label->addr - (sljit_w)(buf_ptr + 2)) >> 2) & 0x00ffffff;
				}
				else {
					SLJIT_ASSERT(((sljit_w)jump->target - (sljit_w)(buf_ptr + 2)) <= 0x01ffffff && ((sljit_w)jump->target - (sljit_w)(buf_ptr + 2)) >= -0x02000000);
					*buf_ptr |= (((sljit_w)jump->target - (sljit_w)(buf_ptr + 2)) >> 2) & 0x00ffffff;
				}
			}
		}
		else {
			SLJIT_ASSERT(jump->flags & (JUMP_LABEL | JUMP_ADDR));
			code_ptr[0] = (sljit_uw)buf_ptr;
			code_ptr[1] = *buf_ptr;
			sljit_set_jump_addr((sljit_uw)code_ptr, (jump->flags & JUMP_LABEL) ? jump->label->addr : jump->target);
			code_ptr += 2;
		}
		jump = jump->next;
	}

	const_ = compiler->consts;
	while (const_) {
		buf_ptr = (sljit_uw*)const_->addr;
		const_->addr = (sljit_uw)code_ptr;

		code_ptr[0] = (sljit_uw)buf_ptr;
		code_ptr[1] = *buf_ptr;
		copy = *buf_ptr;
		if (copy & (1 << 23))
			buf_ptr += ((copy & 0xfff) >> 2) + 2;
		else
			buf_ptr += 1;
		sljit_set_const((sljit_uw)code_ptr, *buf_ptr);
		code_ptr += 2;

		const_ = const_->next;
	}

	SLJIT_ASSERT(code_ptr - code <= size);
	compiler->error = SLJIT_CODE_GENERATED;
	return code;
}

void sljit_free_code(void* code)
{
	SLJIT_FREE_EXEC(code);
}

#define MOV_REG(dst, src)	0xe1a00000 | reg_map[src] | (reg_map[dst] << 12)

int sljit_emit_enter(struct sljit_compiler *compiler, int args, int general)
{
	FUNCTION_ENTRY();
	// TODO: support the others
	SLJIT_ASSERT(args >= 0 && args <= SLJIT_NO_GEN_REGISTERS);
	SLJIT_ASSERT(general >= 0 && general <= SLJIT_NO_GEN_REGISTERS);
	SLJIT_ASSERT(args <= general);
	SLJIT_ASSERT(compiler->general == -1);

	sljit_emit_enter_verbose();

	compiler->general = general;

	if (push_inst(compiler))
		return compiler->error;
	// Push general registers, temporary registers
        // stmdb sp!, {..., lr}
	compiler->last_type = LIT_INS;
	compiler->last_ins = 0xe92d0000 | 0x4000 | 0x0180;
	if (general >= 3)
		compiler->last_ins |= 0x0070;
	else if (general >= 2)
		compiler->last_ins |= 0x0030;
	else if (general >= 1)
		compiler->last_ins |= 0x0010;

	if (args >= 1) {
		if (push_inst(compiler))
			return compiler->error;
		compiler->last_type = LIT_INS;
		compiler->last_ins = MOV_REG(SLJIT_GENERAL_REG1, SLJIT_TEMPORARY_REG1);
	}
	if (args >= 2) {
		if (push_inst(compiler))
			return compiler->error;
		compiler->last_type = LIT_INS;
		compiler->last_ins = MOV_REG(SLJIT_GENERAL_REG2, SLJIT_TEMPORARY_REG2);
	}
	if (args >= 3) {
		if (push_inst(compiler))
			return compiler->error;
		compiler->last_type = LIT_INS;
		compiler->last_ins = MOV_REG(SLJIT_GENERAL_REG3, SLJIT_TEMPORARY_REG3);
	}

	return SLJIT_NO_ERROR;
}

int sljit_emit_return(struct sljit_compiler *compiler, int reg)
{
	FUNCTION_ENTRY();
	SLJIT_ASSERT(reg >= 0 && reg <= SLJIT_NO_REGISTERS);
	SLJIT_ASSERT(compiler->general >= 0);

	sljit_emit_return_verbose();

	if (reg != SLJIT_PREF_RET_REG && reg != SLJIT_NO_REG) {
		if (push_inst(compiler))
			return compiler->error;
		compiler->last_type = LIT_INS;
		compiler->last_ins = MOV_REG(SLJIT_PREF_RET_REG, reg);
	}

	if (push_inst(compiler))
		return compiler->error;
	// Push general registers, temporary registers
        // ldmia sp!, {..., pc}
	compiler->last_type = LIT_INS;
	compiler->last_ins = 0xe8bd0000 | 0x8000 | 0x0180;
	if (compiler->general >= 3)
		compiler->last_ins |= 0x0070;
	else if (compiler->general >= 2)
		compiler->last_ins |= 0x0030;
	else if (compiler->general >= 1)
		compiler->last_ins |= 0x0010;

	return SLJIT_NO_ERROR;
}

// ---------------------------------------------------------------------
//  Operators
// ---------------------------------------------------------------------

#define OP1_OFFSET	(SLJIT_ASHR + 1)

#define TEST_ERROR(ret) \
	if (ret) { \
		return SLJIT_MEMORY_ERROR; \
	}

#define EMIT_DATA_PROCESS_INS(opcode, dst, src1, src2) \
	(0xe0000000 | ((opcode) << 20) | (reg_map[dst] << 12) | (reg_map[src1] << 16) | (src2))
#define EMIT_DATA_TRANSFER(add, load, target, base1, base2) \
	(0xe5000000 | ((add) << 23) | ((load) << 20) | (reg_map[target] << 12) | (reg_map[base1] << 16) | (base2))

// flags:
// Arguments are swapped
#define ARGS_SWAPPED	0x1
// Inverted immediate
#define INV_IMM		0x2
// dst: reg
// src1: reg
// src2: reg or imm (if allowed)
// This flag fits for data processing instructions
#define SRC2_IMM	(1 << 25)

#define SET_DATA_PROCESS_INS(opcode) \
	compiler->last_type = LIT_INS; \
	if (src2 & SRC2_IMM) \
		compiler->last_ins = EMIT_DATA_PROCESS_INS(opcode, dst, src1, src2); \
	else \
		compiler->last_ins = EMIT_DATA_PROCESS_INS(opcode, dst, src1, reg_map[src2]);

#define SET_SHIFT_INS(opcode) \
	compiler->last_type = LIT_INS; \
	if (compiler->shift_imm != 0x20) { \
		SLJIT_ASSERT(src1 == TMP_REG1); \
		SLJIT_ASSERT(!(flags & ARGS_SWAPPED)); \
		compiler->last_ins = EMIT_DATA_PROCESS_INS(0x1b, dst, SLJIT_NO_REG, (compiler->shift_imm << 7) | (opcode << 5) | reg_map[src2]); \
	} \
	else { \
		if (!(flags & ARGS_SWAPPED)) \
			compiler->last_ins = EMIT_DATA_PROCESS_INS(0x1b, dst, SLJIT_NO_REG, (reg_map[src2] << 8) | (opcode << 5) | 0x10 | reg_map[src1]); \
		else \
			compiler->last_ins = EMIT_DATA_PROCESS_INS(0x1b, dst, SLJIT_NO_REG, (reg_map[src1] << 8) | (opcode << 5) | 0x10 | reg_map[src2]); \
	}

static int emit_single_op(struct sljit_compiler *compiler, int op, int flags,
	int dst, int src1, int src2)
{
	switch (op) {
	case SLJIT_ADD:
		SLJIT_ASSERT((flags & INV_IMM) == 0);
		if (push_inst(compiler))
			return compiler->error;
		SET_DATA_PROCESS_INS(0x09);
		return SLJIT_NO_ERROR;

	case SLJIT_ADDC:
		SLJIT_ASSERT((flags & INV_IMM) == 0);
		if (push_inst(compiler))
			return compiler->error;
		SET_DATA_PROCESS_INS(0x0b);
		return SLJIT_NO_ERROR;

	case SLJIT_SUB:
		SLJIT_ASSERT((flags & INV_IMM) == 0);
		if (push_inst(compiler))
			return compiler->error;
		if (!(flags & ARGS_SWAPPED)) {
			SET_DATA_PROCESS_INS(0x05);
		}
		else {
			SET_DATA_PROCESS_INS(0x07);
		}
		return SLJIT_NO_ERROR;

	case SLJIT_SUBC:
		SLJIT_ASSERT((flags & INV_IMM) == 0);
		if (push_inst(compiler))
			return compiler->error;
		if (!(flags & ARGS_SWAPPED)) {
			SET_DATA_PROCESS_INS(0x0d);
		}
		else {
			SET_DATA_PROCESS_INS(0x0f);
		}
		return SLJIT_NO_ERROR;

	case SLJIT_MUL:
		SLJIT_ASSERT((flags & INV_IMM) == 0);
		SLJIT_ASSERT((src2 & SRC2_IMM) == 0);
		if (push_inst(compiler))
			return compiler->error;
		compiler->last_type = LIT_INS;
		if (dst != src2)
			compiler->last_ins = 0xe0100090 | (reg_map[dst] << 16) | (reg_map[src1] << 8) | reg_map[src2];
		else if (dst != src1)
			compiler->last_ins = 0xe0100090 | (reg_map[dst] << 16) | (reg_map[src2] << 8) | reg_map[src1];
		else {
			// Rm and Rd must not be the same register
			SLJIT_ASSERT(dst != TMP_REG1);
			compiler->last_ins = EMIT_DATA_PROCESS_INS(0x1a, TMP_REG1, SLJIT_NO_REG, reg_map[src2]);
			if (push_inst(compiler))
				return compiler->error;
			compiler->last_type = LIT_INS;
			compiler->last_ins = 0xe0100090 | (reg_map[dst] << 16) | (reg_map[src2] << 8) | reg_map[TMP_REG1];
		}
		return SLJIT_NO_ERROR;

	case SLJIT_AND:
		if (push_inst(compiler))
			return compiler->error;
		if (!(flags & INV_IMM)) {
			SET_DATA_PROCESS_INS(0x01);
		}
		else {
			SET_DATA_PROCESS_INS(0x1d);
		}
		return SLJIT_NO_ERROR;

	case SLJIT_OR:
		SLJIT_ASSERT((flags & INV_IMM) == 0);
		if (push_inst(compiler))
			return compiler->error;
		SET_DATA_PROCESS_INS(0x19);
		return SLJIT_NO_ERROR;

	case SLJIT_XOR:
		SLJIT_ASSERT((flags & INV_IMM) == 0);
		if (push_inst(compiler))
			return compiler->error;
		SET_DATA_PROCESS_INS(0x03);
		return SLJIT_NO_ERROR;

	case SLJIT_SHL:
		SLJIT_ASSERT((flags & INV_IMM) == 0);
		SLJIT_ASSERT((src2 & SRC2_IMM) == 0);
		if (push_inst(compiler))
			return compiler->error;
		SET_SHIFT_INS(0);
		return SLJIT_NO_ERROR;

	case SLJIT_LSHR:
		SLJIT_ASSERT((flags & INV_IMM) == 0);
		SLJIT_ASSERT((src2 & SRC2_IMM) == 0);
		if (push_inst(compiler))
			return compiler->error;
		SET_SHIFT_INS(1);
		return SLJIT_NO_ERROR;

	case SLJIT_ASHR:
		SLJIT_ASSERT((flags & INV_IMM) == 0);
		SLJIT_ASSERT((src2 & SRC2_IMM) == 0);
		if (push_inst(compiler))
			return compiler->error;
		SET_SHIFT_INS(2);
		return SLJIT_NO_ERROR;

	case (OP1_OFFSET + SLJIT_MOV):
		SLJIT_ASSERT(src1 == TMP_REG1);
		SLJIT_ASSERT((flags & ARGS_SWAPPED) == 0);
		if (dst != src2) {
			if (push_inst(compiler))
				return compiler->error;
			compiler->last_type = LIT_INS;
			if (src2 & SRC2_IMM) {
				if (flags & INV_IMM)
					compiler->last_ins = EMIT_DATA_PROCESS_INS(0x1e, dst, SLJIT_NO_REG, src2);
				else
					compiler->last_ins = EMIT_DATA_PROCESS_INS(0x1a, dst, SLJIT_NO_REG, src2);
			}
			else
				compiler->last_ins = EMIT_DATA_PROCESS_INS(0x1a, dst, SLJIT_NO_REG, reg_map[src2]);
		}
		return SLJIT_NO_ERROR;

	case (OP1_OFFSET + SLJIT_NOT):
		if (push_inst(compiler))
			return compiler->error;
		compiler->last_type = LIT_INS;
		if (src2 & SRC2_IMM) {
			if (flags & INV_IMM)
				compiler->last_ins = EMIT_DATA_PROCESS_INS(0x1a, dst, SLJIT_NO_REG, src2);
			else
				compiler->last_ins = EMIT_DATA_PROCESS_INS(0x1e, dst, SLJIT_NO_REG, src2);
		}
		else
			compiler->last_ins = EMIT_DATA_PROCESS_INS(0x1e, dst, SLJIT_NO_REG, reg_map[src2]);

		return SLJIT_NO_ERROR;
	}
	SLJIT_ASSERT_IMPOSSIBLE();
	return SLJIT_NO_ERROR;
}

// Tests whether the immediate can be stored in the 12 bit imm field
// returns 0 if not possible
static sljit_uw get_immediate(sljit_uw imm)
{
	int rol = 0;

	if (imm == 0)
		return SRC2_IMM | 0;

	imm = (imm << 24) | (imm >> 8);
	while ((imm & 0xff000000) == 0) {
		imm <<= 8;
		rol += 4;
	}

	if ((imm & 0xf0000000) == 0) {
		imm <<= 4;
		rol += 2;
	}

	if ((imm & 0xc0000000) == 0) {
		imm <<= 2;
		rol += 1;
	}

	if ((imm & 0x00ffffff) == 0)
		return SRC2_IMM | (imm >> 24) | (rol << 8);
	else
		return 0;
}

static int load_immediate(struct sljit_compiler *compiler, int reg, sljit_uw imm)
{
	// Get the immediate at most from two instructions
	sljit_uw rimm, tmp;
	int round = 2;
	int rol1;
	int rol2;
	int byte1;

	rimm = (imm << 24) | (imm >> 8);
	tmp = rimm;
	do {
		rol1 = 0;
		if (tmp == 0) {
			if (push_inst(compiler))
				return compiler->error;
			compiler->last_type = LIT_INS;
			compiler->last_ins = EMIT_DATA_PROCESS_INS((round == 2) ? 0x1a : 0x1e, reg, SLJIT_NO_REG, SRC2_IMM | 0);
			return SLJIT_NO_ERROR;
		}

		while ((tmp & 0xff000000) == 0) {
			tmp <<= 8;
			rol1 += 4;
		}

		if ((tmp & 0xf0000000) == 0) {
			tmp <<= 4;
			rol1 += 2;
		}

		if ((tmp & 0xc0000000) == 0) {
			tmp <<= 2;
			rol1 += 1;
		}

		if ((tmp & 0x00ffffff) == 0) {
			if (push_inst(compiler))
				return compiler->error;
			compiler->last_type = LIT_INS;
			compiler->last_ins = EMIT_DATA_PROCESS_INS((round == 2) ? 0x1a : 0x1e, reg, SLJIT_NO_REG, SRC2_IMM | (tmp >> 24) | (rol1 << 8));
			return SLJIT_NO_ERROR;
		}

		rol2 = rol1 + 4;
		byte1 = tmp >> 24;
		tmp <<= 8;

		while ((tmp & 0xff000000) == 0) {
			tmp <<= 8;
			rol2 += 4;
		}

		if ((tmp & 0xf0000000) == 0) {
			tmp <<= 4;
			rol2 += 2;
		}

		if ((tmp & 0xc0000000) == 0) {
			tmp <<= 2;
			rol2 += 1;
		}

		if ((tmp & 0x00ffffff) == 0) {
			if (push_inst(compiler))
				return compiler->error;
			compiler->last_type = LIT_INS;
			compiler->last_ins = EMIT_DATA_PROCESS_INS((round == 2) ? 0x1a : 0x1e, reg, SLJIT_NO_REG, SRC2_IMM | (byte1) | (rol1 << 8));

			if (push_inst(compiler))
				return compiler->error;
			compiler->last_type = LIT_INS;
			compiler->last_ins = EMIT_DATA_PROCESS_INS((round == 2) ? 0x18 : 0x1c, reg, reg, SRC2_IMM | (tmp >> 24) | (rol2 << 8));
			return SLJIT_NO_ERROR;
		}

		tmp = ~rimm;
	} while (--round > 0);

	if (push_inst(compiler))
		return compiler->error;
	compiler->last_type = LIT_CINS;
	compiler->last_ins = EMIT_DATA_TRANSFER(1, 1, reg, TMP_PC, 0);
	compiler->last_imm = imm;

	return SLJIT_NO_ERROR;
}

#define ARG_LOAD	0x1
#define ARG_TEST	0x2

// Can perform an operation using at most 1 instruction
static int getput_arg_fast(struct sljit_compiler *compiler, int flags, int reg, int arg, sljit_w argw)
{
	sljit_uw imm;

	if (arg & SLJIT_IMM) {
		imm = get_immediate(argw);
		if (imm != 0) {
			if (flags & ARG_TEST)
				return 1;
			if (push_inst(compiler))
				return compiler->error;
			compiler->last_type = LIT_INS;
			compiler->last_ins = EMIT_DATA_PROCESS_INS(0x1a, reg, SLJIT_NO_REG, imm);
			return -1;
		}
		imm = get_immediate(~argw);
		if (imm != 0) {
			if (flags & ARG_TEST)
				return 1;
			if (push_inst(compiler))
				return compiler->error;
			compiler->last_type = LIT_INS;
			compiler->last_ins = EMIT_DATA_PROCESS_INS(0x1e, reg, SLJIT_NO_REG, imm);
			return -1;
		}
		return (flags & ARG_TEST) ? SLJIT_NO_ERROR : 0;
	}

	SLJIT_ASSERT(arg & SLJIT_MEM_FLAG);

	// Fast loads/stores
	if ((arg & 0xf) != 0) {
		if (((arg >> 4) & 0xf) == 0) {
			if (argw >= 0 && argw <= 0xfff) {
				if (flags & ARG_TEST)
					return 1;
				if (push_inst(compiler))
					return compiler->error;
				compiler->last_type = LIT_INS;
				compiler->last_ins = EMIT_DATA_TRANSFER(1, flags & ARG_LOAD, reg, arg & 0xf, argw);
				return -1;
			}
			if (argw < 0 && argw >= -0xfff) {
				if (flags & ARG_TEST)
					return 1;
				if (push_inst(compiler))
					return compiler->error;
				compiler->last_type = LIT_INS;
				compiler->last_ins = EMIT_DATA_TRANSFER(0, flags & ARG_LOAD, reg, arg & 0xf, -argw);
				return -1;
			}
		}
		else if (argw == 0) {
			if (flags & ARG_TEST)
				return 1;
			if (push_inst(compiler))
				return compiler->error;
			compiler->last_type = LIT_INS;
			compiler->last_ins = EMIT_DATA_TRANSFER(1, flags & ARG_LOAD, reg, arg & 0xf, reg_map[(arg >> 4) & 0xf] | SRC2_IMM);
			return -1;
		}
	}

	return (flags & ARG_TEST) ? SLJIT_NO_ERROR : 0;
}

// see getput_arg below
static int can_cache(int arg, sljit_w argw, int next_arg, sljit_w next_argw)
{
	if (arg & SLJIT_IMM)
		return 0;

	if ((arg & 0xf) == 0) {
		if ((next_arg & SLJIT_MEM_FLAG) && (argw - next_argw <= 4095 || next_argw - argw <= 0xfff))
			return 1;
		return 0;
	}

	if (argw >= 0 && argw <= 0xfff) {
		if (arg == next_arg && (next_argw <= 0xfff && next_argw >= -0xfff))
			return 1;
		return 0;
	}

	if ((arg & 0xf0) == SLJIT_NO_REG && (next_arg & 0xf0) == SLJIT_NO_REG && (next_arg & 0xf) != SLJIT_NO_REG && argw == next_argw)
		return 1;

	if (argw < 0 && argw >= -0xfff) {
		if (arg == next_arg && (next_argw <= 0xfff && next_argw >= -0xfff))
			return 1;
		return 0;
	}

	if (arg == next_arg && ((sljit_uw)argw - (sljit_uw)next_argw <= 0xfff || (sljit_uw)next_argw - (sljit_uw)argw <= 0xfff))
		return 1;

	return 0;
}

// emit the necessary instructions
// see can_cache above
static int getput_arg(struct sljit_compiler *compiler, int flags, int reg, int arg, sljit_w argw, int next_arg, sljit_w next_argw)
{
	int tmp_reg;

	if (arg & SLJIT_IMM) {
		SLJIT_ASSERT(flags & ARG_LOAD);
		return load_immediate(compiler, reg, argw);
	}

	SLJIT_ASSERT(arg & SLJIT_MEM_FLAG);

	tmp_reg = (flags & ARG_LOAD) ? reg : TMP_REG3;

	if ((arg & 0xf) == SLJIT_NO_REG) {
		if ((compiler->cache_arg & SLJIT_IMM) && ((sljit_uw)argw - (sljit_uw)compiler->cache_argw) <= 0xfff) {
			if (push_inst(compiler))
				return compiler->error;
			compiler->last_type = LIT_INS;
			compiler->last_ins = EMIT_DATA_TRANSFER(1, flags & ARG_LOAD, reg, TMP_REG3, argw - compiler->cache_argw);
			return SLJIT_NO_ERROR;
		}

		if ((compiler->cache_arg & SLJIT_IMM) && ((sljit_uw)compiler->cache_argw - (sljit_uw)argw) <= 4095) {
			if (push_inst(compiler))
				return compiler->error;
			compiler->last_type = LIT_INS;
			compiler->last_ins = EMIT_DATA_TRANSFER(0, flags & ARG_LOAD, reg, TMP_REG3, compiler->cache_argw - argw);
			return SLJIT_NO_ERROR;
		}

		if ((next_arg & SLJIT_MEM_FLAG) && (argw - next_argw <= 4095 || next_argw - argw <= 0xfff)) {
			SLJIT_ASSERT(flags & ARG_LOAD);
			if (load_immediate(compiler, TMP_REG3, argw))
				return compiler->error;

			compiler->cache_arg = SLJIT_IMM;
			compiler->cache_argw = argw;

			if (push_inst(compiler))
				return compiler->error;
			compiler->last_type = LIT_INS;
			compiler->last_ins = EMIT_DATA_TRANSFER(1, 1, reg, TMP_REG3, 0);
			return SLJIT_NO_ERROR;
		}

		if (load_immediate(compiler, tmp_reg, argw))
			return compiler->error;

		if (push_inst(compiler))
			return compiler->error;
		compiler->last_type = LIT_INS;
		compiler->last_ins = EMIT_DATA_TRANSFER(1, flags & ARG_LOAD, reg, tmp_reg, 0);
		return SLJIT_NO_ERROR;
	}

	if (compiler->cache_arg == arg && ((sljit_uw)argw - (sljit_uw)compiler->cache_argw) <= 0xfff) {
		if (push_inst(compiler))
			return compiler->error;
		compiler->last_type = LIT_INS;
		compiler->last_ins = EMIT_DATA_TRANSFER(1, flags & ARG_LOAD, reg, TMP_REG3, argw - compiler->cache_argw);
		return SLJIT_NO_ERROR;
	}

	if (compiler->cache_arg == arg && ((sljit_uw)compiler->cache_argw - (sljit_uw)argw) <= 0xfff) {
		if (push_inst(compiler))
			return compiler->error;
		compiler->last_type = LIT_INS;
		compiler->last_ins = EMIT_DATA_TRANSFER(0, flags & ARG_LOAD, reg, TMP_REG3, compiler->cache_argw - argw);
		return SLJIT_NO_ERROR;
	}

	if ((compiler->cache_arg & SLJIT_IMM) && compiler->cache_argw == argw && (arg & 0xf0) == SLJIT_NO_REG) {
		if (push_inst(compiler))
			return compiler->error;
		compiler->last_type = LIT_INS;
		compiler->last_ins = EMIT_DATA_TRANSFER(1, flags & ARG_LOAD, reg, TMP_REG3, reg_map[arg & 0xf] | SRC2_IMM);
		return SLJIT_NO_ERROR;
	}

	if ((arg & 0xf0) == SLJIT_NO_REG && (next_arg & 0xf0) == SLJIT_NO_REG && (next_arg & 0xf) != SLJIT_NO_REG && argw == next_argw) {
		SLJIT_ASSERT(flags & ARG_LOAD);
		if (load_immediate(compiler, TMP_REG3, argw))
			return compiler->error;

		compiler->cache_arg = SLJIT_IMM;
		compiler->cache_argw = argw;

		if (push_inst(compiler))
			return compiler->error;
		compiler->last_type = LIT_INS;
		compiler->last_ins = EMIT_DATA_TRANSFER(1, flags & ARG_LOAD, reg, arg & 0xf, reg_map[TMP_REG3] | SRC2_IMM);
		return SLJIT_NO_ERROR;
	}

	if (argw >= 0 && argw <= 0xfff) {
		if (arg == next_arg && (next_argw <= 0xfff && next_argw >= -0xfff)) {
			SLJIT_ASSERT(flags & ARG_LOAD);
			if (push_inst(compiler))
				return compiler->error;
			compiler->last_type = LIT_INS;
			compiler->last_ins = EMIT_DATA_PROCESS_INS(0x08, TMP_REG3, arg & 0xf, reg_map[(arg >> 4) & 0xf]);

			compiler->cache_arg = arg;
			compiler->cache_argw = 0;

			if (push_inst(compiler))
				return compiler->error;
			compiler->last_type = LIT_INS;
			compiler->last_ins = EMIT_DATA_TRANSFER(1, flags & ARG_LOAD, reg, TMP_REG3, argw);
			return SLJIT_NO_ERROR;
		}

		if (push_inst(compiler))
			return compiler->error;
		compiler->last_type = LIT_INS;
		compiler->last_ins = EMIT_DATA_PROCESS_INS(0x08, tmp_reg, arg & 0xf, reg_map[(arg >> 4) & 0xf]);

		if (push_inst(compiler))
			return compiler->error;
		compiler->last_type = LIT_INS;
		compiler->last_ins = EMIT_DATA_TRANSFER(1, flags & ARG_LOAD, reg, tmp_reg, argw);
		return SLJIT_NO_ERROR;
	}

	if (argw < 0 && argw >= -0xfff) {
		if (arg == next_arg && (next_argw <= 0xfff && next_argw >= -0xfff)) {
			SLJIT_ASSERT(flags & ARG_LOAD);
			if (push_inst(compiler))
				return compiler->error;
			compiler->last_type = LIT_INS;
			compiler->last_ins = EMIT_DATA_PROCESS_INS(0x08, TMP_REG3, arg & 0xf, reg_map[(arg >> 4) & 0xf]);

			compiler->cache_arg = arg;
			compiler->cache_argw = 0;

			if (push_inst(compiler))
				return compiler->error;
			compiler->last_type = LIT_INS;
			compiler->last_ins = EMIT_DATA_TRANSFER(0, flags & ARG_LOAD, reg, TMP_REG3, -argw);
			return SLJIT_NO_ERROR;
		}

		if (push_inst(compiler))
			return compiler->error;
		compiler->last_type = LIT_INS;
		compiler->last_ins = EMIT_DATA_PROCESS_INS(0x08, tmp_reg, arg & 0xf, reg_map[(arg >> 4) & 0xf]);

		if (push_inst(compiler))
			return compiler->error;
		compiler->last_type = LIT_INS;
		compiler->last_ins = EMIT_DATA_TRANSFER(0, flags & ARG_LOAD, reg, tmp_reg, -argw);
		return SLJIT_NO_ERROR;
	}

	if (arg == next_arg && ((sljit_uw)argw - (sljit_uw)next_argw <= 0xfff || (sljit_uw)next_argw - (sljit_uw)argw <= 0xfff)) {
		SLJIT_ASSERT(flags & ARG_LOAD);
		if (load_immediate(compiler, TMP_REG3, argw))
			return compiler->error;

		if ((arg & 0xf0) != SLJIT_NO_REG) {
			if (push_inst(compiler))
				return compiler->error;
			compiler->last_type = LIT_INS;
			compiler->last_ins = EMIT_DATA_PROCESS_INS(0x08, TMP_REG3, TMP_REG3, reg_map[(arg >> 4) & 0xf]);
		}

		if (push_inst(compiler))
			return compiler->error;
		compiler->last_type = LIT_INS;
		compiler->last_ins = EMIT_DATA_PROCESS_INS(0x08, TMP_REG3, TMP_REG3, reg_map[arg & 0xf]);

		compiler->cache_arg = arg;
		compiler->cache_argw = argw;

		if (push_inst(compiler))
			return compiler->error;
		compiler->last_type = LIT_INS;
		compiler->last_ins = EMIT_DATA_TRANSFER(1, 1, reg, TMP_REG3, 0);
		return SLJIT_NO_ERROR;
	}

	if (load_immediate(compiler, tmp_reg, argw))
		return compiler->error;

	if ((arg & 0xf0) != SLJIT_NO_REG) {
		if (push_inst(compiler))
			return compiler->error;
		compiler->last_type = LIT_INS;
		compiler->last_ins = EMIT_DATA_PROCESS_INS(0x08, tmp_reg, tmp_reg, reg_map[(arg >> 4) & 0xf]);
	}

	if (push_inst(compiler))
		return compiler->error;
	compiler->last_type = LIT_INS;
	compiler->last_ins = EMIT_DATA_TRANSFER(1, flags & ARG_LOAD, reg, arg & 0xf, reg_map[tmp_reg] | SRC2_IMM);
	return SLJIT_NO_ERROR;
}

#define ORDER_IND_REGS(arg) \
	if ((arg & SLJIT_MEM_FLAG) && ((arg >> 4) & 0xf) > (arg & 0xf)) \
		arg = SLJIT_MEM_FLAG | ((arg << 4) & 0xf0) | ((arg >> 4) & 0xf)

// allow_imm
//  0 - immediate is not allowed, src2 must be a register
//  1 - immediate allowed
//  2 - both immediate and inverted immediate are allowed

static int emit_op(struct sljit_compiler *compiler, int op, int allow_imm,
	int dst, sljit_w dstw,
	int src1, sljit_w src1w,
	int src2, sljit_w src2w)
{
	// arg1 goes to TMP_REG1 or src reg
	// arg2 goes to TMP_REG2, imm or src reg
	// TMP_REG3 can be used for caching
	// result goes to TMP_REG2, so put result uses TMP_REG3

	// We prefers register and simple consts
	int dst_r;
	int src1_r;
	int src2_r = 0;
	int flags = 0;
	int fast_dst = 0;

	compiler->cache_arg = 0;
	compiler->cache_argw = 0;

	// Destination
	dst_r = (dst >= SLJIT_TEMPORARY_REG1 && dst <= TMP_REG3) ? dst : 0;
	if (dst == SLJIT_NO_REG)
		dst_r = TMP_REG2;
	if (dst_r == 0 && getput_arg_fast(compiler, ARG_TEST, TMP_REG2, dst, dstw)) {
		fast_dst = 1;
		dst_r = TMP_REG2;
	}

	// Source 1
	if (src1 >= SLJIT_TEMPORARY_REG1 && src1 <= TMP_REG3)
		src1_r = src1;
	else if (src2 >= SLJIT_TEMPORARY_REG1 && src2 <= TMP_REG3) {
		flags |= ARGS_SWAPPED;
		src1_r = src2;
		src2 = src1;
		src2w = src1w;
	}
	else {
		if (allow_imm && (src1 & SLJIT_IMM)) {
			// The second check will generate a hit
			src2_r = get_immediate(src1w);
			if (src2_r != 0) {
				flags |= ARGS_SWAPPED;
				src1 = src2;
				src1w = src2w;
			}
			if (allow_imm == 2) {
				src2_r = get_immediate(~src1w);
				if (src2_r != 0) {
					flags |= ARGS_SWAPPED | INV_IMM;
					src1 = src2;
					src1w = src2w;
				}
			}
		}

		src1_r = 0;
		if (getput_arg_fast(compiler, ARG_LOAD, TMP_REG1, src1, src1w)) {
			if (compiler->error)
				return compiler->error;
			src1_r = TMP_REG1;
		}
	}

	// Source 2
	if (src2_r == 0) {
		if (src2 >= SLJIT_TEMPORARY_REG1 && src2 <= TMP_REG3)
			src2_r = src2;
		else {
			do {
				if (allow_imm && (src2 & SLJIT_IMM)) {
					src2_r = get_immediate(src2w);
					if (src2_r != 0)
						break;
					if (allow_imm == 2) {
						src2_r = get_immediate(~src2w);
						if (src2_r != 0) {
							flags |= INV_IMM;
							break;
						}
					}
				}

				// src2_r is 0
				if (getput_arg_fast(compiler, ARG_LOAD, TMP_REG2, src2, src2w)) {
					if (compiler->error)
						return compiler->error;
					src2_r = TMP_REG2;
				}
			} while (0);
		}
	}

	// src1_r, src2_r and dst_r can be zero (=unprocessed) or non-zero
	// If they are zero, they must not be registers
	if (src1_r == 0 && src2_r == 0 && dst_r == 0) {
		ORDER_IND_REGS(src1);
		ORDER_IND_REGS(src2);
		ORDER_IND_REGS(dst);
		if (!can_cache(src1, src1w, src2, src2w) && can_cache(src1, src1w, dst, dstw)) {
			SLJIT_ASSERT(!(flags & ARGS_SWAPPED));
			flags |= ARGS_SWAPPED;
			if (getput_arg(compiler, ARG_LOAD, TMP_REG1, src2, src2w, src1, src1w))
				return compiler->error;
			if (getput_arg(compiler, ARG_LOAD, TMP_REG2, src1, src1w, dst, dstw))
				return compiler->error;
		}
		else {
			if (getput_arg(compiler, ARG_LOAD, TMP_REG1, src1, src1w, src2, src2w))
				return compiler->error;
			if (getput_arg(compiler, ARG_LOAD, TMP_REG2, src2, src2w, dst, dstw))
				return compiler->error;
		}
		src1_r = TMP_REG1;
		src2_r = TMP_REG2;
	}
	else if (src1_r == 0 && src2_r == 0) {
		ORDER_IND_REGS(src1);
		ORDER_IND_REGS(src2);
		src1_r = TMP_REG1;
		if (getput_arg(compiler, ARG_LOAD, TMP_REG1, src1, src1w, src2, src2w))
			return compiler->error;
	}
	else if (src1_r == 0 && dst_r == 0) {
		ORDER_IND_REGS(src1);
		ORDER_IND_REGS(dst);
		src1_r = TMP_REG1;
		if (getput_arg(compiler, ARG_LOAD, TMP_REG1, src1, src1w, dst, dstw))
			return compiler->error;
	}
	else if (src2_r == 0 && dst_r == 0) {
		ORDER_IND_REGS(src2);
		ORDER_IND_REGS(dst);
		src2_r = TMP_REG2;
		if (getput_arg(compiler, ARG_LOAD, TMP_REG2, src2, src2w, dst, dstw))
			return compiler->error;
	}

	if (src1_r == 0) {
		src1_r = TMP_REG1;
		if (getput_arg(compiler, ARG_LOAD, TMP_REG1, src1, src1w, 0, 0))
			return compiler->error;
	}

	if (src2_r == 0) {
		src2_r = TMP_REG2;
		if (getput_arg(compiler, ARG_LOAD, TMP_REG2, src2, src2w, 0, 0))
			return compiler->error;
	}

	if (dst_r == 0)
		dst_r = TMP_REG2;

	if (emit_single_op(compiler, op, flags, dst_r, src1_r, src2_r))
		return compiler->error;

	if (dst_r == TMP_REG2 && dst != SLJIT_NO_REG && dst != TMP_REG2) {
		if (fast_dst) {
			if (getput_arg_fast(compiler, 0, dst_r, dst, dstw))
				return compiler->error;
		}
		else {
			if (getput_arg(compiler, 0, dst_r, dst, dstw, 0, 0))
				return compiler->error;
		}
	}
	return SLJIT_NO_ERROR;
}

int sljit_emit_op1(struct sljit_compiler *compiler, int op,
	int dst, sljit_w dstw,
	int src, sljit_w srcw)
{
	FUNCTION_ENTRY();

	SLJIT_ASSERT((op & ~SLJIT_32BIT_OPERATION) >= SLJIT_MOV && (op & ~SLJIT_32BIT_OPERATION) <= SLJIT_NEG);
#ifdef SLJIT_DEBUG
	FUNCTION_CHECK_SRC(src, srcw);
	FUNCTION_CHECK_DST(dst, dstw);
#endif
	sljit_emit_op1_verbose();

	op &= ~SLJIT_32BIT_OPERATION;
	switch (op) {
	case SLJIT_MOV:
	case SLJIT_NOT:
		return emit_op(compiler, OP1_OFFSET + op, 2, dst, dstw, TMP_REG1, 0, src, srcw);

	case SLJIT_NEG:
		return sljit_emit_op2(compiler, SLJIT_SUB, dst, dstw, SLJIT_IMM, 0, src, srcw);
	}

	return SLJIT_NO_ERROR;
}

int sljit_emit_op2(struct sljit_compiler *compiler, int op,
	int dst, sljit_w dstw,
	int src1, sljit_w src1w,
	int src2, sljit_w src2w)
{
	FUNCTION_ENTRY();

	SLJIT_ASSERT((op & ~SLJIT_32BIT_OPERATION) >= SLJIT_ADD && (op & ~SLJIT_32BIT_OPERATION) <= SLJIT_ASHR);
#ifdef SLJIT_DEBUG
	FUNCTION_CHECK_SRC(src1, src1w);
	FUNCTION_CHECK_SRC(src2, src2w);
	FUNCTION_CHECK_DST(dst, dstw);
#endif
	sljit_emit_op2_verbose();

	op &= ~SLJIT_32BIT_OPERATION;
	switch (op) {
	case SLJIT_ADD:
	case SLJIT_ADDC:
	case SLJIT_SUB:
	case SLJIT_SUBC:
	case SLJIT_OR:
	case SLJIT_XOR:
		return emit_op(compiler, op, 1, dst, dstw, src1, src1w, src2, src2w);
	case SLJIT_MUL:
		return emit_op(compiler, op, 0, dst, dstw, src1, src1w, src2, src2w);
	case SLJIT_AND:
		return emit_op(compiler, op, 2, dst, dstw, src1, src1w, src2, src2w);
	case SLJIT_SHL:
	case SLJIT_LSHR:
	case SLJIT_ASHR:
		if (src2 & SLJIT_IMM) {
			compiler->shift_imm = src2w & 0x1f;
			return emit_op(compiler, op, 0, dst, dstw, TMP_REG1, 0, src1, src1w);
		}
		else {
			compiler->shift_imm = 0x20;
			return emit_op(compiler, op, 0, dst, dstw, src1, src1w, src2, src2w);
		}
	}

	return SLJIT_NO_ERROR;
}

// ---------------------------------------------------------------------
//  Conditional instructions
// ---------------------------------------------------------------------

static sljit_uw get_cc(int type)
{
	switch (type) {
	case SLJIT_C_EQUAL:
		return 0x00000000;

	case SLJIT_C_NOT_EQUAL:
		return 0x10000000;

	case SLJIT_C_LESS:
		return 0x30000000;

	case SLJIT_C_NOT_LESS:
		return 0x20000000;

	case SLJIT_C_GREATER:
		return 0x80000000;

	case SLJIT_C_NOT_GREATER:
		return 0x90000000;

	case SLJIT_C_SIG_LESS:
		return 0xb0000000;

	case SLJIT_C_SIG_NOT_LESS:
		return 0xa0000000;

	case SLJIT_C_SIG_GREATER:
		return 0xc0000000;

	case SLJIT_C_SIG_NOT_GREATER:
		return 0xd0000000;

	case SLJIT_C_CARRY:
		return 0x20000000;

	case SLJIT_C_NOT_CARRY:
		return 0x30000000;

	case SLJIT_C_ZERO:
		return 0x00000000;

	case SLJIT_C_NOT_ZERO:
		return 0x10000000;

	case SLJIT_C_OVERFLOW:
		return 0x60000000;

	case SLJIT_C_NOT_OVERFLOW:
		return 0x70000000;

	default: // SLJIT_JUMP
		return 0xe0000000;
	}
}

struct sljit_label* sljit_emit_label(struct sljit_compiler *compiler)
{
	struct sljit_label *label;

	FUNCTION_ENTRY();

	sljit_emit_label_verbose();

	// Flush the pipe to get the real addr
	if (push_inst(compiler))
		return NULL;

	if (compiler->last_label && compiler->last_label->size == compiler->size)
		return compiler->last_label;

	label = ensure_abuf(compiler, sizeof(struct sljit_label));
	TEST_MEM_ERROR2(label);

	label->next = NULL;
	label->size = compiler->size;
	if (compiler->last_label)
		compiler->last_label->next = label;
	else
		compiler->labels = label;
	compiler->last_label = label;

	return label;
}

struct sljit_jump* sljit_emit_jump(struct sljit_compiler *compiler, int type)
{
	struct sljit_jump *jump;

	FUNCTION_ENTRY();
	SLJIT_ASSERT((type & ~0x1ff) == 0);
	SLJIT_ASSERT((type & 0xff) >= SLJIT_C_EQUAL && (type & 0xff) <= SLJIT_CALL3);

	sljit_emit_jump_verbose();

	// Flush the pipe to get the real addr
	if (push_inst(compiler))
		return NULL;

	jump = ensure_abuf(compiler, sizeof(struct sljit_jump));
	TEST_MEM_ERROR2(jump);

	jump->next = NULL;
	jump->flags = type & SLJIT_LONG_JUMP;
	type &= 0xff;
	if (compiler->last_jump)
		compiler->last_jump->next = jump;
	else
		compiler->jumps = jump;
	compiler->last_jump = jump;

	// In ARM, we don't need to touch the arguments

	if (!jump->flags) {
		if (type >= SLJIT_CALL0)
			jump->flags |= IS_BL;
		compiler->last_type = LIT_UCINS;
		compiler->last_ins = get_cc(type) | 0x059ff000;
		compiler->last_imm = 0;
	}
	else {
		compiler->last_type = LIT_UCINS;
		compiler->last_ins = get_cc(type) | 0x059ff000;
		compiler->last_imm = 0;
		compiler->patches++;
	}

	if (type >= SLJIT_CALL0)
		if (emit_mov_ln_pc(compiler))
			return NULL;

	/* now we can fill the address of the jump */
	jump->addr = compiler->size;
	return jump;
}

int sljit_emit_ijump(struct sljit_compiler *compiler, int type, int src, sljit_w srcw)
{
	struct sljit_jump *jump;

	FUNCTION_ENTRY();
	SLJIT_ASSERT(type >= SLJIT_JUMP && type <= SLJIT_CALL3);
#ifdef SLJIT_DEBUG
	FUNCTION_CHECK_SRC(src, srcw);
#endif
	sljit_emit_ijump_verbose();

	// Flush the pipe to get the real addr
	if (push_inst(compiler))
		return compiler->error;

	// In ARM, we don't need to touch the arguments

	if (src & SLJIT_IMM) {
		jump = ensure_abuf(compiler, sizeof(struct sljit_jump));
		TEST_MEM_ERROR(jump);

		jump->next = NULL;
		jump->flags = IS_FIXED | ((type >= SLJIT_CALL0) ? IS_BL : 0);
		jump->target = srcw;
		if (compiler->last_jump)
			compiler->last_jump->next = jump;
		else
			compiler->jumps = jump;
		compiler->last_jump = jump;

		compiler->last_type = LIT_CINS;
		compiler->last_ins = EMIT_DATA_TRANSFER(1, 1, TMP_PC, TMP_PC, 0);
		compiler->last_imm = srcw;

		if (type >= SLJIT_CALL0)
			if (emit_mov_ln_pc(compiler))
				return compiler->error;

		jump->addr = compiler->size;
	}
	else {
		if (emit_op(compiler, OP1_OFFSET + SLJIT_MOV, 2, TMP_REG2, 0, TMP_REG1, 0, src, srcw))
			return compiler->error;
		SLJIT_ASSERT((compiler->last_ins & 0x0c00f000) == (0x00000000 | (reg_map[TMP_REG2] << 12)) || (compiler->last_ins & 0x0c00f000) == (0x04000000 | (reg_map[TMP_REG2] << 12)));
		compiler->last_ins |= 0x0000f000;

		if (type >= SLJIT_CALL0)
			if (emit_mov_ln_pc(compiler))
				return compiler->error;
	}

	return SLJIT_NO_ERROR;
}

int sljit_emit_cond_set(struct sljit_compiler *compiler, int dst, sljit_w dstw, int type)
{
	int reg;

	FUNCTION_ENTRY();
	SLJIT_ASSERT(type >= SLJIT_C_EQUAL && type <= SLJIT_C_NOT_OVERFLOW);
#ifdef SLJIT_DEBUG
	FUNCTION_CHECK_DST(dst, dstw);
#endif
	sljit_emit_set_cond_verbose();

	if (dst == SLJIT_NO_REG)
		return SLJIT_NO_ERROR;

	if (dst >= SLJIT_TEMPORARY_REG1 && dst <= SLJIT_GENERAL_REG3)
		reg = dst;
	else
		reg = TMP_REG2;

	if (push_inst(compiler))
		return compiler->error;
	compiler->last_type = LIT_INS;
	compiler->last_ins = 0xe3a00000 | (reg_map[reg] << 12);

	if (push_inst(compiler))
		return compiler->error;
	compiler->last_type = LIT_INS;
	compiler->last_ins = 0x03a00001 | (reg_map[reg] << 12) | get_cc(type);

	if (reg == TMP_REG2)
		return emit_op(compiler, OP1_OFFSET + SLJIT_MOV, 2, dst, dstw, TMP_REG1, 0, TMP_REG2, 0);
	else
		return SLJIT_NO_ERROR;
}

struct sljit_const* sljit_emit_const(struct sljit_compiler *compiler, int dst, sljit_w dstw, sljit_w initval)
{
	struct sljit_const *const_;
	int reg;

	FUNCTION_ENTRY();
#ifdef SLJIT_DEBUG
	FUNCTION_CHECK_DST(dst, dstw);
#endif
	sljit_emit_const_verbose();

	// Flush the pipe to get the real addr
	if (push_inst(compiler))
		return NULL;

	const_ = ensure_abuf(compiler, sizeof(struct sljit_const));
	TEST_MEM_ERROR2(const_);

	const_->next = NULL;
	const_->addr = compiler->size;
	if (compiler->last_const)
		compiler->last_const->next = const_;
	else
		compiler->consts = const_;
	compiler->last_const = const_;

	reg = (dst >= SLJIT_TEMPORARY_REG1 && dst <= SLJIT_TEMPORARY_REG2) ? dst : TMP_REG2;

	compiler->last_type = LIT_UCINS;
	compiler->last_ins = EMIT_DATA_TRANSFER(1, 1, reg, TMP_PC, 0);
	compiler->last_imm = initval;
	compiler->patches++;

	if (reg == TMP_REG2 && dst != SLJIT_NO_REG)
		if (emit_op(compiler, OP1_OFFSET + SLJIT_MOV, 2, dst, dstw, TMP_REG1, 0, TMP_REG2, 0))
			return NULL;
	return const_;
}

void sljit_set_jump_addr(sljit_uw addr, sljit_uw new_addr)
{
	sljit_uw *ptr = (sljit_uw*)addr;
	sljit_uw *inst = (sljit_uw*)ptr[0];
	sljit_uw mov_pc = ptr[1];
	sljit_w diff = (sljit_w)(((sljit_w)new_addr - (sljit_w)(inst + 2)) >> 2);

	INVALIDATE_INSTRUCTION_CACHE(*inst);

	if (diff <= 0x7fffff && diff >= -0x800000)
		// Turn to branch
		*inst = (mov_pc & 0xf0000000) | 0x0a000000 | (diff & 0xffffff);
	else {
		// Get the position of the constant
		if (mov_pc & (1 << 23))
			ptr = inst + ((mov_pc & 0xfff) >> 2) + 2;
		else
			ptr = inst + 1;

		*inst = mov_pc;
		*ptr = new_addr;
	}
}

void sljit_set_const(sljit_uw addr, sljit_w constant)
{
	sljit_uw *ptr = (sljit_uw*)addr;
	sljit_uw *inst = (sljit_uw*)ptr[0];
	sljit_uw mov_pc = ptr[1];
	sljit_uw src2;

	INVALIDATE_INSTRUCTION_CACHE(*inst);

	src2 = get_immediate(constant);
	if (src2 != 0) {
		*inst = 0xe3a00000 | (mov_pc & 0xf000) | src2;
		return;
	}

	src2 = get_immediate(~constant);
	if (src2 != 0) {
		*inst = 0xe3e00000 | (mov_pc & 0xf000) | src2;
		return;
	}

	if (mov_pc & (1 << 23))
		ptr = inst + ((mov_pc & 0xfff) >> 2) + 2;
	else
		ptr = inst + 1;

	*inst = mov_pc;
	*ptr = constant;
}
