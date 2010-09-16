/*
 *    Stack-less Just-In-Time compiler
 *
 *    Copyright 2009-2010 Zoltan Herczeg (hzmester@freemail.hu). All rights reserved.
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

char* sljit_get_platform_name()
{
#ifdef SLJIT_CONFIG_PPC_32
	return "ppc-32";
#else
	return "ppc-64";
#endif
}

// Length of an instruction word
// Both for ppc-32 and ppc-64
typedef unsigned int sljit_i;

#define TMP_REG1	(SLJIT_NO_REGISTERS + 1)
#define TMP_REG2	(SLJIT_NO_REGISTERS + 2)
#define TMP_REG3	(SLJIT_NO_REGISTERS + 3)
#define ZERO_REG	(SLJIT_NO_REGISTERS + 4)
#define REAL_STACK_PTR	(SLJIT_NO_REGISTERS + 5)

#define TMP_FREG1       (SLJIT_FLOAT_REG4 + 1)
#define TMP_FREG2       (SLJIT_FLOAT_REG4 + 2)

// ---------------------------------------------------------------------
//  Instrucion forms
// ---------------------------------------------------------------------
// The instruction includes the AL condition
// INST_NAME - CONDITIONAL remove this flag
#define D(d)		(reg_map[d] << 21)
#define S(s)		(reg_map[s] << 21)
#define A(a)		(reg_map[a] << 16)
#define B(b)		(reg_map[b] << 11)
#define C(c)		(reg_map[c] << 6)
#define FD(fd)		((fd) << 21)
#define FA(fa)		((fa) << 16)
#define FB(fb)		((fb) << 11)
#define FC(fc)		((fc) << 6)
#define IMM(imm)	((imm) & 0xffff)
#define CRD(d)		((d) << 21)
#define CRA(a)		((a) << 16)
#define CRB(b)		((b) << 11)

// Instruction bit sections
// OE and Rc flag (see ALT_SET_FLAGS)
#define OERC(flags)		(((flags & ALT_SET_FLAGS) >> 14) | ((flags & ALT_SET_FLAGS) >> 4))
// Rc flag (see ALT_SET_FLAGS)
#define RC(flags)		((flags & ALT_SET_FLAGS) >> 14)
#define HI(opcode)	((opcode) << 26)
#define LO(opcode)	((opcode) << 1)

#define ADD		(HI(31) | LO(266))
#define ADDC		(HI(31) | LO(10))
#define ADDE		(HI(31) | LO(138))
#define ADDI		(HI(14))
#define ADDIC		(HI(13))
#define ADDIS		(HI(15))
#define ADDME		(HI(31) | LO(234))
#define AND		(HI(31) | LO(28))
#define ANDI		(HI(28))
#define ANDIS		(HI(29))
#define Bx		(HI(18))
#define BCx		(HI(16))
#define BCCTR		(HI(19) | LO(528) | (3 << 11))
#define BLR		(HI(19) | LO(16) | (0x14 << 21))
#define CMPL		(HI(31) | LO(32))
#define CMPLI		(HI(10))
#define CROR		(HI(19) | LO(449))
#define EXTSB		(HI(31) | LO(954))
#define EXTSH		(HI(31) | LO(922))
#define EXTSW		(HI(31) | LO(986))
#define FABS		(HI(63) | LO(264))
#define FADD		(HI(63) | LO(21))
#define FCMPU		(HI(63) | LO(0))
#define FDIV		(HI(63) | LO(18))
#define FMR		(HI(63) | LO(72))
#define FMUL		(HI(63) | LO(25))
#define FNEG		(HI(63) | LO(40))
#define FSUB		(HI(63) | LO(20))
#define LD		(HI(58) | 0)
#define LFD		(HI(50))
#define LFDUX		(HI(31) | LO(631))
#define LFDX		(HI(31) | LO(599))
#define LWZ		(HI(32))
#define MFCR		(HI(31) | LO(19))
#define MFLR		(HI(31) | LO(339) | 0x80000)
#define MFXER		(HI(31) | LO(339) | 0x10000)
#define MTCTR		(HI(31) | LO(467) | 0x90000)
#define MTLR		(HI(31) | LO(467) | 0x80000)
#define MTXER		(HI(31) | LO(467) | 0x10000)
#define MULLD		(HI(31) | LO(233))
#define MULLI		(HI(7))
#define MULLW		(HI(31) | LO(235))
#define NEG		(HI(31) | LO(104))
#define NOR		(HI(31) | LO(124))
#define OR		(HI(31) | LO(444))
#define ORI		(HI(24))
#define ORIS		(HI(25))
#define RLDICL		(HI(30))
#define RLWINM		(HI(21))
#define SLD		(HI(31) | LO(27))
#define SLW		(HI(31) | LO(24))
#define SRAD		(HI(31) | LO(794))
#define SRADI		(HI(31) | LO(413 << 1))
#define SRAW		(HI(31) | LO(792))
#define SRAWI		(HI(31) | LO(824))
#define SRD		(HI(31) | LO(539))
#define SRW		(HI(31) | LO(536))
#define STD		(HI(62) | 0)
#define STDU		(HI(62) | 1)
#define STDUX		(HI(31) | LO(181))
#define STFD		(HI(54))
#define STFDUX		(HI(31) | LO(759))
#define STFDX		(HI(31) | LO(727))
#define STW		(HI(36))
#define STWU		(HI(37))
#define STWUX		(HI(31) | LO(183))
#define SUBF		(HI(31) | LO(40))
#define SUBFC		(HI(31) | LO(8))
#define SUBFE		(HI(31) | LO(136))
#define SUBFIC		(HI(8))
#define XOR		(HI(31) | LO(316))
#define XORI		(HI(26))
#define XORIS		(HI(27))

#define SIMM_MAX	(0x7fff)
#define SIMM_MIN	(-0x8000)
#define UIMM_MAX	(0xffff)

// SLJIT_LOCALS_REG is not the real stack register, since it must
// point to the head of the stack chain
static SLJIT_CONST sljit_ub reg_map[SLJIT_NO_REGISTERS + 6] = {
  0, 3, 4, 5, 6, 7, 29, 28, 27, 26, 25, 31, 8, 9, 10, 30, 1
};

static int push_inst(struct sljit_compiler *compiler, sljit_i ins)
{
	sljit_i *ptr = (sljit_i*)ensure_buf(compiler, sizeof(sljit_i));
	FAIL_IF(!ptr);
	*ptr = ins;
	compiler->size++;
	return SLJIT_SUCCESS;
}

static SLJIT_INLINE int optimize_jump(struct sljit_jump *jump, sljit_i *code_ptr, sljit_i *code)
{
	sljit_w diff;
	sljit_uw absolute_addr;

	if (jump->flags & SLJIT_REWRITABLE_JUMP)
		return 0;

	if (jump->flags & JUMP_ADDR)
		absolute_addr = jump->target;
	else {
		SLJIT_ASSERT(jump->flags & JUMP_LABEL);
		absolute_addr = (sljit_uw)(code + jump->label->size);
	}
	diff = ((sljit_w)absolute_addr - (sljit_w)(code_ptr)) & ~0x3l;

	if (jump->flags & UNCOND_ADDR) {
		if (diff <= 0x01ffffff && diff >= -0x02000000) {
			jump->flags |= PATCH_B;
			return 1;
		}
		if (absolute_addr <= 0x03ffffff) {
			jump->flags |= PATCH_B | ABSOLUTE_B;
			return 1;
		}
	}
	else {
		if (diff <= 0x7fff && diff >= -0x8000) {
			jump->flags |= PATCH_B;
			return 1;
		}
		if (absolute_addr <= 0xffff) {
			jump->flags |= PATCH_B | ABSOLUTE_B;
			return 1;
		}
	}
	return 0;
}

void* sljit_generate_code(struct sljit_compiler *compiler)
{
	struct sljit_memory_fragment *buf;
	sljit_i *code;
	sljit_i *code_ptr;
	sljit_i *buf_ptr;
	sljit_i *buf_end;
	sljit_uw word_count;
	sljit_uw addr;

	struct sljit_label *label;
	struct sljit_jump *jump;
	struct sljit_const *const_;

	FUNCTION_ENTRY();

	SLJIT_ASSERT(compiler->size > 0);
	reverse_buf(compiler);

#ifdef SLJIT_CONFIG_PPC_64
	compiler->size += (compiler->size & 0x1) ? 3 : 2;
#endif
	code = (sljit_i*)SLJIT_MALLOC_EXEC(compiler->size * sizeof(sljit_uw));
	PTR_FAIL_WITH_EXEC_IF(code);
	buf = compiler->buf;

	code_ptr = code;
	word_count = 0;
	label = compiler->labels;
	jump = compiler->jumps;
	const_ = compiler->consts;
	do {
		buf_ptr = (sljit_i*)buf->memory;
		buf_end = buf_ptr + (buf->used_size >> 2);
		do {
			*code_ptr = *buf_ptr++;
			SLJIT_ASSERT(!label || label->size >= word_count);
			SLJIT_ASSERT(!jump || jump->addr >= word_count);
			SLJIT_ASSERT(!const_ || const_->addr >= word_count);
			// These structures are ordered by their address
			if (label && label->size == word_count) {
				// Just recording the address
				label->addr = (sljit_uw)code_ptr;
				label->size = code_ptr - code;
				label = label->next;
			}
			if (jump && jump->addr == word_count) {
				SLJIT_ASSERT(jump->flags & (JUMP_LABEL | JUMP_ADDR));
#ifdef SLJIT_CONFIG_PPC_32
				jump->addr = (sljit_uw)(code_ptr - 3);
#else
				jump->addr = (sljit_uw)(code_ptr - 6);
#endif
				if (optimize_jump(jump, code_ptr, code)) {
#ifdef SLJIT_CONFIG_PPC_32
					code_ptr[-3] = code_ptr[0];
					code_ptr -= 3;
#else
					code_ptr[-6] = code_ptr[0];
					code_ptr -= 6;
#endif
				}
				jump = jump->next;
			}
			if (const_ && const_->addr == word_count) {
				// Just recording the address
				const_->addr = (sljit_uw)code_ptr;
				const_ = const_->next;
			}
			code_ptr ++;
			word_count ++;
		} while (buf_ptr < buf_end);

		buf = buf->next;
	} while (buf);

	if (label && label->size == word_count) {
		label->addr = (sljit_uw)code_ptr;
		label->size = code_ptr - code;
		label = label->next;
	}

	SLJIT_ASSERT(!label);
	SLJIT_ASSERT(!jump);
	SLJIT_ASSERT(!const_);
#ifdef SLJIT_CONFIG_PPC_64
	SLJIT_ASSERT(code_ptr - code <= (int)compiler->size - ((compiler->size & 0x1) ? 3 : 2));
#else
	SLJIT_ASSERT(code_ptr - code <= (int)compiler->size);
#endif

	jump = compiler->jumps;
	while (jump) {
		do {
			addr = (jump->flags & JUMP_LABEL) ? jump->label->addr : jump->target;
			buf_ptr = (sljit_i*)jump->addr;
			if (!(jump->flags & SLJIT_REWRITABLE_JUMP) && (jump->flags & PATCH_B)) {
				if (jump->flags & UNCOND_ADDR) {
					if (!(jump->flags & ABSOLUTE_B)) {
						addr = addr - jump->addr;
						SLJIT_ASSERT((sljit_w)addr <= 0x01ffffff && (sljit_w)addr >= -0x02000000);
						*buf_ptr = Bx | (addr & 0x03fffffc) | ((*buf_ptr) & 0x1);
					}
					else {
						SLJIT_ASSERT(addr <= 0x03ffffff);
						*buf_ptr = Bx | (addr & 0x03fffffc) | 0x2 | ((*buf_ptr) & 0x1);
					}
				}
				else {
					if (!(jump->flags & ABSOLUTE_B)) {
						addr = addr - jump->addr;
						SLJIT_ASSERT((sljit_w)addr <= 0x7fff && (sljit_w)addr >= -0x8000);
						*buf_ptr = BCx | (addr & 0xfffc) | ((*buf_ptr) & 0x03ff0001);
					}
					else {
						addr = addr & ~0x3l;
						SLJIT_ASSERT(addr <= 0xffff);
						*buf_ptr = BCx | (addr & 0xfffc) | 0x2 | ((*buf_ptr) & 0x03ff0001);
					}

				}
				break;
			}
			// Set the fields of immediate loads
#ifdef SLJIT_CONFIG_PPC_32
			buf_ptr[0] = (buf_ptr[0] & 0xffff0000) | ((addr >> 16) & 0xffff);
			buf_ptr[1] = (buf_ptr[1] & 0xffff0000) | (addr & 0xffff);
#else
			buf_ptr[0] = (buf_ptr[0] & 0xffff0000) | ((addr >> 48) & 0xffff);
			buf_ptr[1] = (buf_ptr[1] & 0xffff0000) | ((addr >> 32) & 0xffff);
			buf_ptr[3] = (buf_ptr[3] & 0xffff0000) | ((addr >> 16) & 0xffff);
			buf_ptr[4] = (buf_ptr[4] & 0xffff0000) | (addr & 0xffff);
#endif
		} while (0);
		jump = jump->next;
	}

	SLJIT_CACHE_FLUSH(code, code_ptr);
	compiler->error = SLJIT_ERR_COMPILED;

#ifdef SLJIT_CONFIG_PPC_64
	if (((sljit_w)code_ptr) & 0x4)
		code_ptr++;
	*(void**)code_ptr = code;
	return code_ptr;
#else
	return code;
#endif
}

static int load_immediate(struct sljit_compiler *compiler, int reg, sljit_w imm);
static int emit_op(struct sljit_compiler *compiler, int op, int inp_flags,
	int dst, sljit_w dstw,
	int src1, sljit_w src1w,
	int src2, sljit_w src2w);

int sljit_emit_enter(struct sljit_compiler *compiler, int args, int temporaries, int generals, int local_size)
{
	FUNCTION_ENTRY();
	// TODO: support the others
	SLJIT_ASSERT(args >= 0 && args <= 3);
	SLJIT_ASSERT(temporaries >= 0 && temporaries <= SLJIT_NO_TMP_REGISTERS);
	SLJIT_ASSERT(generals >= 0 && generals <= SLJIT_NO_GEN_REGISTERS);
	SLJIT_ASSERT(args <= generals);
	SLJIT_ASSERT(local_size >= 0 && local_size <= SLJIT_MAX_LOCAL_SIZE);

	sljit_emit_enter_verbose();

	compiler->temporaries = temporaries;
	compiler->generals = generals;

	FAIL_IF(push_inst(compiler, MFLR | D(0)));
#ifdef SLJIT_CONFIG_PPC_32
	FAIL_IF(push_inst(compiler, STW | S(SLJIT_LOCALS_REG) | A(REAL_STACK_PTR) | IMM(-(int)(sizeof(sljit_w))) ));
	FAIL_IF(push_inst(compiler, STW | S(ZERO_REG) | A(REAL_STACK_PTR) | IMM(-2 * (int)(sizeof(sljit_w))) ));
	if (generals >= 1)
		FAIL_IF(push_inst(compiler, STW | S(SLJIT_GENERAL_REG1) | A(REAL_STACK_PTR) | IMM(-3 * (int)(sizeof(sljit_w))) ));
	if (generals >= 2)
		FAIL_IF(push_inst(compiler, STW | S(SLJIT_GENERAL_REG2) | A(REAL_STACK_PTR) | IMM(-4 * (int)(sizeof(sljit_w))) ));
	if (generals >= 3)
		FAIL_IF(push_inst(compiler, STW | S(SLJIT_GENERAL_REG3) | A(REAL_STACK_PTR) | IMM(-5 * (int)(sizeof(sljit_w))) ));
	if (generals >= 4)
		FAIL_IF(push_inst(compiler, STW | S(SLJIT_GENERAL_EREG1) | A(REAL_STACK_PTR) | IMM(-6 * (int)(sizeof(sljit_w))) ));
	if (generals >= 5)
		FAIL_IF(push_inst(compiler, STW | S(SLJIT_GENERAL_EREG2) | A(REAL_STACK_PTR) | IMM(-7 * (int)(sizeof(sljit_w))) ));
	FAIL_IF(push_inst(compiler, STW | S(0) | A(REAL_STACK_PTR) | IMM(sizeof(sljit_w)) ));
#else
	FAIL_IF(push_inst(compiler, STD | S(SLJIT_LOCALS_REG) | A(REAL_STACK_PTR) | IMM(-(int)(sizeof(sljit_w))) ));
	FAIL_IF(push_inst(compiler, STD | S(ZERO_REG) | A(REAL_STACK_PTR) | IMM(-2 * (int)(sizeof(sljit_w))) ));
	if (generals >= 1)
		FAIL_IF(push_inst(compiler, STD | S(SLJIT_GENERAL_REG1) | A(REAL_STACK_PTR) | IMM(-3 * (int)(sizeof(sljit_w))) ));
	if (generals >= 2)
		FAIL_IF(push_inst(compiler, STD | S(SLJIT_GENERAL_REG2) | A(REAL_STACK_PTR) | IMM(-4 * (int)(sizeof(sljit_w))) ));
	if (generals >= 3)
		FAIL_IF(push_inst(compiler, STD | S(SLJIT_GENERAL_REG3) | A(REAL_STACK_PTR) | IMM(-5 * (int)(sizeof(sljit_w))) ));
	if (generals >= 4)
		FAIL_IF(push_inst(compiler, STD | S(SLJIT_GENERAL_EREG1) | A(REAL_STACK_PTR) | IMM(-6 * (int)(sizeof(sljit_w))) ));
	if (generals >= 5)
		FAIL_IF(push_inst(compiler, STD | S(SLJIT_GENERAL_EREG2) | A(REAL_STACK_PTR) | IMM(-7 * (int)(sizeof(sljit_w))) ));
	FAIL_IF(push_inst(compiler, STD | S(0)| A(REAL_STACK_PTR) | IMM(2 * sizeof(sljit_w)) ));
#endif

	FAIL_IF(push_inst(compiler, ADDI | D(ZERO_REG) | A(0) | 0));
	if (args >= 1)
		FAIL_IF(push_inst(compiler, OR | S(SLJIT_TEMPORARY_REG1) | A(SLJIT_GENERAL_REG1) | B(SLJIT_TEMPORARY_REG1)));
	if (args >= 2)
		FAIL_IF(push_inst(compiler, OR | S(SLJIT_TEMPORARY_REG2) | A(SLJIT_GENERAL_REG2) | B(SLJIT_TEMPORARY_REG2)));
	if (args >= 3)
		FAIL_IF(push_inst(compiler, OR | S(SLJIT_TEMPORARY_REG3) | A(SLJIT_GENERAL_REG3) | B(SLJIT_TEMPORARY_REG3)));

#ifdef SLJIT_CONFIG_PPC_32
	compiler->local_size = (2 + generals + 1) * sizeof(sljit_w) + local_size;
#else
	compiler->local_size = (2 + generals + 7) * sizeof(sljit_w) + local_size;
#endif
	compiler->local_size = (compiler->local_size + 15) & ~0xf;

#ifdef SLJIT_CONFIG_PPC_32
	if (compiler->local_size <= SIMM_MAX)
		FAIL_IF(push_inst(compiler, STWU | S(REAL_STACK_PTR) | A(REAL_STACK_PTR) | IMM(-compiler->local_size)));
	else {
		FAIL_IF(load_immediate(compiler, 0, -compiler->local_size));
		FAIL_IF(push_inst(compiler, STWUX | S(REAL_STACK_PTR) | A(REAL_STACK_PTR) | B(0)));
	}
	FAIL_IF(push_inst(compiler, ADDI | D(SLJIT_LOCALS_REG) | A(REAL_STACK_PTR) | IMM(2 * sizeof(sljit_w))));
#else
	if (compiler->local_size <= SIMM_MAX)
		FAIL_IF(push_inst(compiler, STDU | S(REAL_STACK_PTR) | A(REAL_STACK_PTR) | IMM(-compiler->local_size)));
	else {
		FAIL_IF(load_immediate(compiler, 0, -compiler->local_size));
		FAIL_IF(push_inst(compiler, STDUX | S(REAL_STACK_PTR) | A(REAL_STACK_PTR) | B(0)));
	}
	FAIL_IF(push_inst(compiler, ADDI | D(SLJIT_LOCALS_REG) | A(REAL_STACK_PTR) | IMM(7 * sizeof(sljit_w))));
#endif

	return SLJIT_SUCCESS;
}

void sljit_fake_enter(struct sljit_compiler *compiler, int args, int temporaries, int generals, int local_size)
{
	SLJIT_ASSERT(args >= 0 && args <= 3);
	SLJIT_ASSERT(temporaries >= 0 && temporaries <= SLJIT_NO_TMP_REGISTERS);
	SLJIT_ASSERT(generals >= 0 && generals <= SLJIT_NO_GEN_REGISTERS);
	SLJIT_ASSERT(args <= generals);
	SLJIT_ASSERT(local_size >= 0 && local_size <= SLJIT_MAX_LOCAL_SIZE);

	sljit_fake_enter_verbose();

	compiler->temporaries = temporaries;
	compiler->generals = generals;

#ifdef SLJIT_CONFIG_PPC_32
	compiler->local_size = (2 + generals + 1) * sizeof(sljit_w) + local_size;
#else
	compiler->local_size = (2 + generals + 7) * sizeof(sljit_w) + local_size;
#endif
	compiler->local_size = (compiler->local_size + 15) & ~0xf;
}

int sljit_emit_return(struct sljit_compiler *compiler, int src, sljit_w srcw)
{
	FUNCTION_ENTRY();
#ifdef SLJIT_DEBUG
	if (src != SLJIT_UNUSED) {
		FUNCTION_CHECK_SRC(src, srcw);
	}
	else
		SLJIT_ASSERT(srcw == 0);
#endif

	sljit_emit_return_verbose();

	if (src != SLJIT_PREF_RET_REG && src != SLJIT_UNUSED)
		FAIL_IF(emit_op(compiler, SLJIT_MOV, 0 /* WORD_DATA */, SLJIT_PREF_RET_REG, 0, TMP_REG1, 0, src, srcw));

	if (compiler->local_size <= SIMM_MAX)
		FAIL_IF(push_inst(compiler, ADDI | D(REAL_STACK_PTR) | A(REAL_STACK_PTR) | IMM(compiler->local_size)));
	else {
		FAIL_IF(load_immediate(compiler, 0, compiler->local_size));
		FAIL_IF(push_inst(compiler, ADD | D(REAL_STACK_PTR) | A(REAL_STACK_PTR) | B(0)));
	}

#ifdef SLJIT_CONFIG_PPC_32
	FAIL_IF(push_inst(compiler, LWZ | D(0) | A(REAL_STACK_PTR) | IMM(sizeof(sljit_w))));
	if (compiler->generals >= 5)
		FAIL_IF(push_inst(compiler, LWZ | D(SLJIT_GENERAL_EREG2) | A(REAL_STACK_PTR) | IMM(-7 * (int)(sizeof(sljit_w))) ));
	if (compiler->generals >= 4)
		FAIL_IF(push_inst(compiler, LWZ | D(SLJIT_GENERAL_EREG1) | A(REAL_STACK_PTR) | IMM(-6 * (int)(sizeof(sljit_w))) ));
	if (compiler->generals >= 3)
		FAIL_IF(push_inst(compiler, LWZ | D(SLJIT_GENERAL_REG3) | A(REAL_STACK_PTR) | IMM(-5 * (int)(sizeof(sljit_w))) ));
	if (compiler->generals >= 2)
		FAIL_IF(push_inst(compiler, LWZ | D(SLJIT_GENERAL_REG2) | A(REAL_STACK_PTR) | IMM(-4 * (int)(sizeof(sljit_w))) ));
	if (compiler->generals >= 1)
		FAIL_IF(push_inst(compiler, LWZ | D(SLJIT_GENERAL_REG1) | A(REAL_STACK_PTR) | IMM(-3 * (int)(sizeof(sljit_w))) ));
	FAIL_IF(push_inst(compiler, LWZ | D(ZERO_REG) | A(REAL_STACK_PTR) | IMM(-2 * (int)(sizeof(sljit_w))) ));
	FAIL_IF(push_inst(compiler, LWZ | D(SLJIT_LOCALS_REG) | A(REAL_STACK_PTR) | IMM(-(int)(sizeof(sljit_w))) ));
#else
	FAIL_IF(push_inst(compiler, LD | D(0) | A(REAL_STACK_PTR) | IMM(2 * sizeof(sljit_w))));
	if (compiler->generals >= 5)
		FAIL_IF(push_inst(compiler, LD | D(SLJIT_GENERAL_EREG2) | A(REAL_STACK_PTR) | IMM(-7 * (int)(sizeof(sljit_w))) ));
	if (compiler->generals >= 4)
		FAIL_IF(push_inst(compiler, LD | D(SLJIT_GENERAL_EREG1) | A(REAL_STACK_PTR) | IMM(-6 * (int)(sizeof(sljit_w))) ));
	if (compiler->generals >= 3)
		FAIL_IF(push_inst(compiler, LD | D(SLJIT_GENERAL_REG3) | A(REAL_STACK_PTR) | IMM(-5 * (int)(sizeof(sljit_w))) ));
	if (compiler->generals >= 2)
		FAIL_IF(push_inst(compiler, LD | D(SLJIT_GENERAL_REG2) | A(REAL_STACK_PTR) | IMM(-4 * (int)(sizeof(sljit_w))) ));
	if (compiler->generals >= 1)
		FAIL_IF(push_inst(compiler, LD | D(SLJIT_GENERAL_REG1) | A(REAL_STACK_PTR) | IMM(-3 * (int)(sizeof(sljit_w))) ));
	FAIL_IF(push_inst(compiler, LD | D(ZERO_REG) | A(REAL_STACK_PTR) | IMM(-2 * (int)(sizeof(sljit_w))) ));
	FAIL_IF(push_inst(compiler, LD | D(SLJIT_LOCALS_REG) | A(REAL_STACK_PTR) | IMM(-(int)(sizeof(sljit_w))) ));
#endif

	FAIL_IF(push_inst(compiler, MTLR | S(0)));
	FAIL_IF(push_inst(compiler, BLR));

	return SLJIT_SUCCESS;
}

// ---------------------------------------------------------------------
//  Operators
// ---------------------------------------------------------------------

// inp_flags:

// Creates an index in data_transfer_insts array
#define WORD_DATA	0x00
#define BYTE_DATA	0x01
#define HALF_DATA	0x02
#define INT_DATA	0x03
#define SIGNED_DATA	0x04
#define LOAD_DATA	0x08
#define WRITE_BACK	0x10
#define INDEXED		0x20

#define MEM_MASK	0x3f

// Other inp_flags

#define ARG_TEST	0x0100
#define ALT_FORM1	0x0200
#define ALT_FORM2	0x0400
#define ALT_FORM3	0x0800
#define ALT_FORM4	0x1000
// integer opertion and set flags -> requires exts on 64 bit systems
#define ALT_SIGN_EXT	0x2000
// this flag affects the R() and OR() macros
#define ALT_SET_FLAGS	0x4000

// i/x - immediate/indexed form
// n/w - no write-back / write-back (1 bit)
// s/l - store/load (1 bit)
// u/s - signed/unsigned (1 bit)
// w/b/h/i - word/byte/half/int allowed (2 bit)
// It contans 32 items, but not all are different

// 64 bit only: [reg+imm] must be aligned to 4 bytes
#define ADDR_MODE2	0x10000
// 64-bit only: there is no lwau instruction
#define UPDATE_REQ	0x20000

#ifdef SLJIT_CONFIG_PPC_32
#define ARCH_DEPEND(a, b)	a
#define GET_INST_CODE(inst)	(inst)
#else
#define ARCH_DEPEND(a, b)	b
#define GET_INST_CODE(index)	((inst) & ~(ADDR_MODE2 | UPDATE_REQ))
#endif


static SLJIT_CONST sljit_i data_transfer_insts[64] = {

// No write-back

/* i n s u w */ ARCH_DEPEND(HI(36) /* stw */, HI(62) | ADDR_MODE2 | 0x0 /* std */),
/* i n s u b */ HI(38) /* stb */,
/* i n s u h */ HI(44) /* sth*/,
/* i n s u i */ HI(36) /* stw */,

/* i n s s w */ ARCH_DEPEND(HI(36) /* stw */, HI(62) | ADDR_MODE2 | 0x0 /* std */),
/* i n s s b */ HI(38) /* stb */,
/* i n s s h */ HI(44) /* sth*/,
/* i n s s i */ HI(36) /* stw */,

/* i n l u w */ ARCH_DEPEND(HI(32) /* lwz */, HI(58) | ADDR_MODE2 | 0x0 /* ld */),
/* i n l u b */ HI(34) /* lbz */,
/* i n l u h */ HI(40) /* lhz */,
/* i n l u i */ HI(32) /* lwz */,

/* i n l s w */ ARCH_DEPEND(HI(32) /* lwz */, HI(58) | ADDR_MODE2 | 0x0 /* ld */),
/* i n l s b */ HI(34) /* lbz */ /* EXTS_REQ */,
/* i n l s h */ HI(42) /* lha */,
/* i n l s i */ ARCH_DEPEND(HI(32) /* lwz */, HI(58) | ADDR_MODE2 | 0x2 /* lwa */),

// Write-back

/* i w s u w */ ARCH_DEPEND(HI(37) /* stwu */, HI(62) | ADDR_MODE2 | 0x1 /* stdu */),
/* i w s u b */ HI(39) /* stbu */,
/* i w s u h */ HI(45) /* sthu */,
/* i w s u i */ HI(37) /* stwu */,

/* i w s s w */ ARCH_DEPEND(HI(37) /* stwu */, HI(62) | ADDR_MODE2 | 0x1 /* stdu */),
/* i w s s b */ HI(39) /* stbu */,
/* i w s s h */ HI(45) /* sthu */,
/* i w s s i */ HI(37) /* stwu */,

/* i w l u w */ ARCH_DEPEND(HI(33) /* lwzu */, HI(58) | ADDR_MODE2 | 0x1 /* ldu */),
/* i w l u b */ HI(35) /* lbzu */,
/* i w l u h */ HI(41) /* lhzu */,
/* i w l u i */ HI(33) /* lwzu */,

/* i w l s w */ ARCH_DEPEND(HI(33) /* lwzu */, HI(58) | ADDR_MODE2 | 0x1 /* ldu */),
/* i w l s b */ HI(35) /* lbzu */ /* EXTS_REQ */,
/* i w l s h */ HI(43) /* lhau */,
/* i w l s i */ ARCH_DEPEND(HI(33) /* lwzu */, HI(58) | ADDR_MODE2 | UPDATE_REQ | 0x2 /* lwa */),

// ----------
//  Indexed
// ---------

// No write-back

/* x n s u w */ ARCH_DEPEND(HI(31) | LO(151) /* stwx */, HI(31) | LO(149) /* stdx */),
/* x n s u b */ HI(31) | LO(215) /* stbx */,
/* x n s u h */ HI(31) | LO(407) /* sthx */,
/* x n s u i */ HI(31) | LO(151) /* stwx */,

/* x n s s w */ ARCH_DEPEND(HI(31) | LO(151) /* stwx */, HI(31) | LO(149) /* stdx */),
/* x n s s b */ HI(31) | LO(215) /* stbx */,
/* x n s s h */ HI(31) | LO(407) /* sthx */,
/* x n s s i */ HI(31) | LO(151) /* stwx */,

/* x n l u w */ ARCH_DEPEND(HI(31) | LO(23) /* lwzx */, HI(31) | LO(21) /* ldx */),
/* x n l u b */ HI(31) | LO(87) /* lbzx */,
/* x n l u h */ HI(31) | LO(279) /* lhzx */,
/* x n l u i */ HI(31) | LO(23) /* lwzx */,

/* x n l s w */ ARCH_DEPEND(HI(31) | LO(23) /* lwzx */, HI(31) | LO(21) /* ldx */),
/* x n l s b */ HI(31) | LO(87) /* lbzx */ /* EXTS_REQ */,
/* x n l s h */ HI(31) | LO(343) /* lhax */,
/* x n l s i */ ARCH_DEPEND(HI(31) | LO(23) /* lwzx */, HI(31) | LO(341) /* lwax */),

// Write-back

/* x w s u w */ ARCH_DEPEND(HI(31) | LO(183) /* stwux */, HI(31) | LO(181) /* stdux */),
/* x w s u b */ HI(31) | LO(247) /* stbux */,
/* x w s u h */ HI(31) | LO(439) /* sthux */,
/* x w s u i */ HI(31) | LO(183) /* stwux */,

/* x w s s w */ ARCH_DEPEND(HI(31) | LO(183) /* stwux */, HI(31) | LO(181) /* stdux */),
/* x w s s b */ HI(31) | LO(247) /* stbux */,
/* x w s s h */ HI(31) | LO(439) /* sthux */,
/* x w s s i */ HI(31) | LO(183) /* stwux */,

/* x w l u w */ ARCH_DEPEND(HI(31) | LO(55) /* lwzux */, HI(31) | LO(53) /* ldux */),
/* x w l u b */ HI(31) | LO(119) /* lbzux */,
/* x w l u h */ HI(31) | LO(311) /* lhzux */,
/* x w l u i */ HI(31) | LO(55) /* lwzux */,

/* x w l s w */ ARCH_DEPEND(HI(31) | LO(55) /* lwzux */, HI(31) | LO(53) /* ldux */),
/* x w l s b */ HI(31) | LO(119) /* lbzux */ /* EXTS_REQ */,
/* x w l s h */ HI(31) | LO(375) /* lhaux */,
/* x w l s i */ ARCH_DEPEND(HI(31) | LO(55) /* lwzux */, HI(31) | LO(373) /* lwaux */)

};

#undef ARCH_DEPEND

  // Source and destination is register
#define REG_DEST	0x0001
#define REG1_SOURCE	0x0002
#define REG2_SOURCE	0x0004
  // getput_arg_fast returned true
#define FAST_DEST	0x0008
  // Multiple instructions are required
#define SLOW_DEST	0x0010
// ALT_FORM1		0x0200
// ALT_FORM2		0x0400
// ALT_FORM3		0x0800
// ALT_FORM4		0x1000
// ALT_SIGN_EXT		0x2000
// ALT_SET_FLAGS	0x4000

#ifdef SLJIT_CONFIG_PPC_32
#include "sljitNativePPC_32.c"
#else
#include "sljitNativePPC_64.c"
#endif

// Simple cases, (no caching is required)
static int getput_arg_fast(struct sljit_compiler *compiler, int inp_flags, int reg, int arg, sljit_w argw)
{
	sljit_i inst;
#ifdef SLJIT_CONFIG_PPC_64
	int tmp_reg;
#endif

	SLJIT_ASSERT(arg & SLJIT_MEM);
	if (!(arg & 0xf)) {
#ifdef SLJIT_CONFIG_PPC_32
		if (argw <= SIMM_MAX && argw >= SIMM_MIN) {
			if (inp_flags & ARG_TEST)
				return 1;

			inst = data_transfer_insts[(inp_flags & ~WRITE_BACK) & MEM_MASK];
			SLJIT_ASSERT(!(inst & (ADDR_MODE2 | UPDATE_REQ)));
			push_inst(compiler, GET_INST_CODE(inst) | D(reg) | IMM(argw));
			return -1;
		}
#else
		inst = data_transfer_insts[(inp_flags & ~WRITE_BACK) & MEM_MASK];
		if (argw <= SIMM_MAX && argw >= SIMM_MIN &&
				(!(inst & ADDR_MODE2) || (argw & 0x3) == 0)) {
			if (inp_flags & ARG_TEST)
				return 1;

			push_inst(compiler, GET_INST_CODE(inst) | D(reg) | IMM(argw));
			return -1;
		}
#endif
		return (inp_flags & ARG_TEST) ? SLJIT_SUCCESS : 0;
	}

	if (!(arg & 0xf0)) {
#ifdef SLJIT_CONFIG_PPC_32
		if (argw <= SIMM_MAX && argw >= SIMM_MIN) {
			if (inp_flags & ARG_TEST)
				return 1;

			inst = data_transfer_insts[inp_flags & MEM_MASK];
			SLJIT_ASSERT(!(inst & (ADDR_MODE2 | UPDATE_REQ)));
			push_inst(compiler, GET_INST_CODE(inst) | D(reg) | A(arg & 0xf) | IMM(argw));
			return -1;
		}
#else
		inst = data_transfer_insts[inp_flags & MEM_MASK];
		if (argw <= SIMM_MAX && argw >= SIMM_MIN && (!(inst & ADDR_MODE2) || (argw & 0x3) == 0)) {
			if (inp_flags & ARG_TEST)
				return 1;

			if ((inp_flags & WRITE_BACK) && (inst & UPDATE_REQ)) {
				tmp_reg = (inp_flags & LOAD_DATA) ? (arg & 0xf) : TMP_REG3;
				if (push_inst(compiler, ADDI | D(tmp_reg) | A(arg & 0xf) | IMM(argw)))
					return -1;
				arg = tmp_reg | SLJIT_MEM;
				argw = 0;
			}
			push_inst(compiler, GET_INST_CODE(inst) | D(reg) | A(arg & 0xf) | IMM(argw));
			return -1;
		}
#endif
	}
	else if (!(argw & 0x3)) {
		if (inp_flags & ARG_TEST)
			return 1;
		inst = data_transfer_insts[(inp_flags | INDEXED) & MEM_MASK];
		SLJIT_ASSERT(!(inst & (ADDR_MODE2 | UPDATE_REQ)));
		push_inst(compiler, GET_INST_CODE(inst) | D(reg) | A(arg & 0xf) | B((arg >> 4) & 0xf));
		return -1;
	}
	return (inp_flags & ARG_TEST) ? SLJIT_SUCCESS : 0;
}

// see getput_arg below
// Note: can_cache is called only for binary operators. Those operator always
// uses word arguments without write back
static int can_cache(int arg, sljit_w argw, int next_arg, sljit_w next_argw)
{
	SLJIT_ASSERT(arg & SLJIT_MEM);
	SLJIT_ASSERT(next_arg & SLJIT_MEM);

	if (!(arg & 0xf)) {
		if ((next_arg & SLJIT_MEM) && ((sljit_uw)argw - (sljit_uw)next_argw <= SIMM_MAX || (sljit_uw)next_argw - (sljit_uw)argw <= SIMM_MAX))
			return 1;
		return 0;
	}

	if (arg & 0xf0)
		return 0;

	if (argw <= SIMM_MAX && argw >= SIMM_MIN) {
		if (arg == next_arg && (next_argw >= SIMM_MAX && next_argw <= SIMM_MIN))
			return 1;
	}

	if (arg == next_arg && ((sljit_uw)argw - (sljit_uw)next_argw <= SIMM_MAX || (sljit_uw)next_argw - (sljit_uw)argw <= SIMM_MAX))
		return 1;

	return 0;
}

#ifdef SLJIT_CONFIG_PPC_64
#define ADJUST_CACHED_IMM(imm) \
	if ((inst & ADDR_MODE2) && (imm & 0x3)) { \
		/* Adjust cached value. Fortunately this is really a rare case */ \
		compiler->cache_argw += imm & 0x3; \
		FAIL_IF(push_inst(compiler, ADDI | D(TMP_REG3) | A(TMP_REG3) | (imm & 0x3))); \
		imm &= ~0x3; \
	}
#else
#define ADJUST_CACHED_IMM(imm)
#endif

// emit the necessary instructions
// see can_cache above
static int getput_arg(struct sljit_compiler *compiler, int inp_flags, int reg, int arg, sljit_w argw, int next_arg, sljit_w next_argw)
{
	int tmp_reg;
	sljit_i inst;

	SLJIT_ASSERT(arg & SLJIT_MEM);

	tmp_reg = (inp_flags & LOAD_DATA) ? reg : TMP_REG3;

	if (!(arg & 0xf)) {
		inst = data_transfer_insts[(inp_flags & ~WRITE_BACK) & MEM_MASK];
		if ((compiler->cache_arg & SLJIT_IMM) && (((sljit_uw)argw - (sljit_uw)compiler->cache_argw) <= SIMM_MAX || ((sljit_uw)compiler->cache_argw - (sljit_uw)argw) <= SIMM_MAX)) {
			argw = argw - compiler->cache_argw;
			ADJUST_CACHED_IMM(argw);
			SLJIT_ASSERT(!(inst & UPDATE_REQ));
			return push_inst(compiler, GET_INST_CODE(inst) | D(reg) | A(TMP_REG3) | IMM(argw));
		}

		if ((next_arg & SLJIT_MEM) && (argw - next_argw <= SIMM_MAX || next_argw - argw <= SIMM_MAX)) {
			SLJIT_ASSERT(inp_flags & LOAD_DATA);

			compiler->cache_arg = SLJIT_IMM;
			compiler->cache_argw = argw;
			tmp_reg = TMP_REG3;
		}

		FAIL_IF(load_immediate(compiler, tmp_reg, argw));
		return push_inst(compiler, GET_INST_CODE(inst) | D(reg) | A(tmp_reg));
	}

	if (arg & 0xf0) {
		argw &= 0x3;
		// Otherwise getput_arg_fast would capture it
		SLJIT_ASSERT(argw);
#ifdef SLJIT_CONFIG_PPC_32
		FAIL_IF(push_inst(compiler, RLWINM | S((arg >> 4) & 0xf) | A(tmp_reg) | (argw << 11) | ((31 - argw) << 1)));
#else
		FAIL_IF(push_inst(compiler, RLDI(tmp_reg, (arg >> 4) & 0xf, argw, 63 - argw, 1)));
#endif
		inst = data_transfer_insts[(inp_flags | INDEXED) & MEM_MASK];
		SLJIT_ASSERT(!(inst & (ADDR_MODE2 | UPDATE_REQ)));
		return push_inst(compiler, GET_INST_CODE(inst) | D(reg) | A(arg & 0xf) | B(tmp_reg));
	}

	inst = data_transfer_insts[inp_flags & MEM_MASK];

	if (compiler->cache_arg == arg && ((sljit_uw)argw - (sljit_uw)compiler->cache_argw <= SIMM_MAX || (sljit_uw)compiler->cache_argw - (sljit_uw)argw <= SIMM_MAX)) {
		SLJIT_ASSERT(!(inp_flags & WRITE_BACK));
		argw = argw - compiler->cache_argw;
		ADJUST_CACHED_IMM(argw);
		return push_inst(compiler, GET_INST_CODE(inst) | D(reg) | A(TMP_REG3) | IMM(argw));
	}

	if ((compiler->cache_arg & SLJIT_IMM) && compiler->cache_argw == argw) {
		inst = data_transfer_insts[(inp_flags | INDEXED) & MEM_MASK];
		SLJIT_ASSERT(!(inst & (ADDR_MODE2 | UPDATE_REQ)));
		return push_inst(compiler, GET_INST_CODE(inst) | D(reg) | A(arg & 0xf) | B(TMP_REG3));
	}

	if (argw == next_argw && (next_arg & SLJIT_MEM)) {
		SLJIT_ASSERT(inp_flags & LOAD_DATA);
		FAIL_IF(load_immediate(compiler, TMP_REG3, argw));

		compiler->cache_arg = SLJIT_IMM;
		compiler->cache_argw = argw;

		inst = data_transfer_insts[(inp_flags | INDEXED) & MEM_MASK];
		SLJIT_ASSERT(!(inst & (ADDR_MODE2 | UPDATE_REQ)));
		return push_inst(compiler, GET_INST_CODE(inst) | D(reg) | A(arg & 0xf) | B(TMP_REG3));
	}

	if (arg == next_arg && !(inp_flags & WRITE_BACK) && ((sljit_uw)argw - (sljit_uw)next_argw <= SIMM_MAX || (sljit_uw)next_argw - (sljit_uw)argw <= SIMM_MAX)) {
		SLJIT_ASSERT(inp_flags & LOAD_DATA);
		FAIL_IF(load_immediate(compiler, TMP_REG3, argw));
		FAIL_IF(push_inst(compiler, ADD | D(TMP_REG3) | A(TMP_REG3) | B(arg & 0xf)));

		compiler->cache_arg = arg;
		compiler->cache_argw = argw;

		return push_inst(compiler, GET_INST_CODE(inst) | D(reg) | A(TMP_REG3));
	}

	// Get the indexed version instead of the normal one
	inst = data_transfer_insts[(inp_flags | INDEXED) & MEM_MASK];
	SLJIT_ASSERT(!(inst & (ADDR_MODE2 | UPDATE_REQ)));
	FAIL_IF(load_immediate(compiler, tmp_reg, argw));
	return push_inst(compiler, GET_INST_CODE(inst) | D(reg) | A(arg & 0xf) | B(tmp_reg));
}

static int emit_op(struct sljit_compiler *compiler, int op, int inp_flags,
	int dst, sljit_w dstw,
	int src1, sljit_w src1w,
	int src2, sljit_w src2w)
{
	// arg1 goes to TMP_REG1 or src reg
	// arg2 goes to TMP_REG2, imm or src reg
	// TMP_REG3 can be used for caching
	// result goes to TMP_REG2, so put result can use TMP_REG1 and TMP_REG3
	int dst_r;
	int src1_r;
	int src2_r;
	int sugg_src2_r = TMP_REG2;
	int flags = inp_flags & (ALT_FORM1 | ALT_FORM2 | ALT_FORM3 | ALT_FORM4 | ALT_SIGN_EXT | ALT_SET_FLAGS);

	compiler->cache_arg = 0;
	compiler->cache_argw = 0;

	// Destination check
	if (dst >= SLJIT_TEMPORARY_REG1 && dst <= TMP_REG3) {
		dst_r = dst;
		flags |= REG_DEST;
		if (op >= SLJIT_MOV && op <= SLJIT_MOVU_SI)
			sugg_src2_r = dst_r;
	}
	else if (dst == SLJIT_UNUSED) {
		if (op >= SLJIT_MOV && op <= SLJIT_MOVU_SI && !(src2 & SLJIT_MEM))
			return SLJIT_SUCCESS;
		dst_r = TMP_REG2;
	}
	else {
		SLJIT_ASSERT(dst & SLJIT_MEM);
		if (getput_arg_fast(compiler, inp_flags | ARG_TEST, TMP_REG2, dst, dstw)) {
			flags |= FAST_DEST;
			dst_r = TMP_REG2;
		}
		else {
			flags |= SLOW_DEST;
			dst_r = 0;
		}
	}

	// Source 1
	if (src1 >= SLJIT_TEMPORARY_REG1 && src1 <= TMP_REG3) {
		src1_r = src1;
		flags |= REG1_SOURCE;
	}
	else if (src1 & SLJIT_IMM) {
#ifdef SLJIT_CONFIG_PPC_64
		if ((inp_flags & 0x3) == INT_DATA) {
			if (inp_flags & SIGNED_DATA)
				src1w = (signed int)src1w;
			else
				src1w = (unsigned int)src1w;
		}
#endif
		FAIL_IF(load_immediate(compiler, TMP_REG1, src1w));
		src1_r = TMP_REG1;
	}
	else if (getput_arg_fast(compiler, inp_flags | LOAD_DATA, TMP_REG1, src1, src1w)) {
		FAIL_IF(compiler->error);
		src1_r = TMP_REG1;
	}
	else
		src1_r = 0;

	if (src2 >= SLJIT_TEMPORARY_REG1 && src2 <= TMP_REG3) {
		src2_r = src2;
		flags |= REG2_SOURCE;
		if (!(flags & REG_DEST) && op >= SLJIT_MOV && op <= SLJIT_MOVU_SI)
			dst_r = src2_r;
	}
	else if (src2 & SLJIT_IMM) {
#ifdef SLJIT_CONFIG_PPC_64
		if ((inp_flags & 0x3) == INT_DATA) {
			if (inp_flags & SIGNED_DATA)
				src2w = (signed int)src2w;
			else
				src2w = (unsigned int)src2w;
		}
#endif
		FAIL_IF(load_immediate(compiler, sugg_src2_r, src2w));
		src2_r = sugg_src2_r;
	}
	else if (getput_arg_fast(compiler, inp_flags | LOAD_DATA, sugg_src2_r, src2, src2w)) {
		FAIL_IF(compiler->error);
		src2_r = sugg_src2_r;
	}
	else
		src2_r = 0;

	// src1_r, src2_r and dst_r can be zero (=unprocessed)
	// All arguments are complex addressing modes, and it is a binary operator
	if (src1_r == 0 && src2_r == 0 && dst_r == 0) {
		if (!can_cache(src1, src1w, src2, src2w) && can_cache(src1, src1w, dst, dstw)) {
			FAIL_IF(getput_arg(compiler, inp_flags | LOAD_DATA, TMP_REG2, src2, src2w, src1, src1w));
			FAIL_IF(getput_arg(compiler, inp_flags | LOAD_DATA, TMP_REG1, src1, src1w, dst, dstw));
		}
		else {
			FAIL_IF(getput_arg(compiler, inp_flags | LOAD_DATA, TMP_REG1, src1, src1w, src2, src2w));
			FAIL_IF(getput_arg(compiler, inp_flags | LOAD_DATA, TMP_REG2, src2, src2w, dst, dstw));
		}
		src1_r = TMP_REG1;
		src2_r = TMP_REG2;
	}
	else if (src1_r == 0 && src2_r == 0) {
		FAIL_IF(getput_arg(compiler, inp_flags | LOAD_DATA, TMP_REG1, src1, src1w, src2, src2w));
		src1_r = TMP_REG1;
	}
	else if (src1_r == 0 && dst_r == 0) {
		FAIL_IF(getput_arg(compiler, inp_flags | LOAD_DATA, TMP_REG1, src1, src1w, dst, dstw));
		src1_r = TMP_REG1;
	}
	else if (src2_r == 0 && dst_r == 0) {
		FAIL_IF(getput_arg(compiler, inp_flags | LOAD_DATA, sugg_src2_r, src2, src2w, dst, dstw));
		src2_r = sugg_src2_r;
	}

	if (dst_r == 0)
		dst_r = TMP_REG2;

	if (src1_r == 0) {
		FAIL_IF(getput_arg(compiler, inp_flags | LOAD_DATA, TMP_REG1, src1, src1w, 0, 0));
		src1_r = TMP_REG1;
	}

	if (src2_r == 0) {
		FAIL_IF(getput_arg(compiler, inp_flags | LOAD_DATA, sugg_src2_r, src2, src2w, 0, 0));
		src2_r = sugg_src2_r;
	}

	FAIL_IF(emit_single_op(compiler, op, flags, dst_r, src1_r, src2_r));

	if (flags & (FAST_DEST | SLOW_DEST)) {
		if (flags & FAST_DEST)
			FAIL_IF(getput_arg_fast(compiler, inp_flags, dst_r, dst, dstw));
		else
			FAIL_IF(getput_arg(compiler, inp_flags, dst_r, dst, dstw, 0, 0));
	}
	return SLJIT_SUCCESS;
}

int sljit_emit_op0(struct sljit_compiler *compiler, int op)
{
	FUNCTION_ENTRY();

	SLJIT_ASSERT(GET_OPCODE(op) >= SLJIT_DEBUGGER && GET_OPCODE(op) <= SLJIT_DEBUGGER);
	sljit_emit_op0_verbose();

	op = GET_OPCODE(op);
	switch (op) {
	case SLJIT_DEBUGGER:
		break;
	}

	return SLJIT_SUCCESS;
}

int sljit_emit_op1(struct sljit_compiler *compiler, int op,
	int dst, sljit_w dstw,
	int src, sljit_w srcw)
{
	int inp_flags = GET_FLAGS(op) ? ALT_SET_FLAGS : 0;

	FUNCTION_ENTRY();

	SLJIT_ASSERT(GET_OPCODE(op) >= SLJIT_MOV && GET_OPCODE(op) <= SLJIT_NEG);
#ifdef SLJIT_DEBUG
	FUNCTION_CHECK_OP();
	FUNCTION_CHECK_SRC(src, srcw);
	FUNCTION_CHECK_DST(dst, dstw);
	FUNCTION_CHECK_OP1();
#endif
	sljit_emit_op1_verbose();

#ifdef SLJIT_CONFIG_PPC_64
	if (op & SLJIT_INT_OP) {
		inp_flags |= INT_DATA | SIGNED_DATA;
		if (src & SLJIT_IMM)
			srcw = (int)srcw;
	}
#endif
	if (op & SLJIT_SET_O)
		FAIL_IF(push_inst(compiler, MTXER | S(ZERO_REG)));

	switch (GET_OPCODE(op)) {
	case SLJIT_MOV:
		return emit_op(compiler, SLJIT_MOV, inp_flags | WORD_DATA, dst, dstw, TMP_REG1, 0, src, srcw);

	case SLJIT_MOV_UI:
		return emit_op(compiler, SLJIT_MOV_UI, inp_flags | INT_DATA, dst, dstw, TMP_REG1, 0, src, srcw);

	case SLJIT_MOV_SI:
		return emit_op(compiler, SLJIT_MOV_SI, inp_flags | INT_DATA | SIGNED_DATA, dst, dstw, TMP_REG1, 0, src, srcw);

	case SLJIT_MOV_UB:
		return emit_op(compiler, SLJIT_MOV_UB, inp_flags | BYTE_DATA, dst, dstw, TMP_REG1, 0, src, (src & SLJIT_IMM) ? (unsigned char)srcw : srcw);

	case SLJIT_MOV_SB:
		return emit_op(compiler, SLJIT_MOV_SB, inp_flags | BYTE_DATA | SIGNED_DATA, dst, dstw, TMP_REG1, 0, src, (src & SLJIT_IMM) ? (signed char)srcw : srcw);

	case SLJIT_MOV_UH:
		return emit_op(compiler, SLJIT_MOV_UH, inp_flags | HALF_DATA, dst, dstw, TMP_REG1, 0, src, (src & SLJIT_IMM) ? (unsigned short)srcw : srcw);

	case SLJIT_MOV_SH:
		return emit_op(compiler, SLJIT_MOV_SH, inp_flags | HALF_DATA | SIGNED_DATA, dst, dstw, TMP_REG1, 0, src, (src & SLJIT_IMM) ? (signed short)srcw : srcw);

	case SLJIT_MOVU:
		return emit_op(compiler, SLJIT_MOV, inp_flags | WORD_DATA | WRITE_BACK, dst, dstw, TMP_REG1, 0, src, srcw);

	case SLJIT_MOVU_UI:
		return emit_op(compiler, SLJIT_MOV_UI, inp_flags | INT_DATA | WRITE_BACK, dst, dstw, TMP_REG1, 0, src, srcw);

	case SLJIT_MOVU_SI:
		return emit_op(compiler, SLJIT_MOV_SI, inp_flags | INT_DATA | SIGNED_DATA | WRITE_BACK, dst, dstw, TMP_REG1, 0, src, srcw);

	case SLJIT_MOVU_UB:
		return emit_op(compiler, SLJIT_MOV_UB, inp_flags | BYTE_DATA | WRITE_BACK, dst, dstw, TMP_REG1, 0, src, (src & SLJIT_IMM) ? (unsigned char)srcw : srcw);

	case SLJIT_MOVU_SB:
		return emit_op(compiler, SLJIT_MOV_SB, inp_flags | BYTE_DATA | SIGNED_DATA | WRITE_BACK, dst, dstw, TMP_REG1, 0, src, (src & SLJIT_IMM) ? (signed char)srcw : srcw);

	case SLJIT_MOVU_UH:
		return emit_op(compiler, SLJIT_MOV_UH, inp_flags | HALF_DATA | WRITE_BACK, dst, dstw, TMP_REG1, 0, src, (src & SLJIT_IMM) ? (unsigned short)srcw : srcw);

	case SLJIT_MOVU_SH:
		return emit_op(compiler, SLJIT_MOV_SH, inp_flags | HALF_DATA | SIGNED_DATA | WRITE_BACK, dst, dstw, TMP_REG1, 0, src, (src & SLJIT_IMM) ? (signed short)srcw : srcw);

	case SLJIT_NOT:
		return emit_op(compiler, SLJIT_NOT, inp_flags, dst, dstw, TMP_REG1, 0, src, srcw);

	case SLJIT_NEG:
		return emit_op(compiler, SLJIT_NEG, inp_flags, dst, dstw, TMP_REG1, 0, src, srcw);
	}

	return SLJIT_SUCCESS;
}

#define TEST_SL_IMM(src, srcw) \
	(((src) & SLJIT_IMM) && (srcw) <= SIMM_MAX && (srcw) >= SIMM_MIN)

#define TEST_UL_IMM(src, srcw) \
	(((src) & SLJIT_IMM) && !((srcw) & ~0xffff))

#ifdef SLJIT_CONFIG_PPC_64
#define TEST_SH_IMM(src, srcw) \
	(((src) & SLJIT_IMM) && !((srcw) & 0xffff) && (srcw) <= 0x7fffffff && (srcw) >= -0x80000000l)
#else
#define TEST_SH_IMM(src, srcw) \
	(((src) & SLJIT_IMM) && !((srcw) & 0xffff))
#endif

#define TEST_UH_IMM(src, srcw) \
	(((src) & SLJIT_IMM) && !((srcw) & ~0xffff0000))

int sljit_emit_op2(struct sljit_compiler *compiler, int op,
	int dst, sljit_w dstw,
	int src1, sljit_w src1w,
	int src2, sljit_w src2w)
{
	int inp_flags = GET_FLAGS(op) ? ALT_SET_FLAGS : 0;

	FUNCTION_ENTRY();

	SLJIT_ASSERT(GET_OPCODE(op) >= SLJIT_ADD && GET_OPCODE(op) <= SLJIT_ASHR);
#ifdef SLJIT_DEBUG
	FUNCTION_CHECK_OP();
	FUNCTION_CHECK_SRC(src1, src1w);
	FUNCTION_CHECK_SRC(src2, src2w);
	FUNCTION_CHECK_DST(dst, dstw);
#endif
	sljit_emit_op2_verbose();

#ifdef SLJIT_CONFIG_PPC_64
	if (op & SLJIT_INT_OP) {
		inp_flags |= INT_DATA | SIGNED_DATA;
		if (src1 & SLJIT_IMM)
			src1w = (src1w << 32) >> 32;
		if (src2 & SLJIT_IMM)
			src2w = (src2w << 32) >> 32;
		if (GET_FLAGS(op))
			inp_flags |= ALT_SIGN_EXT;
	}
#endif
	if (op & SLJIT_SET_O)
		FAIL_IF(push_inst(compiler, MTXER | S(ZERO_REG)));

	switch (GET_OPCODE(op)) {
	case SLJIT_ADD:
		if (!GET_FLAGS(op)) {
			if (TEST_SL_IMM(src2, src2w)) {
				compiler->imm = src2w & 0xffff;
				return emit_op(compiler, SLJIT_ADD, inp_flags | ALT_FORM1, dst, dstw, src1, src1w, TMP_REG2, 0);
			}
			if (TEST_SL_IMM(src1, src1w)) {
				compiler->imm = src1w & 0xffff;
				return emit_op(compiler, SLJIT_ADD, inp_flags | ALT_FORM1, dst, dstw, src2, src2w, TMP_REG2, 0);
			}
			if (TEST_SH_IMM(src2, src2w)) {
				compiler->imm = (src2w >> 16) & 0xffff;
				return emit_op(compiler, SLJIT_ADD, inp_flags | ALT_FORM2, dst, dstw, src1, src1w, TMP_REG2, 0);
			}
			if (TEST_SH_IMM(src1, src1w)) {
				compiler->imm = (src1w >> 16) & 0xffff;
				return emit_op(compiler, SLJIT_ADD, inp_flags | ALT_FORM2, dst, dstw, src2, src2w, TMP_REG2, 0);
			}
		}
		if (!(GET_FLAGS(op) & (SLJIT_SET_E | SLJIT_SET_O))) {
			if (TEST_SL_IMM(src2, src2w)) {
				compiler->imm = src2w & 0xffff;
				return emit_op(compiler, SLJIT_ADD, inp_flags | ALT_FORM3, dst, dstw, src1, src1w, TMP_REG2, 0);
			}
			if (TEST_SL_IMM(src1, src1w)) {
				compiler->imm = src1w & 0xffff;
				return emit_op(compiler, SLJIT_ADD, inp_flags | ALT_FORM3, dst, dstw, src2, src2w, TMP_REG2, 0);
			}
		}
		return emit_op(compiler, SLJIT_ADD, inp_flags, dst, dstw, src1, src1w, src2, src2w);

	case SLJIT_ADDC:
		return emit_op(compiler, SLJIT_ADDC, inp_flags | (!(op & SLJIT_KEEP_FLAGS) ? 0 : ALT_FORM1), dst, dstw, src1, src1w, src2, src2w);

	case SLJIT_SUB:
		if (!GET_FLAGS(op)) {
			if (TEST_SL_IMM(src2, -src2w)) {
				compiler->imm = (-src2w) & 0xffff;
				return emit_op(compiler, SLJIT_ADD, inp_flags | ALT_FORM1, dst, dstw, src1, src1w, TMP_REG2, 0);
			}
			if (TEST_SL_IMM(src1, src1w)) {
				compiler->imm = src1w & 0xffff;
				return emit_op(compiler, SLJIT_SUB, inp_flags | ALT_FORM1, dst, dstw, src2, src2w, TMP_REG2, 0);
			}
			if (TEST_SH_IMM(src2, -src2w)) {
				compiler->imm = ((-src2w) >> 16) & 0xffff;
				return emit_op(compiler, SLJIT_ADD, inp_flags | ALT_FORM2, dst, dstw, src1, src1w, TMP_REG2, 0);
			}
		}
		if (dst == SLJIT_UNUSED && GET_FLAGS(op) == SLJIT_SET_U) {
			// We know ALT_SIGN_EXT is set if it is an SLJIT_INT_OP on 64 bit systems
			if (TEST_UL_IMM(src2, src2w)) {
				compiler->imm = src2w & 0xffff;
				return emit_op(compiler, SLJIT_SUB, inp_flags | ALT_FORM2, dst, dstw, src1, src1w, TMP_REG2, 0);
			}
			return emit_op(compiler, SLJIT_SUB, inp_flags | ALT_FORM3, dst, dstw, src1, src1w, src2, src2w);
		}
		if (!(op & (SLJIT_SET_E | SLJIT_SET_S | SLJIT_SET_U | SLJIT_SET_O))) {
			if (TEST_SL_IMM(src2, -src2w)) {
				compiler->imm = (-src2w) & 0xffff;
				return emit_op(compiler, SLJIT_ADD, inp_flags | ALT_FORM3, dst, dstw, src1, src1w, TMP_REG2, 0);
			}
		}
		// We know ALT_SIGN_EXT is set if it is an SLJIT_INT_OP on 64 bit systems
		return emit_op(compiler, SLJIT_SUB, inp_flags | (!(op & SLJIT_SET_U) ? 0 : ALT_FORM4), dst, dstw, src1, src1w, src2, src2w);

	case SLJIT_SUBC:
		return emit_op(compiler, SLJIT_SUBC, inp_flags | (!(op & SLJIT_SET_U) ? 0 : ALT_FORM4) | (!(op & SLJIT_KEEP_FLAGS) ? 0 : ALT_FORM1), dst, dstw, src1, src1w, src2, src2w);

	case SLJIT_MUL:
#ifdef SLJIT_CONFIG_PPC_64
		if (op & SLJIT_INT_OP)
			inp_flags |= ALT_FORM2;
#endif
		if (!GET_FLAGS(op)) {
			if (TEST_SL_IMM(src2, src2w)) {
				compiler->imm = src2w & 0xffff;
				return emit_op(compiler, SLJIT_MUL, inp_flags | ALT_FORM1, dst, dstw, src1, src1w, TMP_REG2, 0);
			}
			if (TEST_SL_IMM(src1, src1w)) {
				compiler->imm = src1w & 0xffff;
				return emit_op(compiler, SLJIT_MUL, inp_flags | ALT_FORM1, dst, dstw, src2, src2w, TMP_REG2, 0);
			}
		}
		return emit_op(compiler, SLJIT_MUL, inp_flags, dst, dstw, src1, src1w, src2, src2w);

	case SLJIT_AND:
	case SLJIT_OR:
	case SLJIT_XOR:
		// Commutative unsigned operations
		if (!GET_FLAGS(op) || GET_OPCODE(op) == SLJIT_AND) {
			if (TEST_UL_IMM(src2, src2w)) {
				compiler->imm = src2w & 0xffff;
				return emit_op(compiler, GET_OPCODE(op), inp_flags | ALT_FORM1, dst, dstw, src1, src1w, TMP_REG2, 0);
			}
			if (TEST_UL_IMM(src1, src1w)) {
				compiler->imm = src1w & 0xffff;
				return emit_op(compiler, GET_OPCODE(op), inp_flags | ALT_FORM1, dst, dstw, src2, src2w, TMP_REG2, 0);
			}
			if (TEST_UH_IMM(src2, src2w)) {
				compiler->imm = (src2w >> 16) & 0xffff;
				return emit_op(compiler, GET_OPCODE(op), inp_flags | ALT_FORM2, dst, dstw, src1, src1w, TMP_REG2, 0);
			}
			if (TEST_UH_IMM(src1, src1w)) {
				compiler->imm = (src1w >> 16) & 0xffff;
				return emit_op(compiler, GET_OPCODE(op), inp_flags | ALT_FORM2, dst, dstw, src2, src2w, TMP_REG2, 0);
			}
		}
		return emit_op(compiler, GET_OPCODE(op), inp_flags, dst, dstw, src1, src1w, src2, src2w);

	case SLJIT_SHL:
	case SLJIT_LSHR:
	case SLJIT_ASHR:
#ifdef SLJIT_CONFIG_PPC_64
		if (op & SLJIT_INT_OP)
			inp_flags |= ALT_FORM2;
#endif
		if (src2 & SLJIT_IMM) {
			compiler->imm = src2w;
			return emit_op(compiler, GET_OPCODE(op), inp_flags | ALT_FORM1, dst, dstw, src1, src1w, TMP_REG2, 0);
		}
		return emit_op(compiler, GET_OPCODE(op), inp_flags, dst, dstw, src1, src1w, src2, src2w);
	}

	return SLJIT_SUCCESS;
}

// ---------------------------------------------------------------------
//  Floating point operators
// ---------------------------------------------------------------------

int sljit_is_fpu_available(void)
{
	// Always available
	return 1;
}

static int emit_fpu_data_transfer(struct sljit_compiler *compiler, int fpu_reg, int load, int arg, sljit_w argw)
{
	SLJIT_ASSERT(arg & SLJIT_MEM);

	// Fast loads and stores
	if (!(arg & 0xf0)) {
		// Both for (arg & 0xf) == SLJIT_UNUSED and (arg & 0xf) != SLJIT_UNUSED
		if (argw <= SIMM_MAX && argw >= SIMM_MIN)
			return push_inst(compiler, (load ? LFD : STFD) | FD(fpu_reg) | A(arg & 0xf) | IMM(argw));
	}

	if (arg & 0xf0) {
		argw &= 0x3;
		if (argw) {
#ifdef SLJIT_CONFIG_PPC_32
			FAIL_IF(push_inst(compiler, RLWINM | S((arg >> 4) & 0xf) | A(TMP_REG2) | (argw << 11) | ((31 - argw) << 1)));
#else
			FAIL_IF(push_inst(compiler, RLDI(TMP_REG2, (arg >> 4) & 0xf, argw, 63 - argw, 1)));
#endif
			return push_inst(compiler, (load ? LFDX : STFDX) | FD(fpu_reg) | A(arg & 0xf) | B(TMP_REG2));
		}
		return push_inst(compiler, (load ? LFDX : STFDX) | FD(fpu_reg) | A(arg & 0xf) | B((arg >> 4) & 0xf));
	}

	// Use cache
	if (compiler->cache_arg == arg && argw - compiler->cache_argw <= SIMM_MAX && argw - compiler->cache_argw >= SIMM_MIN)
		return push_inst(compiler, (load ? LFD : STFD) | FD(fpu_reg) | A(TMP_REG3) | IMM(argw - compiler->cache_argw));

	if (compiler->cache_argw == argw) {
		if (!(compiler->cache_arg & 0xf))
			return push_inst(compiler, (load ? LFDX : STFDX) | FD(fpu_reg) | A(arg & 0xf) | B(TMP_REG3));
	}

	// Put value to cache
	compiler->cache_arg = arg;
	compiler->cache_argw = argw;

	FAIL_IF(load_immediate(compiler, TMP_REG3, argw));
	if (!(arg & 0xf))
		return push_inst(compiler, (load ? LFDX : STFDX) | FD(fpu_reg) | A(0) | B(TMP_REG3));
	return push_inst(compiler, (load ? LFDUX : STFDUX) | FD(fpu_reg) | A(TMP_REG3) | B(arg & 0xf));
}

int sljit_emit_fop1(struct sljit_compiler *compiler, int op,
	int dst, sljit_w dstw,
	int src, sljit_w srcw)
{
	int dst_freg;

	FUNCTION_ENTRY();

	SLJIT_ASSERT(sljit_is_fpu_available());
	SLJIT_ASSERT(GET_OPCODE(op) >= SLJIT_FCMP && GET_OPCODE(op) <= SLJIT_FABS);
#ifdef SLJIT_DEBUG
	FUNCTION_CHECK_OP();
	FUNCTION_FCHECK(src, srcw);
	FUNCTION_FCHECK(dst, dstw);
#endif
	sljit_emit_fop1_verbose();

	compiler->cache_arg = 0;
	compiler->cache_argw = 0;

	if (GET_OPCODE(op) == SLJIT_FCMP) {
		if (dst > SLJIT_FLOAT_REG4) {
			FAIL_IF(emit_fpu_data_transfer(compiler, TMP_FREG1, 1, dst, dstw));
			dst = TMP_FREG1;
		}
		if (src > SLJIT_FLOAT_REG4) {
			FAIL_IF(emit_fpu_data_transfer(compiler, TMP_FREG2, 1, src, srcw));
			src = TMP_FREG2;
		}
		return push_inst(compiler, FCMPU | CRD(4) | FA(dst) | FB(src));
	}

	dst_freg = (dst > SLJIT_FLOAT_REG4) ? TMP_FREG1 : dst;

	if (src > SLJIT_FLOAT_REG4) {
		FAIL_IF(emit_fpu_data_transfer(compiler, dst_freg, 1, src, srcw));
		src = dst_freg;
	}

	switch (op) {
		case SLJIT_FMOV:
			if (src != dst_freg && dst_freg != TMP_FREG1)
				FAIL_IF(push_inst(compiler, FMR | FD(dst_freg) | FB(src)));
			break;
		case SLJIT_FNEG:
			FAIL_IF(push_inst(compiler, FNEG | FD(dst_freg) | FB(src)));
			break;
		case SLJIT_FABS:
			FAIL_IF(push_inst(compiler, FABS | FD(dst_freg) | FB(src)));
			break;
	}

	if (dst_freg == TMP_FREG1)
		FAIL_IF(emit_fpu_data_transfer(compiler, src, 0, dst, dstw));

	return SLJIT_SUCCESS;
}

int sljit_emit_fop2(struct sljit_compiler *compiler, int op,
	int dst, sljit_w dstw,
	int src1, sljit_w src1w,
	int src2, sljit_w src2w)
{
	int dst_freg;

	FUNCTION_ENTRY();

	SLJIT_ASSERT(sljit_is_fpu_available());
	SLJIT_ASSERT(GET_OPCODE(op) >= SLJIT_FADD && GET_OPCODE(op) <= SLJIT_FDIV);
#ifdef SLJIT_DEBUG
	FUNCTION_CHECK_OP();
	FUNCTION_FCHECK(src1, src1w);
	FUNCTION_FCHECK(src2, src2w);
	FUNCTION_FCHECK(dst, dstw);
#endif
	sljit_emit_fop2_verbose();

	compiler->cache_arg = 0;
	compiler->cache_argw = 0;

	dst_freg = (dst > SLJIT_FLOAT_REG4) ? TMP_FREG1 : dst;

	if (src2 > SLJIT_FLOAT_REG4) {
		FAIL_IF(emit_fpu_data_transfer(compiler, TMP_FREG2, 1, src2, src2w));
		src2 = TMP_FREG2;
	}

	if (src1 > SLJIT_FLOAT_REG4) {
		FAIL_IF(emit_fpu_data_transfer(compiler, TMP_FREG1, 1, src1, src1w));
		src1 = TMP_FREG1;
	}

	switch (op) {
	case SLJIT_FADD:
		FAIL_IF(push_inst(compiler, FADD | FD(dst_freg) | FA(src1) | FB(src2)));
		break;

	case SLJIT_FSUB:
		FAIL_IF(push_inst(compiler, FSUB | FD(dst_freg) | FA(src1) | FB(src2)));
		break;

	case SLJIT_FMUL:
		FAIL_IF(push_inst(compiler, FMUL | FD(dst_freg) | FA(src1) | FC(src2) /* FMUL use FC as src2 */));
		break;

	case SLJIT_FDIV:
		FAIL_IF(push_inst(compiler, FDIV | FD(dst_freg) | FA(src1) | FB(src2)));
		break;
	}

	if (dst_freg == TMP_FREG1)
		FAIL_IF(emit_fpu_data_transfer(compiler, TMP_FREG1, 0, dst, dstw));

	return SLJIT_SUCCESS;
}

// ---------------------------------------------------------------------
//  Conditional instructions
// ---------------------------------------------------------------------

struct sljit_label* sljit_emit_label(struct sljit_compiler *compiler)
{
	struct sljit_label *label;

	FUNCTION_ENTRY();

	sljit_emit_label_verbose();

	if (compiler->last_label && compiler->last_label->size == compiler->size)
		return compiler->last_label;

	label = (struct sljit_label*)ensure_abuf(compiler, sizeof(struct sljit_label));
	PTR_FAIL_IF(!label);

	label->next = NULL;
	label->size = compiler->size;
	if (compiler->last_label)
		compiler->last_label->next = label;
	else
		compiler->labels = label;
	compiler->last_label = label;
	return label;
}

static sljit_i get_bo_bi_flags(struct sljit_compiler *compiler, int type)
{
	switch (type) {
	case SLJIT_C_EQUAL:
		return (12 << 21) | (2 << 16);

	case SLJIT_C_NOT_EQUAL:
		return (4 << 21) | (2 << 16);

	case SLJIT_C_LESS:
	case SLJIT_C_FLOAT_LESS:
		return (12 << 21) | ((4 + 0) << 16);

	case SLJIT_C_NOT_LESS:
	case SLJIT_C_FLOAT_NOT_LESS:
		return (4 << 21) | ((4 + 0) << 16);

	case SLJIT_C_GREATER:
	case SLJIT_C_FLOAT_GREATER:
		return (12 << 21) | ((4 + 1) << 16);

	case SLJIT_C_NOT_GREATER:
	case SLJIT_C_FLOAT_NOT_GREATER:
		return (4 << 21) | ((4 + 1) << 16);

	case SLJIT_C_SIG_LESS:
		return (12 << 21) | (0 << 16);

	case SLJIT_C_SIG_NOT_LESS:
		return (4 << 21) | (0 << 16);

	case SLJIT_C_SIG_GREATER:
		return (12 << 21) | (1 << 16);

	case SLJIT_C_SIG_NOT_GREATER:
		return (4 << 21) | (1 << 16);

	case SLJIT_C_OVERFLOW:
	case SLJIT_C_MUL_OVERFLOW:
		return (12 << 21) | (3 << 16);

	case SLJIT_C_NOT_OVERFLOW:
	case SLJIT_C_MUL_NOT_OVERFLOW:
		return (4 << 21) | (3 << 16);

	case SLJIT_C_FLOAT_EQUAL:
		return (12 << 21) | ((4 + 2) << 16);

	case SLJIT_C_FLOAT_NOT_EQUAL:
		return (4 << 21) | ((4 + 2) << 16);

	case SLJIT_C_FLOAT_NAN:
		return (12 << 21) | ((4 + 3) << 16);

	case SLJIT_C_FLOAT_NOT_NAN:
		return (4 << 21) | ((4 + 3) << 16);

	default:
		SLJIT_ASSERT(type >= SLJIT_JUMP && type <= SLJIT_CALL3);
		return (20 << 21);
	}
}

struct sljit_jump* sljit_emit_jump(struct sljit_compiler *compiler, int type)
{
	struct sljit_jump *jump;
	sljit_i bo_bi_flags;

	FUNCTION_ENTRY();
	SLJIT_ASSERT((type & ~0x1ff) == 0);
	SLJIT_ASSERT((type & 0xff) >= SLJIT_C_EQUAL && (type & 0xff) <= SLJIT_CALL3);

	sljit_emit_jump_verbose();

	bo_bi_flags = get_bo_bi_flags(compiler, type & 0xff);
	if (!bo_bi_flags)
		return NULL;

	jump = (struct sljit_jump*)ensure_abuf(compiler, sizeof(struct sljit_jump));
	PTR_FAIL_IF(!jump);

	jump->next = NULL;
	jump->flags = type & SLJIT_REWRITABLE_JUMP;
	type &= 0xff;
	if (compiler->last_jump)
		compiler->last_jump->next = jump;
	else
		compiler->jumps = jump;
	compiler->last_jump = jump;

	// In PPC, we don't need to touch the arguments
	if (type >= SLJIT_JUMP)
		jump->flags |= UNCOND_ADDR;

	PTR_FAIL_IF(emit_const(compiler, TMP_REG1, 0));
	PTR_FAIL_IF(push_inst(compiler, MTCTR | S(TMP_REG1)));
	jump->addr = compiler->size;
	PTR_FAIL_IF(push_inst(compiler, BCCTR | bo_bi_flags | (type >= SLJIT_CALL0 ? 1 : 0)));
	return jump;
}

int sljit_emit_ijump(struct sljit_compiler *compiler, int type, int src, sljit_w srcw)
{
	sljit_i bo_bi_flags;
	int src_r;

	FUNCTION_ENTRY();
	SLJIT_ASSERT(type >= SLJIT_JUMP && type <= SLJIT_CALL3);
#ifdef SLJIT_DEBUG
	FUNCTION_CHECK_SRC(src, srcw);
#endif
	sljit_emit_ijump_verbose();

	bo_bi_flags = get_bo_bi_flags(compiler, type);
	FAIL_IF(!bo_bi_flags);

	if (src >= SLJIT_TEMPORARY_REG1 && src <= SLJIT_NO_REGISTERS)
		src_r = src;
	else if (src & SLJIT_IMM) {
		FAIL_IF(load_immediate(compiler, TMP_REG2, srcw));
		src_r = TMP_REG2;
	}
	else {
		FAIL_IF(emit_op(compiler, SLJIT_MOV, WORD_DATA, TMP_REG2, 0, TMP_REG1, 0, src, srcw));
		src_r = TMP_REG2;
	}

	FAIL_IF(push_inst(compiler, MTCTR | S(src_r)));
	return push_inst(compiler, BCCTR | bo_bi_flags | (type >= SLJIT_CALL0 ? 1 : 0));
}

// Get a bit from CR, all other bits are zeroed
#define GET_CR_BIT(bit, dst) \
	FAIL_IF(push_inst(compiler, MFCR | D(dst))); \
	FAIL_IF(push_inst(compiler, RLWINM | S(dst) | A(dst) | ((1 + (bit)) << 11) | (31 << 6) | (31 << 1)));

#define INVERT_BIT(dst) \
	FAIL_IF(push_inst(compiler, XORI | S(dst) | A(dst) | 0x1));

int sljit_emit_cond_set(struct sljit_compiler *compiler, int dst, sljit_w dstw, int type)
{
	int reg;

	FUNCTION_ENTRY();
	SLJIT_ASSERT(type >= SLJIT_C_EQUAL && type < SLJIT_JUMP);
#ifdef SLJIT_DEBUG
	FUNCTION_CHECK_DST(dst, dstw);
#endif
	sljit_emit_set_cond_verbose();

	if (dst == SLJIT_UNUSED)
		return SLJIT_SUCCESS;

	if (dst >= SLJIT_TEMPORARY_REG1 && dst <= SLJIT_NO_REGISTERS)
		reg = dst;
	else
		reg = TMP_REG2;

	switch (type) {
	case SLJIT_C_EQUAL:
		GET_CR_BIT(2, reg);
		break;

	case SLJIT_C_NOT_EQUAL:
		GET_CR_BIT(2, reg);
		INVERT_BIT(reg);
		break;

	case SLJIT_C_LESS:
	case SLJIT_C_FLOAT_LESS:
		GET_CR_BIT(4 + 0, reg);
		break;

	case SLJIT_C_NOT_LESS:
	case SLJIT_C_FLOAT_NOT_LESS:
		GET_CR_BIT(4 + 0, reg);
		INVERT_BIT(reg);
		break;

	case SLJIT_C_GREATER:
	case SLJIT_C_FLOAT_GREATER:
		GET_CR_BIT(4 + 1, reg);
		break;

	case SLJIT_C_NOT_GREATER:
	case SLJIT_C_FLOAT_NOT_GREATER:
		GET_CR_BIT(4 + 1, reg);
		INVERT_BIT(reg);
		break;

	case SLJIT_C_SIG_LESS:
		GET_CR_BIT(0, reg);
		break;

	case SLJIT_C_SIG_NOT_LESS:
		GET_CR_BIT(0, reg);
		INVERT_BIT(reg);
		break;

	case SLJIT_C_SIG_GREATER:
		GET_CR_BIT(1, reg);
		break;

	case SLJIT_C_SIG_NOT_GREATER:
		GET_CR_BIT(1, reg);
		INVERT_BIT(reg);
		break;

	case SLJIT_C_OVERFLOW:
	case SLJIT_C_MUL_OVERFLOW:
		GET_CR_BIT(3, reg);
		break;

	case SLJIT_C_NOT_OVERFLOW:
	case SLJIT_C_MUL_NOT_OVERFLOW:
		GET_CR_BIT(3, reg);
		INVERT_BIT(reg);
		break;

	case SLJIT_C_FLOAT_EQUAL:
		GET_CR_BIT(4 + 2, reg);
		break;

	case SLJIT_C_FLOAT_NOT_EQUAL:
		GET_CR_BIT(4 + 2, reg);
		INVERT_BIT(reg);
		break;

	case SLJIT_C_FLOAT_NAN:
		GET_CR_BIT(4 + 3, reg);
		break;

	case SLJIT_C_FLOAT_NOT_NAN:
		GET_CR_BIT(4 + 3, reg);
		INVERT_BIT(reg);
		break;

	default:
		SLJIT_ASSERT_STOP();
		break;
	}

	if (reg == TMP_REG2)
		return emit_op(compiler, SLJIT_MOV, WORD_DATA, dst, dstw, TMP_REG1, 0, TMP_REG2, 0);
	return SLJIT_SUCCESS;
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

	const_ = (struct sljit_const*)ensure_abuf(compiler, sizeof(struct sljit_const));
	PTR_FAIL_IF(!const_);

	const_->next = NULL;
	const_->addr = compiler->size;
	if (compiler->last_const)
		compiler->last_const->next = const_;
	else
		compiler->consts = const_;
	compiler->last_const = const_;

	reg = (dst >= SLJIT_TEMPORARY_REG1 && dst <= SLJIT_NO_REGISTERS) ? dst : TMP_REG2;

	if (emit_const(compiler, reg, initval))
		return NULL;

	if (reg == TMP_REG2 && dst != SLJIT_UNUSED)
		if (emit_op(compiler, SLJIT_MOV, WORD_DATA, dst, dstw, TMP_REG1, 0, TMP_REG2, 0))
			return NULL;
	return const_;
}
