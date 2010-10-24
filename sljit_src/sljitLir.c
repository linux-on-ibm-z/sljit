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

#include "sljitLir.h"

#ifndef SLJIT_CONFIG_UNSUPPORTED

#define FUNCTION_ENTRY() \
	SLJIT_ASSERT(compiler->error == SLJIT_SUCCESS)

#define FAIL_IF(expr) \
	do { \
		if (SLJIT_UNLIKELY(expr)) \
			return compiler->error; \
	} while (0)

#define PTR_FAIL_IF(expr) \
	do { \
		if (SLJIT_UNLIKELY(expr)) \
			return NULL; \
	} while (0)

#define FAIL_IF_NULL(ptr) \
	do { \
		if (SLJIT_UNLIKELY(!(ptr))) { \
			compiler->error = SLJIT_ERR_ALLOC_FAILED; \
			return SLJIT_ERR_ALLOC_FAILED; \
		} \
	} while (0)

#define PTR_FAIL_IF_NULL(ptr) \
	do { \
		if (SLJIT_UNLIKELY(!(ptr))) { \
			compiler->error = SLJIT_ERR_ALLOC_FAILED; \
			return NULL; \
		} \
	} while (0)

#define PTR_FAIL_WITH_EXEC_IF(ptr) \
	do { \
		if (SLJIT_UNLIKELY(!(ptr))) { \
			compiler->error = SLJIT_ERR_EX_ALLOC_FAILED; \
			return NULL; \
		} \
	} while (0)

#define GET_OPCODE(op) \
	((op) & ~(SLJIT_INT_OP | SLJIT_SET_E | SLJIT_SET_S | SLJIT_SET_U | SLJIT_SET_O | SLJIT_SET_C | SLJIT_KEEP_FLAGS))

#define GET_FLAGS(op) \
	((op) & (SLJIT_SET_E | SLJIT_SET_S | SLJIT_SET_U | SLJIT_SET_O | SLJIT_SET_C))

#define GET_ALL_FLAGS(op) \
	((op) & (SLJIT_SET_E | SLJIT_SET_S | SLJIT_SET_U | SLJIT_SET_O | SLJIT_SET_C | SLJIT_KEEP_FLAGS))

#define BUF_SIZE	2048
#define ABUF_SIZE	512

// Jump flags
#define JUMP_LABEL	0x1
#define JUMP_ADDR	0x2

#if defined(SLJIT_CONFIG_X86_32) || defined(SLJIT_CONFIG_X86_64)
	#define PATCH_MB	0x4
	#define PATCH_MW	0x8
#ifdef SLJIT_CONFIG_X86_64
	#define PATCH_MD	0x10
#endif
#endif

#if defined(SLJIT_CONFIG_ARM_V5) || defined(SLJIT_CONFIG_ARM_V7)
	#define IS_BL		0x4
	#define PATCH_B		0x8
#endif

#ifdef SLJIT_CONFIG_ARM_V5
	#define CPOOL_SIZE	512
#endif

#if defined(SLJIT_CONFIG_ARM_THUMB2)
	#define IS_CONDITIONAL	0x04
	#define IS_BL		0x08
	/* cannot be encoded as branch */
	#define B_TYPE0		0x00
	/* conditional + imm8 */
	#define B_TYPE1		0x10
	/* conditional + imm20 */
	#define B_TYPE2		0x20
	/* IT + imm24 */
	#define B_TYPE3		0x30
	/* imm11 */
	#define B_TYPE4		0x40
	/* imm24 */
	#define B_TYPE5		0x50
	/* BL + imm24 */
	#define BL_TYPE6	0x60
#endif

#if defined(SLJIT_CONFIG_PPC_32) || defined(SLJIT_CONFIG_PPC_64)
	#define UNCOND_B	0x04
	#define PATCH_B		0x08
	#define ABSOLUTE_B	0x10
#endif

#if defined(SLJIT_CONFIG_MIPS_32)
	#define IS_MOVABLE	0x04
	#define IS_JAL		0x08
	#define IS_BIT26_COND	0x10
	#define IS_BIT16_COND	0x20

	#define IS_COND		(IS_BIT26_COND | IS_BIT16_COND)

	#define PATCH_B		0x40
	#define PATCH_J		0x80

	/* instruction types */
	#define UNMOVABLE_INS	0
	/* 1 - 31 last destination register */
	/* 32 - 39 FCSR FCC bits */
	#define FCSR_FCC	32
	/* no destination (i.e: store) */
	#define MOVABLE_INS	40
#endif

#ifdef SLJIT_EXECUTABLE_ALLOCATOR
#include "sljitExecAllocator.c"
#endif

#if defined(SLJIT_SSE2_AUTO) && !defined(SLJIT_SSE2)
#error SLJIT_SSE2_AUTO cannot be enabled without SLJIT_SSE2
#endif

// ---------------------------------------------------------------------
//  Public functions
// ---------------------------------------------------------------------

#if defined(SLJIT_CONFIG_ARM_V5) || (defined(SLJIT_SSE2) && (defined(SLJIT_CONFIG_X86_32) || defined(SLJIT_CONFIG_X86_64)))
#define NEEDS_COMPILER_INIT
static int compiler_initialized = 0;
// A thread safe initialization
static void init_compiler();
#endif

struct sljit_compiler* sljit_create_compiler(void)
{
	struct sljit_compiler *compiler = (struct sljit_compiler*)SLJIT_MALLOC(sizeof(struct sljit_compiler));

	if (!compiler)
		return NULL;

	compiler->error = SLJIT_SUCCESS;

	compiler->labels = NULL;
	compiler->jumps = NULL;
	compiler->consts = NULL;
	compiler->last_label = NULL;
	compiler->last_jump = NULL;
	compiler->last_const = NULL;

	compiler->buf = (struct sljit_memory_fragment*)SLJIT_MALLOC(BUF_SIZE);
	compiler->abuf = (struct sljit_memory_fragment*)SLJIT_MALLOC(ABUF_SIZE);

	if (!compiler->buf || !compiler->abuf) {
		if (compiler->buf)
			SLJIT_FREE(compiler->buf);
		if (compiler->abuf)
			SLJIT_FREE(compiler->abuf);
		SLJIT_FREE(compiler);
		return NULL;
	}

	compiler->buf->next = NULL;
	compiler->buf->used_size = 0;
	compiler->abuf->next = NULL;
	compiler->abuf->used_size = 0;

	compiler->temporaries = -1;
	compiler->generals = -1;
	compiler->local_size = 0;
	compiler->size = 0;

#ifdef SLJIT_CONFIG_X86_32
	compiler->args = -1;
#endif

#if defined(SLJIT_CONFIG_X86_32) || defined(SLJIT_CONFIG_X86_64)
	compiler->flags_saved = 0;
#endif

#ifdef SLJIT_CONFIG_ARM_V5
	compiler->cpool = (sljit_uw*)SLJIT_MALLOC(CPOOL_SIZE * sizeof(sljit_uw) + CPOOL_SIZE * sizeof(sljit_ub));
	if (!compiler->cpool) {
		SLJIT_FREE(compiler->buf);
		SLJIT_FREE(compiler->abuf);
		SLJIT_FREE(compiler);
		return NULL;
	}
	compiler->cpool_unique = (sljit_ub*)(compiler->cpool + CPOOL_SIZE);
	compiler->cpool_diff = 0xffffffff;
	compiler->cpool_fill = 0;
	compiler->patches = 0;
#endif

#if defined(SLJIT_CONFIG_MIPS_32)
	compiler->has_locals = 0;
	compiler->delay_slot = UNMOVABLE_INS;
#endif

#ifdef SLJIT_VERBOSE
	compiler->verbose = NULL;
#endif

#ifdef NEEDS_COMPILER_INIT
	if (!compiler_initialized) {
		init_compiler();
		compiler_initialized = 1;
	}
#endif

	return compiler;
}

void sljit_free_compiler(struct sljit_compiler *compiler)
{
	struct sljit_memory_fragment *buf;
	struct sljit_memory_fragment *curr;

	buf = compiler->buf;
	while (buf) {
		curr = buf;
		buf = buf->next;
		SLJIT_FREE(curr);
	}

	buf = compiler->abuf;
	while (buf) {
		curr = buf;
		buf = buf->next;
		SLJIT_FREE(curr);
	}

#ifdef SLJIT_CONFIG_ARM_V5
	SLJIT_FREE(compiler->cpool);
#endif
	SLJIT_FREE(compiler);
}

#if defined(SLJIT_CONFIG_ARM_THUMB2)
void sljit_free_code(void* code)
{
	// Remove thumb mode flag
	SLJIT_FREE_EXEC((void*)((sljit_uw)code & ~0x1));
}
#elif defined(SLJIT_CONFIG_PPC_64)
void sljit_free_code(void* code)
{
	// Resolve indirection
	code = (void*)(*(sljit_uw*)code);
	SLJIT_FREE_EXEC(code);
}
#else
void sljit_free_code(void* code)
{
	SLJIT_FREE_EXEC(code);
}
#endif

void sljit_set_label(struct sljit_jump *jump, struct sljit_label* label)
{
	jump->flags &= ~JUMP_ADDR;
	jump->flags |= JUMP_LABEL;
	jump->label = label;
}

void sljit_set_target(struct sljit_jump *jump, sljit_uw target)
{
	SLJIT_ASSERT(jump->flags & SLJIT_REWRITABLE_JUMP);

	jump->flags &= ~JUMP_LABEL;
	jump->flags |= JUMP_ADDR;
	jump->target = target;
}

// ---------------------------------------------------------------------
//  Private functions
// ---------------------------------------------------------------------

static void* ensure_buf(struct sljit_compiler *compiler, int size)
{
	sljit_ub *ret;
	struct sljit_memory_fragment *new_frag;

	if (compiler->buf->used_size + size <= (int)(BUF_SIZE - sizeof(int) - sizeof(void*))) {
		ret = compiler->buf->memory + compiler->buf->used_size;
		compiler->buf->used_size += size;
		return ret;
	}
	new_frag = (struct sljit_memory_fragment*)SLJIT_MALLOC(BUF_SIZE);
	PTR_FAIL_IF_NULL(new_frag);
	new_frag->next = compiler->buf;
	compiler->buf = new_frag;
	new_frag->used_size = size;
	return new_frag->memory;
}

static void* ensure_abuf(struct sljit_compiler *compiler, int size)
{
	sljit_ub *ret;
	struct sljit_memory_fragment *new_frag;

	if (compiler->abuf->used_size + size <= (int)(ABUF_SIZE - sizeof(int) - sizeof(void*))) {
		ret = compiler->abuf->memory + compiler->abuf->used_size;
		compiler->abuf->used_size += size;
		return ret;
	}
	new_frag = (struct sljit_memory_fragment*)SLJIT_MALLOC(ABUF_SIZE);
	PTR_FAIL_IF_NULL(new_frag);
	new_frag->next = compiler->abuf;
	compiler->abuf = new_frag;
	new_frag->used_size = size;
	return new_frag->memory;
}

static SLJIT_INLINE void reverse_buf(struct sljit_compiler *compiler)
{
	struct sljit_memory_fragment *buf = compiler->buf;
	struct sljit_memory_fragment *prev = NULL;
	struct sljit_memory_fragment *tmp;

	do {
		tmp = buf->next;
		buf->next = prev;
		prev = buf;
		buf = tmp;
	} while (buf != NULL);

	compiler->buf = prev;
}

static SLJIT_INLINE void set_label(struct sljit_label *label, struct sljit_compiler *compiler)
{
	label->next = NULL;
	label->size = compiler->size;
	if (compiler->last_label)
		compiler->last_label->next = label;
	else
		compiler->labels = label;
	compiler->last_label = label;
}

static SLJIT_INLINE void set_jump(struct sljit_jump *jump, struct sljit_compiler *compiler, int flags)
{
	jump->next = NULL;
	jump->flags = flags;
	if (compiler->last_jump)
		compiler->last_jump->next = jump;
	else
		compiler->jumps = jump;
	compiler->last_jump = jump;
}

#define depends_on(exp, reg) \
	(((exp) & SLJIT_MEM) && (((exp) & 0xf) == reg || (((exp) >> 4) & 0xf) == reg))

#ifdef SLJIT_DEBUG
#define FUNCTION_CHECK_OP() \
	SLJIT_ASSERT(!GET_FLAGS(op) || !(op & SLJIT_KEEP_FLAGS)); \
	switch (GET_OPCODE(op)) { \
	case SLJIT_NOT: \
	case SLJIT_AND: \
	case SLJIT_OR: \
	case SLJIT_XOR: \
	case SLJIT_SHL: \
	case SLJIT_LSHR: \
	case SLJIT_ASHR: \
		SLJIT_ASSERT(!(op & (SLJIT_SET_S | SLJIT_SET_U | SLJIT_SET_O | SLJIT_SET_C))); \
		break; \
	case SLJIT_NEG: \
		SLJIT_ASSERT(!(op & (SLJIT_SET_S | SLJIT_SET_U | SLJIT_SET_C))); \
		break; \
	case SLJIT_MUL: \
		SLJIT_ASSERT(!(op & (SLJIT_SET_E | SLJIT_SET_S | SLJIT_SET_U | SLJIT_SET_C))); \
		break; \
	case SLJIT_FCMP: \
		SLJIT_ASSERT(!(op & (SLJIT_INT_OP | SLJIT_SET_U | SLJIT_SET_O | SLJIT_SET_C | SLJIT_KEEP_FLAGS))); \
		SLJIT_ASSERT((op & (SLJIT_SET_E | SLJIT_SET_S))); \
		break; \
	case SLJIT_ADD: \
		SLJIT_ASSERT(!(op & (SLJIT_SET_S | SLJIT_SET_U))); \
		break; \
	case SLJIT_SUB: \
		break; \
	case SLJIT_ADDC: \
	case SLJIT_SUBC: \
		SLJIT_ASSERT(!(op & (SLJIT_SET_E | SLJIT_SET_S | SLJIT_SET_U | SLJIT_SET_O))); \
		break; \
	default: \
		/* Nothing allowed */ \
		SLJIT_ASSERT(!(op & (SLJIT_INT_OP | SLJIT_SET_E | SLJIT_SET_S | SLJIT_SET_U | SLJIT_SET_O | SLJIT_SET_C | SLJIT_KEEP_FLAGS))); \
		break; \
	}

#define FUNCTION_CHECK_IS_REG(r) \
	((r) == SLJIT_UNUSED || (r) == SLJIT_LOCALS_REG || \
	((r) >= SLJIT_TEMPORARY_REG1 && (r) <= SLJIT_TEMPORARY_REG3 && (r) <= SLJIT_TEMPORARY_REG1 - 1 + compiler->temporaries) || \
	((r) >= SLJIT_GENERAL_REG1 && (r) <= SLJIT_GENERAL_REG3 && (r) <= SLJIT_GENERAL_REG1 - 1 + compiler->generals)) \

#define FUNCTION_CHECK_SRC(p, i) \
	SLJIT_ASSERT(compiler->temporaries != -1 && compiler->generals != -1); \
	if (((p) >= SLJIT_TEMPORARY_REG1 && (p) <= SLJIT_TEMPORARY_REG1 - 1 + compiler->temporaries) || \
			((p) >= SLJIT_GENERAL_REG1 && (p) <= SLJIT_GENERAL_REG1 - 1 + compiler->generals) || \
			(p) == SLJIT_LOCALS_REG) \
		SLJIT_ASSERT(i == 0); \
	else if ((p) == SLJIT_IMM) \
		; \
	else if ((p) & SLJIT_MEM) { \
		SLJIT_ASSERT(FUNCTION_CHECK_IS_REG((p) & 0xf)); \
		if ((p) & 0xf0) { \
			SLJIT_ASSERT(FUNCTION_CHECK_IS_REG(((p) >> 4) & 0xf)); \
			SLJIT_ASSERT(((p) & 0xf0) != (SLJIT_LOCALS_REG << 4) && !(i & ~0x3)); \
		} else \
			SLJIT_ASSERT((((p) >> 4) & 0xf) == 0); \
		SLJIT_ASSERT(((p) >> 9) == 0); \
	} \
	else \
		SLJIT_ASSERT_STOP();

#define FUNCTION_CHECK_DST(p, i) \
	SLJIT_ASSERT(compiler->temporaries != -1 && compiler->generals != -1); \
	if (((p) >= SLJIT_TEMPORARY_REG1 && (p) <= SLJIT_TEMPORARY_REG1 - 1 + compiler->temporaries) || \
			((p) >= SLJIT_GENERAL_REG1 && (p) <= SLJIT_GENERAL_REG1 - 1 + compiler->generals) || \
			(p) == SLJIT_UNUSED) \
		SLJIT_ASSERT(i == 0); \
	else if ((p) & SLJIT_MEM) { \
		SLJIT_ASSERT(FUNCTION_CHECK_IS_REG((p) & 0xf)); \
		if ((p) & 0xf0) { \
			SLJIT_ASSERT(FUNCTION_CHECK_IS_REG(((p) >> 4) & 0xf)); \
			SLJIT_ASSERT(((p) & 0xf0) != (SLJIT_LOCALS_REG << 4) && !(i & ~0x3)); \
		} else \
			SLJIT_ASSERT((((p) >> 4) & 0xf) == 0); \
		SLJIT_ASSERT(((p) >> 9) == 0); \
	} \
	else \
		SLJIT_ASSERT_STOP();

#define FUNCTION_FCHECK(p, i) \
	if ((p) >= SLJIT_FLOAT_REG1 && (p) <= SLJIT_FLOAT_REG4) \
		SLJIT_ASSERT(i == 0); \
	else if ((p) & SLJIT_MEM) { \
		SLJIT_ASSERT(FUNCTION_CHECK_IS_REG((p) & 0xf)); \
		if ((p) & 0xf0) { \
			SLJIT_ASSERT(FUNCTION_CHECK_IS_REG(((p) >> 4) & 0xf)); \
			SLJIT_ASSERT(((p) & 0xf0) != (SLJIT_LOCALS_REG << 4) && !(i & ~0x3)); \
		} else \
			SLJIT_ASSERT((((p) >> 4) & 0xf) == 0); \
		SLJIT_ASSERT(((p) >> 9) == 0); \
	} \
	else \
		SLJIT_ASSERT_STOP();

#define FUNCTION_CHECK_OP1() \
	if (GET_OPCODE(op) >= SLJIT_MOV && GET_OPCODE(op) <= SLJIT_MOVU_SI) { \
		SLJIT_ASSERT(!GET_ALL_FLAGS(op)); \
	} \
        if (GET_OPCODE(op) >= SLJIT_MOVU && GET_OPCODE(op) <= SLJIT_MOVU_SI) { \
		SLJIT_ASSERT(!(src & SLJIT_MEM) || (src & 0xf) != SLJIT_LOCALS_REG); \
		SLJIT_ASSERT(!(dst & SLJIT_MEM) || (dst & 0xf) != SLJIT_LOCALS_REG); \
		if ((src & SLJIT_MEM) && (src & 0xf)) \
			SLJIT_ASSERT((dst & 0xf) != (src & 0xf) && ((dst >> 4) & 0xf) != (src & 0xf)); \
	}

#endif

#ifdef SLJIT_VERBOSE

void sljit_compiler_verbose(struct sljit_compiler *compiler, FILE* verbose)
{
	compiler->verbose = verbose;
}

static char* reg_names[] = {
	(char*)"<noreg>", (char*)"tmp_r1", (char*)"tmp_r2", (char*)"tmp_r3",
	(char*)"tmp_er1", (char*)"tmp_er2", (char*)"gen_r1", (char*)"gen_r2",
	(char*)"gen_r3", (char*)"gen_er1", (char*)"gen_er2", (char*)"stack_r"
};

static char* freg_names[] = {
	(char*)"<noreg>", (char*)"float_r1", (char*)"float_r2", (char*)"float_r3", (char*)"float_r4"
};

#if defined(SLJIT_CONFIG_X86_64) || defined(SLJIT_CONFIG_PPC_64)
#ifdef _WIN64
	#define SLJIT_PRINT_D	"I64"
#else
	#define SLJIT_PRINT_D	"l"
#endif
#else
	#define SLJIT_PRINT_D	""
#endif

#define sljit_verbose_param(p, i) \
	if ((p) & SLJIT_IMM) \
		fprintf(compiler->verbose, "#%"SLJIT_PRINT_D"d", (i)); \
	else if ((p) & SLJIT_MEM) { \
		if ((p) & 0xf) { \
			if (i) { \
				if (((p) >> 4) & 0xf) \
					fprintf(compiler->verbose, "[%s + %s * %d]", reg_names[(p) & 0xF], reg_names[((p) >> 4)& 0xF], 1 << (i)); \
				else \
					fprintf(compiler->verbose, "[%s + #%"SLJIT_PRINT_D"d]", reg_names[(p) & 0xF], (i)); \
			} \
			else { \
				if (((p) >> 4) & 0xf) \
					fprintf(compiler->verbose, "[%s + %s]", reg_names[(p) & 0xF], reg_names[((p) >> 4)& 0xF]); \
				else \
					fprintf(compiler->verbose, "[%s]", reg_names[(p) & 0xF]); \
			} \
		} \
		else \
			fprintf(compiler->verbose, "[#%"SLJIT_PRINT_D"d]", (i)); \
	} else \
		fprintf(compiler->verbose, "%s", reg_names[p]);
#define sljit_verbose_fparam(p, i) \
	if ((p) & SLJIT_MEM) { \
		if ((p) & 0xf) { \
			if (i) { \
				if (((p) >> 4) & 0xf) \
					fprintf(compiler->verbose, "[%s + %s * %d]", reg_names[(p) & 0xF], reg_names[((p) >> 4)& 0xF], 1 << (i)); \
				else \
					fprintf(compiler->verbose, "[%s + #%"SLJIT_PRINT_D"d]", reg_names[(p) & 0xF], (i)); \
			} \
			else { \
				if (((p) >> 4) & 0xF) \
					fprintf(compiler->verbose, "[%s + %s]", reg_names[(p) & 0xF], reg_names[((p) >> 4)& 0xF]); \
				else \
					fprintf(compiler->verbose, "[%s]", reg_names[(p) & 0xF]); \
			} \
		} \
		else \
			fprintf(compiler->verbose, "[#%"SLJIT_PRINT_D"d]", (i)); \
	} else \
		fprintf(compiler->verbose, "%s", freg_names[p]);

static SLJIT_CONST char* op_names[] = {
	// op0
	(char*)"debugger", (char*)"nop",
	// op1
	(char*)"mov", (char*)"mov.ub", (char*)"mov.sb", (char*)"mov.uh",
	(char*)"mov.sh", (char*)"mov.ui", (char*)"mov.si", (char*)"movu",
	(char*)"movu.ub", (char*)"movu.sb", (char*)"movu.uh", (char*)"movu.sh",
	(char*)"movu.ui", (char*)"movu.si", (char*)"not", (char*)"neg",
	// op2
	(char*)"add", (char*)"addc", (char*)"sub", (char*)"subc",
	(char*)"mul", (char*)"and", (char*)"or", (char*)"xor",
	(char*)"shl", (char*)"lshr", (char*)"ashr",
	// fop1
	(char*)"fcmp", (char*)"fmov", (char*)"fneg", (char*)"fabs",
	// fop2
	(char*)"fadd", (char*)"fsub", (char*)"fmul", (char*)"fdiv"
};

static char* jump_names[] = {
	(char*)"c_equal", (char*)"c_not_equal",
	(char*)"c_less", (char*)"c_not_less",
	(char*)"c_greater", (char*)"c_not_greater",
	(char*)"c_sig_less", (char*)"c_sig_not_less",
	(char*)"c_sig_greater", (char*)"c_sig_not_greater",
	(char*)"c_overflow", (char*)"c_not_overflow",
	(char*)"c_mul_overflow", (char*)"c_mul_not_overflow",
	(char*)"c_float_equal", (char*)"c_float_not_equal",
	(char*)"c_float_less", (char*)"c_float_not_less",
	(char*)"c_float_greater", (char*)"c_float_not_greater",
	(char*)"c_float_nan", (char*)"c_float_not_nan",
	(char*)"jump",
	(char*)"call0", (char*)"call1", (char*)"call2", (char*)"call3"
};

#endif

// ---------------------------------------------------------------------
//  Arch dependent
// ---------------------------------------------------------------------

static SLJIT_INLINE void check_sljit_generate_code(struct sljit_compiler *compiler)
{
	// If debug and verbose are disabled, all arguments are unused
	(void)compiler;

	FUNCTION_ENTRY();
	SLJIT_ASSERT(compiler->size > 0);
}

static SLJIT_INLINE void check_sljit_emit_enter(struct sljit_compiler *compiler, int args, int temporaries, int generals, int local_size)
{
	// If debug and verbose are disabled, all arguments are unused
	(void)compiler;
	(void)args;
	(void)temporaries;
	(void)generals;
	(void)local_size;

	FUNCTION_ENTRY();
	SLJIT_ASSERT(args >= 0 && args <= 3);
	SLJIT_ASSERT(temporaries >= 0 && temporaries <= SLJIT_NO_TMP_REGISTERS);
	SLJIT_ASSERT(generals >= 0 && generals <= SLJIT_NO_GEN_REGISTERS);
	SLJIT_ASSERT(args <= generals);
	SLJIT_ASSERT(local_size >= 0 && local_size <= SLJIT_MAX_LOCAL_SIZE);
#ifdef SLJIT_VERBOSE
	if (SLJIT_UNLIKELY(!!compiler->verbose))
		fprintf(compiler->verbose, "  enter args=%d temporaries=%d generals=%d local_size=%d\n", args, temporaries, generals, local_size);
#endif
}

static SLJIT_INLINE void check_sljit_fake_enter(struct sljit_compiler *compiler, int args, int temporaries, int generals, int local_size)
{
	// If debug and verbose are disabled, all arguments are unused
	(void)compiler;
	(void)args;
	(void)temporaries;
	(void)generals;
	(void)local_size;

	FUNCTION_ENTRY();
	SLJIT_ASSERT(args >= 0 && args <= 3);
	SLJIT_ASSERT(temporaries >= 0 && temporaries <= SLJIT_NO_TMP_REGISTERS);
	SLJIT_ASSERT(generals >= 0 && generals <= SLJIT_NO_GEN_REGISTERS);
	SLJIT_ASSERT(args <= generals);
	SLJIT_ASSERT(local_size >= 0 && local_size <= SLJIT_MAX_LOCAL_SIZE);
#ifdef SLJIT_VERBOSE
	if (SLJIT_UNLIKELY(!!compiler->verbose))
		fprintf(compiler->verbose, "  fake_enter args=%d temporaries=%d generals=%d local_size=%d\n", args, temporaries, generals, local_size);
#endif
}

static SLJIT_INLINE void check_sljit_emit_return(struct sljit_compiler *compiler, int src, sljit_w srcw)
{
	// If debug and verbose are disabled, all arguments are unused
	(void)compiler;
	(void)src;
	(void)srcw;

	FUNCTION_ENTRY();
#ifdef SLJIT_DEBUG
	if (src != SLJIT_UNUSED) {
		FUNCTION_CHECK_SRC(src, srcw);
	}
	else
		SLJIT_ASSERT(srcw == 0);
#endif
#ifdef SLJIT_VERBOSE
	if (SLJIT_UNLIKELY(!!compiler->verbose)) {
		fprintf(compiler->verbose, "  return ");
		sljit_verbose_param(src, srcw);
		fprintf(compiler->verbose, "\n");
	}
#endif
}

static SLJIT_INLINE void check_sljit_emit_fast_enter(struct sljit_compiler *compiler, int dst, sljit_w dstw, int args, int temporaries, int generals, int local_size)
{
	// If debug and verbose are disabled, all arguments are unused
	(void)compiler;
	(void)dst;
	(void)dstw;
	(void)args;
	(void)temporaries;
	(void)generals;
	(void)local_size;

	FUNCTION_ENTRY();
	SLJIT_ASSERT(args >= 0 && args <= 3);
	SLJIT_ASSERT(temporaries >= 0 && temporaries <= SLJIT_NO_TMP_REGISTERS);
	SLJIT_ASSERT(generals >= 0 && generals <= SLJIT_NO_GEN_REGISTERS);
	SLJIT_ASSERT(args <= generals);
	SLJIT_ASSERT(local_size >= 0 && local_size <= SLJIT_MAX_LOCAL_SIZE);
#ifdef SLJIT_DEBUG
	compiler->temporaries = temporaries;
	compiler->generals = generals;
	FUNCTION_CHECK_DST(dst, dstw);
	compiler->temporaries = -1;
	compiler->generals = -1;
#endif
#ifdef SLJIT_VERBOSE
	if (SLJIT_UNLIKELY(!!compiler->verbose)) {
		fprintf(compiler->verbose, "  fast_enter ");
		sljit_verbose_param(dst, dstw);
		fprintf(compiler->verbose, " args=%d temporaries=%d generals=%d local_size=%d\n", args, temporaries, generals, local_size);
	}
#endif
}

static SLJIT_INLINE void check_sljit_emit_fast_return(struct sljit_compiler *compiler, int src, sljit_w srcw)
{
	// If debug and verbose are disabled, all arguments are unused
	(void)compiler;
	(void)src;
	(void)srcw;

	FUNCTION_ENTRY();
#ifdef SLJIT_DEBUG
	FUNCTION_CHECK_SRC(src, srcw);
#endif
#ifdef SLJIT_VERBOSE
	if (SLJIT_UNLIKELY(!!compiler->verbose)) {
		fprintf(compiler->verbose, "  fast_return ");
		sljit_verbose_param(src, srcw);
		fprintf(compiler->verbose, "\n");
	}
#endif
}

static SLJIT_INLINE void check_sljit_emit_op0(struct sljit_compiler *compiler, int op)
{
	// If debug and verbose are disabled, all arguments are unused
	(void)compiler;
	(void)op;

	FUNCTION_ENTRY();
	SLJIT_ASSERT(GET_OPCODE(op) >= SLJIT_DEBUGGER && GET_OPCODE(op) <= SLJIT_NOP);
#ifdef SLJIT_VERBOSE
	if (SLJIT_UNLIKELY(!!compiler->verbose))
		fprintf(compiler->verbose, "  %s\n", op_names[GET_OPCODE(op)]);
#endif
}

static SLJIT_INLINE void check_sljit_emit_op1(struct sljit_compiler *compiler, int op,
	int dst, sljit_w dstw,
	int src, sljit_w srcw)
{
	// If debug and verbose are disabled, all arguments are unused
	(void)compiler;
	(void)op;
	(void)dst;
	(void)dstw;
	(void)src;
	(void)srcw;

	FUNCTION_ENTRY();
	SLJIT_ASSERT(GET_OPCODE(op) >= SLJIT_MOV && GET_OPCODE(op) <= SLJIT_NEG);
#ifdef SLJIT_DEBUG
	FUNCTION_CHECK_OP();
	FUNCTION_CHECK_SRC(src, srcw);
	FUNCTION_CHECK_DST(dst, dstw);
	FUNCTION_CHECK_OP1();
#endif
#ifdef SLJIT_VERBOSE
	if (SLJIT_UNLIKELY(!!compiler->verbose)) {
		fprintf(compiler->verbose, "  %s%s%s%s%s%s%s%s ", !(op & SLJIT_INT_OP) ? "" : "i", op_names[GET_OPCODE(op)],
			!(op & SLJIT_SET_E) ? "" : "E", !(op & SLJIT_SET_S) ? "" : "S", !(op & SLJIT_SET_U) ? "" : "U", !(op & SLJIT_SET_O) ? "" : "O", !(op & SLJIT_SET_C) ? "" : "C", !(op & SLJIT_KEEP_FLAGS) ? "" : "K");
		sljit_verbose_param(dst, dstw);
		fprintf(compiler->verbose, ", ");
		sljit_verbose_param(src, srcw);
		fprintf(compiler->verbose, "\n");
	}
#endif
}

static SLJIT_INLINE void check_sljit_emit_op2(struct sljit_compiler *compiler, int op,
	int dst, sljit_w dstw,
	int src1, sljit_w src1w,
	int src2, sljit_w src2w)
{
	// If debug and verbose are disabled, all arguments are unused
	(void)compiler;
	(void)op;
	(void)dst;
	(void)dstw;
	(void)src1;
	(void)src1w;
	(void)src2;
	(void)src2w;

	FUNCTION_ENTRY();
	SLJIT_ASSERT(GET_OPCODE(op) >= SLJIT_ADD && GET_OPCODE(op) <= SLJIT_ASHR);
#ifdef SLJIT_DEBUG
	FUNCTION_CHECK_OP();
	FUNCTION_CHECK_SRC(src1, src1w);
	FUNCTION_CHECK_SRC(src2, src2w);
	FUNCTION_CHECK_DST(dst, dstw);
#endif
#ifdef SLJIT_VERBOSE
	if (SLJIT_UNLIKELY(!!compiler->verbose)) {
		fprintf(compiler->verbose, "  %s%s%s%s%s%s%s%s ", !(op & SLJIT_INT_OP) ? "" : "i", op_names[GET_OPCODE(op)],
			!(op & SLJIT_SET_E) ? "" : "E", !(op & SLJIT_SET_S) ? "" : "S", !(op & SLJIT_SET_U) ? "" : "U", !(op & SLJIT_SET_O) ? "" : "O", !(op & SLJIT_SET_C) ? "" : "C", !(op & SLJIT_KEEP_FLAGS) ? "" : "K");
		sljit_verbose_param(dst, dstw);
		fprintf(compiler->verbose, ", ");
		sljit_verbose_param(src1, src1w);
		fprintf(compiler->verbose, ", ");
		sljit_verbose_param(src2, src2w);
		fprintf(compiler->verbose, "\n");
	}
#endif
}

static SLJIT_INLINE void check_sljit_emit_fop1(struct sljit_compiler *compiler, int op,
	int dst, sljit_w dstw,
	int src, sljit_w srcw)
{
	// If debug and verbose are disabled, all arguments are unused
	(void)compiler;
	(void)op;
	(void)dst;
	(void)dstw;
	(void)src;
	(void)srcw;

	FUNCTION_ENTRY();
	SLJIT_ASSERT(sljit_is_fpu_available());
	SLJIT_ASSERT(GET_OPCODE(op) >= SLJIT_FCMP && GET_OPCODE(op) <= SLJIT_FABS);
#ifdef SLJIT_DEBUG
	FUNCTION_CHECK_OP();
	FUNCTION_FCHECK(src, srcw);
	FUNCTION_FCHECK(dst, dstw);
#endif
#ifdef SLJIT_VERBOSE
	if (SLJIT_UNLIKELY(!!compiler->verbose)) {
		fprintf(compiler->verbose, "  %s%s%s ", op_names[GET_OPCODE(op)],
			!(op & SLJIT_SET_E) ? "" : "E", !(op & SLJIT_SET_S) ? "" : "S");
		sljit_verbose_fparam(dst, dstw);
		fprintf(compiler->verbose, ", ");
		sljit_verbose_fparam(src, srcw);
		fprintf(compiler->verbose, "\n");
	}
#endif
}

static SLJIT_INLINE void check_sljit_emit_fop2(struct sljit_compiler *compiler, int op,
	int dst, sljit_w dstw,
	int src1, sljit_w src1w,
	int src2, sljit_w src2w)
{
	// If debug and verbose are disabled, all arguments are unused
	(void)compiler;
	(void)op;
	(void)dst;
	(void)dstw;
	(void)src1;
	(void)src1w;
	(void)src2;
	(void)src2w;

	FUNCTION_ENTRY();
	SLJIT_ASSERT(sljit_is_fpu_available());
	SLJIT_ASSERT(GET_OPCODE(op) >= SLJIT_FADD && GET_OPCODE(op) <= SLJIT_FDIV);
#ifdef SLJIT_DEBUG
	FUNCTION_CHECK_OP();
	FUNCTION_FCHECK(src1, src1w);
	FUNCTION_FCHECK(src2, src2w);
	FUNCTION_FCHECK(dst, dstw);
#endif
#ifdef SLJIT_VERBOSE
	if (SLJIT_UNLIKELY(!!compiler->verbose)) {
		fprintf(compiler->verbose, "  %s ", op_names[GET_OPCODE(op)]);
		sljit_verbose_fparam(dst, dstw);
		fprintf(compiler->verbose, ", ");
		sljit_verbose_fparam(src1, src1w);
		fprintf(compiler->verbose, ", ");
		sljit_verbose_fparam(src2, src2w);
		fprintf(compiler->verbose, "\n");
	}
#endif
}

static SLJIT_INLINE void check_sljit_emit_label(struct sljit_compiler *compiler)
{
	// If debug and verbose are disabled, all arguments are unused
	(void)compiler;

	FUNCTION_ENTRY();
#ifdef SLJIT_VERBOSE
	if (SLJIT_UNLIKELY(!!compiler->verbose))
		fprintf(compiler->verbose, "label:\n");
#endif
}

static SLJIT_INLINE void check_sljit_emit_jump(struct sljit_compiler *compiler, int type)
{
	// If debug and verbose are disabled, all arguments are unused
	(void)compiler;
	(void)type;

	FUNCTION_ENTRY();
	SLJIT_ASSERT(!(type & ~(0xff | SLJIT_REWRITABLE_JUMP)));
	SLJIT_ASSERT((type & 0xff) >= SLJIT_C_EQUAL && (type & 0xff) <= SLJIT_CALL3);
#ifdef SLJIT_VERBOSE
	if (SLJIT_UNLIKELY(!!compiler->verbose))
		fprintf(compiler->verbose, "  jump%s <%s>\n", !(type & SLJIT_REWRITABLE_JUMP) ? "" : "R", jump_names[type & 0xff]);
#endif
}

static SLJIT_INLINE void check_sljit_emit_cmp(struct sljit_compiler *compiler, int type,
	int src1, sljit_w src1w,
	int src2, sljit_w src2w)
{
	(void)compiler;
	(void)type;
	(void)src1;
	(void)src1w;
	(void)src2;
	(void)src2w;

	FUNCTION_ENTRY();
	SLJIT_ASSERT(!(type & ~(0xff | SLJIT_INT_OP | SLJIT_REWRITABLE_JUMP)));
	SLJIT_ASSERT((type & 0xff) >= SLJIT_C_EQUAL && (type & 0xff) <= SLJIT_C_SIG_NOT_GREATER);
#ifdef SLJIT_DEBUG
	FUNCTION_CHECK_SRC(src1, src1w);
	FUNCTION_CHECK_SRC(src2, src2w);
#endif
#ifdef SLJIT_VERBOSE
	if (SLJIT_UNLIKELY(!!compiler->verbose)) {
		fprintf(compiler->verbose, "  %scmp%s <%s> ", !(type & SLJIT_INT_OP) ? "" : "i", !(type & SLJIT_REWRITABLE_JUMP) ? "" : "R", jump_names[type & 0xff]);
		sljit_verbose_param(src1, src1w);
		fprintf(compiler->verbose, ", ");
		sljit_verbose_param(src2, src2w);
		fprintf(compiler->verbose, "\n");
	}
#endif
}

static SLJIT_INLINE void check_sljit_emit_ijump(struct sljit_compiler *compiler, int type, int src, sljit_w srcw)
{
	// If debug and verbose are disabled, all arguments are unused
	(void)compiler;
	(void)type;
	(void)src;
	(void)srcw;

	FUNCTION_ENTRY();
	SLJIT_ASSERT(type >= SLJIT_JUMP && type <= SLJIT_CALL3);
#ifdef SLJIT_DEBUG
	FUNCTION_CHECK_SRC(src, srcw);
#endif
#ifdef SLJIT_VERBOSE
	if (SLJIT_UNLIKELY(!!compiler->verbose)) {
		fprintf(compiler->verbose, "  ijump <%s> ", jump_names[type]);
		sljit_verbose_param(src, srcw);
		fprintf(compiler->verbose, "\n");
	}
#endif
}

static SLJIT_INLINE void check_sljit_emit_cond_set(struct sljit_compiler *compiler, int dst, sljit_w dstw, int type)
{
	// If debug and verbose are disabled, all arguments are unused
	(void)compiler;
	(void)dst;
	(void)dstw;
	(void)type;

	FUNCTION_ENTRY();
	SLJIT_ASSERT(type >= SLJIT_C_EQUAL && type < SLJIT_JUMP);
#ifdef SLJIT_DEBUG
	FUNCTION_CHECK_DST(dst, dstw);
#endif
#ifdef SLJIT_VERBOSE
	if (SLJIT_UNLIKELY(!!compiler->verbose)) {
		fprintf(compiler->verbose, "  cond_set ");
		sljit_verbose_param(dst, dstw);
		fprintf(compiler->verbose, ", %s\n", jump_names[type]);
	}
#endif
}

static SLJIT_INLINE void check_sljit_emit_const(struct sljit_compiler *compiler, int dst, sljit_w dstw, sljit_w init_value)
{
	// If debug and verbose are disabled, all arguments are unused
	(void)compiler;
	(void)dst;
	(void)dstw;
	(void)init_value;

	FUNCTION_ENTRY();
#ifdef SLJIT_DEBUG
	FUNCTION_CHECK_DST(dst, dstw);
#endif
#ifdef SLJIT_VERBOSE
	if (SLJIT_UNLIKELY(!!compiler->verbose)) {
		fprintf(compiler->verbose, "  const ");
		sljit_verbose_param(dst, dstw);
		fprintf(compiler->verbose, ", #%"SLJIT_PRINT_D"d\n", init_value);
	}
#endif
}

#if defined(SLJIT_CONFIG_X86_32)
	#include "sljitNativeX86_common.c"
#elif defined(SLJIT_CONFIG_X86_64)
	#include "sljitNativeX86_common.c"
#elif defined(SLJIT_CONFIG_ARM_V5) || defined(SLJIT_CONFIG_ARM_V7)
	#include "sljitNativeARM_v5.c"
#elif defined(SLJIT_CONFIG_ARM_THUMB2)
	#include "sljitNativeARM_Thumb2.c"
#elif defined(SLJIT_CONFIG_PPC_32)
	#include "sljitNativePPC_common.c"
#elif defined(SLJIT_CONFIG_PPC_64)
	#include "sljitNativePPC_common.c"
#elif defined(SLJIT_CONFIG_MIPS_32)
	#include "sljitNativeMIPS_common.c"
#endif

#if !defined(SLJIT_CONFIG_MIPS_32)
struct sljit_jump* sljit_emit_cmp(struct sljit_compiler *compiler, int type,
	int src1, sljit_w src1w,
	int src2, sljit_w src2w)
{
	// Default compare for most architectures
	int flags, tmp_src, condition;
	sljit_w tmp_srcw;
#ifdef SLJIT_VERBOSE
	FILE* verbose;
	struct sljit_jump* jump;
#endif

	check_sljit_emit_cmp(compiler, type, src1, src1w, src2, src2w);

	condition = type & 0xff;
	if (SLJIT_UNLIKELY((src1 & SLJIT_IMM) && !(src2 & SLJIT_IMM))) {
		// Immediate is prefered as second argument by most architectures
		switch (condition) {
		case SLJIT_C_LESS:
			condition = SLJIT_C_GREATER;
			break;
		case SLJIT_C_NOT_LESS:
			condition = SLJIT_C_NOT_GREATER;
			break;
		case SLJIT_C_GREATER:
			condition = SLJIT_C_LESS;
			break;
		case SLJIT_C_NOT_GREATER:
			condition = SLJIT_C_NOT_LESS;
			break;
		case SLJIT_C_SIG_LESS:
			condition = SLJIT_C_SIG_GREATER;
			break;
		case SLJIT_C_SIG_NOT_LESS:
			condition = SLJIT_C_SIG_NOT_GREATER;
			break;
		case SLJIT_C_SIG_GREATER:
			condition = SLJIT_C_SIG_LESS;
			break;
		case SLJIT_C_SIG_NOT_GREATER:
			condition = SLJIT_C_SIG_NOT_LESS;
			break;
		}
		type = condition | (type & (SLJIT_INT_OP | SLJIT_REWRITABLE_JUMP));
		tmp_src = src1;
		src1 = src2;
		src2 = tmp_src;
		tmp_srcw = src1w;
		src1w = src2w;
		src2w = tmp_srcw;
	}

	if (condition <= SLJIT_C_NOT_ZERO)
		flags = SLJIT_SET_E;
	else if (condition <= SLJIT_C_NOT_GREATER)
		flags = SLJIT_SET_U;
	else
		flags = SLJIT_SET_S;

#ifdef SLJIT_VERBOSE
	if (SLJIT_UNLIKELY(!!compiler->verbose)) {
		verbose = compiler->verbose;
		compiler->verbose = NULL;
		if (sljit_emit_op2(compiler, SLJIT_SUB | flags | (type & SLJIT_INT_OP),
			SLJIT_UNUSED, 0, src1, src1w, src2, src2w)) {
			compiler->verbose = verbose;
			return NULL;
		}
		jump = sljit_emit_jump(compiler, condition | (type & SLJIT_REWRITABLE_JUMP));
		compiler->verbose = verbose;
		return jump;
	}
#endif

	PTR_FAIL_IF(sljit_emit_op2(compiler, SLJIT_SUB | flags | (type & SLJIT_INT_OP),
		SLJIT_UNUSED, 0, src1, src1w, src2, src2w));
	return sljit_emit_jump(compiler, condition | (type & SLJIT_REWRITABLE_JUMP));
}
#endif

#else /* SLJIT_CONFIG_UNSUPPORTED */

// Empty function bodies for those machines, which are not (yet) supported

struct sljit_compiler* sljit_create_compiler(void)
{
	SLJIT_ASSERT_STOP();
	return NULL;
}

void sljit_free_compiler(struct sljit_compiler *compiler)
{
	(void)compiler;
	SLJIT_ASSERT_STOP();
}

#ifdef SLJIT_VERBOSE
void sljit_compiler_verbose(struct sljit_compiler *compiler, FILE* verbose)
{
	(void)compiler;
	(void)verbose;
	SLJIT_ASSERT_STOP();
}
#endif

void* sljit_generate_code(struct sljit_compiler *compiler)
{
	(void)compiler;
	SLJIT_ASSERT_STOP();
	return NULL;
}

void sljit_free_code(void* code)
{
	(void)code;
	SLJIT_ASSERT_STOP();
}

int sljit_emit_enter(struct sljit_compiler *compiler, int args, int temporaries, int generals, int local_size)
{
	(void)compiler;
	(void)args;
	(void)temporaries;
	(void)generals;
	(void)local_size;
	SLJIT_ASSERT_STOP();
	return SLJIT_ERR_UNSUPPORTED;
}

void sljit_fake_enter(struct sljit_compiler *compiler, int args, int temporaries, int generals, int local_size)
{
	(void)compiler;
	(void)args;
	(void)temporaries;
	(void)generals;
	(void)local_size;
	SLJIT_ASSERT_STOP();
}

int sljit_emit_return(struct sljit_compiler *compiler, int src, sljit_w srcw)
{
	(void)compiler;
	(void)src;
	(void)srcw;
	SLJIT_ASSERT_STOP();
	return SLJIT_ERR_UNSUPPORTED;
}

int sljit_emit_op1(struct sljit_compiler *compiler, int op,
	int dst, sljit_w dstw,
	int src, sljit_w srcw)
{
	(void)compiler;
	(void)op;
	(void)dst;
	(void)dstw;
	(void)src;
	(void)srcw;
	SLJIT_ASSERT_STOP();
	return SLJIT_ERR_UNSUPPORTED;
}

int sljit_emit_op2(struct sljit_compiler *compiler, int op,
	int dst, sljit_w dstw,
	int src1, sljit_w src1w,
	int src2, sljit_w src2w)
{
	(void)compiler;
	(void)op;
	(void)dst;
	(void)dstw;
	(void)src1;
	(void)src1w;
	(void)src2;
	(void)src2w;
	SLJIT_ASSERT_STOP();
	return SLJIT_ERR_UNSUPPORTED;
}

int sljit_is_fpu_available(void)
{
	SLJIT_ASSERT_STOP();
	return 0;
}

int sljit_emit_fop1(struct sljit_compiler *compiler, int op,
	int dst, sljit_w dstw,
	int src, sljit_w srcw)
{
	(void)compiler;
	(void)op;
	(void)dst;
	(void)dstw;
	(void)src;
	(void)srcw;
	SLJIT_ASSERT_STOP();
	return SLJIT_ERR_UNSUPPORTED;
}

int sljit_emit_fop2(struct sljit_compiler *compiler, int op,
	int dst, sljit_w dstw,
	int src1, sljit_w src1w,
	int src2, sljit_w src2w)
{
	(void)compiler;
	(void)op;
	(void)dst;
	(void)dstw;
	(void)src1;
	(void)src1w;
	(void)src2;
	(void)src2w;
	SLJIT_ASSERT_STOP();
	return SLJIT_ERR_UNSUPPORTED;
}

struct sljit_label* sljit_emit_label(struct sljit_compiler *compiler)
{
	(void)compiler;
	SLJIT_ASSERT_STOP();
	return NULL;
}

struct sljit_jump* sljit_emit_jump(struct sljit_compiler *compiler, int type)
{
	(void)compiler;
	(void)type;
	SLJIT_ASSERT_STOP();
	return NULL;
}

void sljit_set_label(struct sljit_jump *jump, struct sljit_label* label)
{
	(void)jump;
	(void)label;
	SLJIT_ASSERT_STOP();
}

void sljit_set_target(struct sljit_jump *jump, sljit_uw target)
{
	(void)jump;
	(void)target;
	SLJIT_ASSERT_STOP();
}

int sljit_emit_ijump(struct sljit_compiler *compiler, int type, int src, sljit_w srcw)
{
	(void)compiler;
	(void)type;
	(void)src;
	(void)srcw;
	SLJIT_ASSERT_STOP();
	return SLJIT_ERR_UNSUPPORTED;
}

int sljit_emit_cond_set(struct sljit_compiler *compiler, int dst, sljit_w dstw, int type)
{
	(void)compiler;
	(void)dst;
	(void)dstw;
	(void)type;
	SLJIT_ASSERT_STOP();
	return SLJIT_ERR_UNSUPPORTED;
}

struct sljit_const* sljit_emit_const(struct sljit_compiler *compiler, int dst, sljit_w dstw, sljit_w initval)
{
	(void)compiler;
	(void)dst;
	(void)dstw;
	(void)initval;
	SLJIT_ASSERT_STOP();
	return NULL;
}

void sljit_set_jump_addr(sljit_uw addr, sljit_uw new_addr)
{
	(void)addr;
	(void)new_addr;
	SLJIT_ASSERT_STOP();
}

void sljit_set_const(sljit_uw addr, sljit_w new_constant)
{
	(void)addr;
	(void)new_constant;
	SLJIT_ASSERT_STOP();
}

#endif
