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

// RR form instructions
#define SLJIT_S390X_RR(name, pattern) \
SLJIT_S390X_INSTRUCTION(name, sljit_gpr dst, sljit_gpr src) \
{ \
	return pattern | ((dst&0xf)<<4) | (src&0xf); \
}

// ADD
SLJIT_S390X_RR(ar,   0x1a00)

// ADD LOGICAL
SLJIT_S390X_RR(alr,  0x1e00)

// AND
SLJIT_S390X_RR(nr,   0x1400)

// BRANCH AND LINK
SLJIT_S390X_RR(balr, 0x0500)

// BRANCH AND SAVE
SLJIT_S390X_RR(basr, 0x0d00)

// BRANCH ON CONDITION
SLJIT_S390X_RR(bcr,  0x0700) // TODO(mundaym): type for mask?

// BRANCH AND COUNT
SLJIT_S390X_RR(bctr, 0x0600)

// COMPARE
SLJIT_S390X_RR(cr,   0x1900)

// COMPARE LOGICAL
SLJIT_S390X_RR(clr,  0x1500)

// DIVIDE
SLJIT_S390X_RR(dr,   0x1d00)

// EXCLUSIVE OR
SLJIT_S390X_RR(xr,   0x1700)

// LOAD
SLJIT_S390X_RR(lr,   0x1800)

// LOAD AND TEST
SLJIT_S390X_RR(ltr,  0x1200)

// LOAD COMPLEMENT
SLJIT_S390X_RR(lcr,  0x1300)

// LOAD NEGATIVE
SLJIT_S390X_RR(lnr,  0x1100)

// LOAD POSITIVE
SLJIT_S390X_RR(lpr,  0x1000)

// MULTIPLY
SLJIT_S390X_RR(mr,   0x1c00)

// OR
SLJIT_S390X_RR(or,   0x1600)

// SUBTRACT
SLJIT_S390X_RR(sr,   0x1b00)

// SUBTRACT LOGICAL
SLJIT_S390X_RR(slr,  0x1f00)

#undef SLJIT_S390X_RR

// RRE form instructions
#define SLJIT_S390X_RRE(name, pattern) \
SLJIT_S390X_INSTRUCTION(name, sljit_gpr dst, sljit_gpr src) \
{ \
	return pattern | ((dst&0xf)<<4) | (src&0xf); \
}

// ADD
SLJIT_S390X_RRE(agr,   0xb9080000)
SLJIT_S390X_RRE(agfr,  0xb9180000)

// ADD LOGICAL
SLJIT_S390X_RRE(algr,  0xb90a0000)
SLJIT_S390X_RRE(algfr, 0xb91a0000)

// ADD LOGICAL WITH CARRY
SLJIT_S390X_RRE(alcr,  0xb9980000)
SLJIT_S390X_RRE(alcgr, 0xb9880000)

// AND
SLJIT_S390X_RRE(ngr,   0xb9800000)

// BRANCH ON COUNT
SLJIT_S390X_RRE(bctgr, 0xb9460000)

// COMPARE
SLJIT_S390X_RRE(cgr,   0xb9200000)
SLJIT_S390X_RRE(cgfr,  0xb9300000)

// COMPARE LOGICAL
SLJIT_S390X_RRE(clgr,  0xb9210000)
SLJIT_S390X_RRE(clgfr, 0xb9310000)

// DIVIDE LOGICAL
SLJIT_S390X_RRE(dlr,   0xb9970000)
SLJIT_S390X_RRE(dlgr,  0xb9870000)

// DIVIDE SINGLE
SLJIT_S390X_RRE(dsgr,  0xb90d0000)
SLJIT_S390X_RRE(dsgfr, 0xb91d0000)

// EXCLUSIVE OR
SLJIT_S390X_RRE(xgr,   0xb9820000)

// LOAD
SLJIT_S390X_RRE(lgr,   0xb9040000)
SLJIT_S390X_RRE(lgfr,  0xb9140000)

// LOAD AND TEST
SLJIT_S390X_RRE(ltgr,  0xb9020000)
SLJIT_S390X_RRE(ltgfr, 0xb9120000)

// LOAD BYTE
SLJIT_S390X_RRE(lbr,   0xb9260000)
SLJIT_S390X_RRE(lgbr,  0xb9060000)

// LOAD COMPLEMENT
SLJIT_S390X_RRE(lcgr,  0xb9030000)
SLJIT_S390X_RRE(lcgfr, 0xb9130000)

// LOAD HALFWORD
SLJIT_S390X_RRE(lhr,   0xb9270000)
SLJIT_S390X_RRE(lghr,  0xb9070000)

// LOAD LOGICAL
SLJIT_S390X_RRE(llgfr, 0xb9160000)

// LOAD LOGICAL CHARACTER
SLJIT_S390X_RRE(llcr,  0xb9940000)
SLJIT_S390X_RRE(llgcr, 0xb9840000)

// LOAD LOGICAL HALFWORD
SLJIT_S390X_RRE(llhr,  0xb9950000)
SLJIT_S390X_RRE(llghr, 0xb9850000)

// LOAD NEGATIVE
SLJIT_S390X_RRE(lngr,  0xb9010000)
SLJIT_S390X_RRE(lngfr, 0xb9110000)

// LOAD POSITIVE
SLJIT_S390X_RRE(lpgr,  0xb9900000)
SLJIT_S390X_RRE(lpgfr, 0xb9100000)

// LOAD REVERSED
SLJIT_S390X_RRE(lrvr,  0xb91f0000)
SLJIT_S390X_RRE(lrvgr, 0xb90f0000)

// MULTIPLY LOGICAL
SLJIT_S390X_RRE(mlr,   0xb9960000)
SLJIT_S390X_RRE(mlgr,  0xb9860000)

// MULTIPLY SINGLE
SLJIT_S390X_RRE(msr,   0xb2520000)
SLJIT_S390X_RRE(msgr,  0xb90c0000)
SLJIT_S390X_RRE(msgfr, 0xb91c0000)

// OR
SLJIT_S390X_RRE(ogr,   0xb9810000)

// SUBTRACT
SLJIT_S390X_RRE(sgr,   0xb9090000)
SLJIT_S390X_RRE(sgfr,  0xb9190000)

// SUBTRACT LOGICAL
SLJIT_S390X_RRE(slgr,  0xb90b0000)
SLJIT_S390X_RRE(slgfr, 0xb91b0000)

// SUBTRACT LOGICAL WITH BORROW
SLJIT_S390X_RRE(slbr,  0xb9990000)
SLJIT_S390X_RRE(slbgr, 0xb9890000)

#undef SLJIT_S390X_RRE

// RI-a form instructions
#define SLJIT_S390X_RIA(name, pattern, imm_type) \
SLJIT_S390X_INSTRUCTION(name, sljit_gpr reg, imm_type imm) \
{ \
	return pattern | ((reg&0xf) << 20) | (imm&0xffff); \
}

// ADD HALFWORD IMMEDIATE
SLJIT_S390X_RIA(ahi,   0xa70a0000, sljit_s16)
SLJIT_S390X_RIA(aghi,  0xa70b0000, sljit_s16)

// AND IMMEDIATE
SLJIT_S390X_RIA(nihh,  0xa5040000, sljit_u16)
SLJIT_S390X_RIA(nihl,  0xa5050000, sljit_u16)
SLJIT_S390X_RIA(nilh,  0xa5060000, sljit_u16)
SLJIT_S390X_RIA(nill,  0xa5070000, sljit_u16)

// COMPARE HALFWORD IMMEDIATE
SLJIT_S390X_RIA(chi,   0xa70e0000, sljit_s16)
SLJIT_S390X_RIA(cghi,  0xa70f0000, sljit_s16)

// INSERT IMMEDIATE
SLJIT_S390X_RIA(iilh,  0xa5020000, sljit_u16)
SLJIT_S390X_RIA(iill,  0xa5030000, sljit_u16)

// LOAD HALFWORD IMMEDIATE
SLJIT_S390X_RIA(lhi,   0xa7080000, sljit_s16)
SLJIT_S390X_RIA(lghi,  0xa7090000, sljit_s16)

// LOAD LOGICAL IMMEDIATE
SLJIT_S390X_RIA(llihh, 0xa50c0000, sljit_u16)
SLJIT_S390X_RIA(llihl, 0xa50d0000, sljit_u16)
SLJIT_S390X_RIA(llilh, 0xa50e0000, sljit_u16)
SLJIT_S390X_RIA(llill, 0xa50f0000, sljit_u16)

// MULTIPLY HALFWORD IMMEDIATE
SLJIT_S390X_RIA(mhi,   0xa70c0000, sljit_s16)
SLJIT_S390X_RIA(mghi,  0xa70d0000, sljit_s16)

// OR IMMEDIATE
SLJIT_S390X_RIA(oihh,  0xa5080000, sljit_u16)
SLJIT_S390X_RIA(oihl,  0xa5090000, sljit_u16)
SLJIT_S390X_RIA(oilh,  0xa50a0000, sljit_u16)
SLJIT_S390X_RIA(oill,  0xa50b0000, sljit_u16)

// TEST UNDER MASK
SLJIT_S390X_RIA(tmhh,  0xa7020000, sljit_u16)
SLJIT_S390X_RIA(tmhl,  0xa7030000, sljit_u16)
SLJIT_S390X_RIA(tmlh,  0xa7000000, sljit_u16)
SLJIT_S390X_RIA(tmll,  0xa7010000, sljit_u16)

#undef SLJIT_S390X_RIA

// RIL-a form instructions (requires extended immediate facility)
#define SLJIT_S390X_RILA(name, pattern, imm_type) \
SLJIT_S390X_INSTRUCTION(name, sljit_gpr reg, imm_type imm) \
{ \
	return pattern | ((sljit_ins)(reg&0xf) << 36) | (imm&0xffffffff); \
}

// ADD IMMEDIATE
SLJIT_S390X_RILA(afi,   0xc20900000000, sljit_s32)
SLJIT_S390X_RILA(agfi,  0xc20800000000, sljit_s32)

// ADD LOGICAL IMMEDIATE
SLJIT_S390X_RILA(alfi,  0xc20b00000000, sljit_u32)
SLJIT_S390X_RILA(algfi, 0xc20a00000000, sljit_u32)

// AND IMMEDIATE
SLJIT_S390X_RILA(nihf,  0xc00a00000000, sljit_u32)
SLJIT_S390X_RILA(nilf,  0xc00b00000000, sljit_u32)

// COMPARE IMMEDIATE
SLJIT_S390X_RILA(cfi,   0xc20d00000000, sljit_s32)
SLJIT_S390X_RILA(cgfi,  0xc20c00000000, sljit_s32)

// COMPARE LOGICAL IMMEDIATE
SLJIT_S390X_RILA(clfi,  0xc20f00000000, sljit_u32)
SLJIT_S390X_RILA(clgfi, 0xc20e00000000, sljit_u32)

// EXCLUSIVE OR IMMEDIATE
SLJIT_S390X_RILA(xihf,  0xc00600000000, sljit_u32)
SLJIT_S390X_RILA(xilf,  0xc00700000000, sljit_u32)

// INSERT IMMEDIATE
SLJIT_S390X_RILA(iihf,  0xc00800000000, sljit_u32)
SLJIT_S390X_RILA(iilf,  0xc00900000000, sljit_u32)

// LOAD IMMEDIATE
SLJIT_S390X_RILA(lgfi,  0xc00100000000, sljit_s32)

// LOAD LOGICAL IMMEDIATE
SLJIT_S390X_RILA(llihf, 0xc00e00000000, sljit_u32)
SLJIT_S390X_RILA(llilf, 0xc00f00000000, sljit_u32)

// MULTIPLY SINGLE IMMEDIATE
SLJIT_S390X_RILA(msfi,  0xc20100000000, sljit_s32)
SLJIT_S390X_RILA(msgfi, 0xc20000000000, sljit_s32)

// OR IMMEDIATE
SLJIT_S390X_RILA(oihf,  0xc00c00000000, sljit_u32)
SLJIT_S390X_RILA(oilf,  0xc00d00000000, sljit_u32)

// SUBTRACT LOGICAL IMMEDIATE
SLJIT_S390X_RILA(slfi,  0xc20500000000, sljit_u32)
SLJIT_S390X_RILA(slgfi, 0xc20400000000, sljit_u32)

#undef SLJIT_S390X_RILA

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

/* Helper functions for instructions. */

static int have_eimm() { return 1; } // TODO(mundaym): make conditional

// load 64-bit immediate into register without clobbering flags
static sljit_s32 push_load_imm_inst(struct sljit_compiler *compiler, sljit_gpr target, sljit_sw v)
{
	// 4 byte instructions
	if (v == (sljit_sw)((sljit_s16)v)) {
		return push_inst(compiler, lghi(target, (sljit_s16)v));
	}
	if (v == (v & 0x000000000000ffff)) {
		return push_inst(compiler, llill(target, (sljit_u16)(v)));
	}
	if (v == (v & 0x00000000ffff0000)) {
		return push_inst(compiler, llilh(target, (sljit_u16)(v>>16)));
	}
	if (v == (v & 0x0000ffff00000000)) {
		return push_inst(compiler, llihl(target, (sljit_u16)(v>>32)));
	}
	if (v == (v & 0xffff000000000000)) {
		return push_inst(compiler, llihh(target, (sljit_u16)(v>>48)));
	}

	// 6 byte instructions (requires extended immediate facility)
	if (have_eimm()) {
		if (v == (sljit_sw)((sljit_s32)v)) {
			return push_inst(compiler, lghi(target, (sljit_s32)v));
		}
		if (v == (v & 0x00000000ffffffff)) {
			return push_inst(compiler, llilf(target, (sljit_u32)(v)));
		}
		if (v == (v & 0xffffffff00000000)) {
			return push_inst(compiler, llihf(target, (sljit_u32)(v>>32)));
		}
		FAIL_IF(push_inst(compiler, llilf(target, (sljit_u32)(v))));
		return push_inst(compiler, iihf(target, (sljit_u32)(v>>32)));
	}
	// TODO(mundaym): instruction sequences that don't use extended immediates
	abort();
}

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
	if (local_size != 0) {
		SLJIT_ASSERT(local_size < ((1<<15) - 1));
		FAIL_IF(push_inst(compiler, aghi(r15, -((sljit_s16)local_size))));
	}

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
		if (FAST_IS_REG(dst) && FAST_IS_REG(src)) {
			// TODO(mundaym): sign/zero extension
			return push_inst(compiler, lgr(gpr(dst), gpr(src)));
		}
		if (FAST_IS_REG(dst) && (src & SLJIT_IMM)) {
			return push_load_imm_inst(compiler, gpr(dst), srcw);
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
