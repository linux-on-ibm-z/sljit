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

const sljit_gpr tmp0 = 0; // r0
const sljit_gpr tmp1 = 1; // r1

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

/* Helper functions for instructions. */

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

// extended-immediate facility
static int have_eimm() { return 1; }  // TODO(mundaym): make conditional

// long-displacement facility
static int have_ldisp() { return 1; } // TODO(mundaym): make conditional

// distinct-operands facility
static int have_distop() { return 1; } // TODO(mundaym): make conditional

// load/store-on-condition 1 facility
static int have_lscond1() { return 1; } // TODO(mundaym): make conditional

// load/store-on-condition 2 facility
static int have_lscond2() { return 1; } // TODO(mundaym): make conditional

#define CHECK_SIGNED(v, bitlen) \
	((v) == (((v) << (sizeof(v)*8 - bitlen)) >> (sizeof(v)*8 - bitlen)))
static int is_s16(sljit_sw d) { return CHECK_SIGNED(d, 16); }
static int is_s20(sljit_sw d) { return CHECK_SIGNED(d, 20); }
static int is_s32(sljit_sw d) { return CHECK_SIGNED(d, 32); }
#undef CHECK_SIGNED

static int is_u12(sljit_sw d) { return 0 <= d && d <= 0x00000fffL; }
static int is_u16(sljit_sw d) { return 0 <= d && d <= 0x0000ffffL; }
static int is_u32(sljit_sw d) { return 0 <= d && d <= 0xffffffffL; }

static sljit_uw disp_s20(sljit_s32 d)
{
	SLJIT_ASSERT(is_s20(d));
	sljit_uw dh = (d >> 12) & 0xff;
	sljit_uw dl = (d << 8) & 0xfff00;
	return dh | dl;
}

#define SLJIT_S390X_INSTRUCTION(op, ...) \
static sljit_ins op(__VA_ARGS__)


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
	SLJIT_ASSERT(have_eimm()); \
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

// RX-a form instructions
#define SLJIT_S390X_RXA(name, pattern) \
SLJIT_S390X_INSTRUCTION(name, sljit_gpr r, sljit_u16 d, sljit_gpr x, sljit_gpr b) \
{ \
	SLJIT_ASSERT((d&0xfff) == d); \
	sljit_ins ri = (sljit_ins)(r&0xf) << 20; \
	sljit_ins xi = (sljit_ins)(x&0xf) << 16; \
	sljit_ins bi = (sljit_ins)(b&0xf) << 12; \
	sljit_ins di = (sljit_ins)(d&0xfff); \
	return pattern | ri | xi | bi | di; \
}

// ADD
SLJIT_S390X_RXA(a,   0x5a000000)

// ADD HALFWORD
SLJIT_S390X_RXA(ah,  0x4a000000)

// ADD LOGICAL
SLJIT_S390X_RXA(al,  0x5e000000)

// AND
SLJIT_S390X_RXA(n,   0x54000000)

// COMPARE
SLJIT_S390X_RXA(c,   0x59000000)

// COMPARE HALFWORD
SLJIT_S390X_RXA(ch,  0x49000000)

// COMPARE LOGICAL
SLJIT_S390X_RXA(cl,  0x55000000)

// DIVIDE
SLJIT_S390X_RXA(d,   0x5d000000)

// EXCLUSIVE OR
SLJIT_S390X_RXA(x,   0x57000000)

// INSERT CHARACTER
SLJIT_S390X_RXA(ic,  0x43000000)

// LOAD
SLJIT_S390X_RXA(l,   0x58000000)

// LOAD ADDRESS
SLJIT_S390X_RXA(la,  0x41000000)

// LOAD HALFWORD
SLJIT_S390X_RXA(lh,  0x48000000)

// MULTIPLY
SLJIT_S390X_RXA(m,   0x5c000000)

// MULTIPLY HALFWORD
SLJIT_S390X_RXA(mh,  0x4c000000)

// MULTIPLY SINGLE
SLJIT_S390X_RXA(ms,  0x71000000)

// OR
SLJIT_S390X_RXA(o,   0x56000000)

// STORE
SLJIT_S390X_RXA(st,  0x50000000)

// STORE CHARACTER
SLJIT_S390X_RXA(stc, 0x42000000)

// STORE HALFWORD
SLJIT_S390X_RXA(sth, 0x40000000)

// SUBTRACT
SLJIT_S390X_RXA(s,   0x5b000000)

// SUBTRACT HALFWORD
SLJIT_S390X_RXA(sh,  0x4b000000)

// SUBTRACT LOGICAL
SLJIT_S390X_RXA(sl,  0x5f000000)

#undef SLJIT_S390X_RXA

// RXY-a instructions
#define SLJIT_S390X_RXYA(name, pattern, cond) \
SLJIT_S390X_INSTRUCTION(name, sljit_gpr r, sljit_s32 d, sljit_gpr x, sljit_gpr b) \
{ \
	SLJIT_ASSERT(cond); \
	sljit_ins ri = (sljit_ins)(r&0xf) << 36; \
	sljit_ins xi = (sljit_ins)(x&0xf) << 32; \
	sljit_ins bi = (sljit_ins)(b&0xf) << 28; \
	sljit_ins di = (sljit_ins)disp_s20(d) << 8; \
	return pattern | ri | xi | bi | di; \
}

// ADD
SLJIT_S390X_RXYA(ay,    0xe3000000005a, have_ldisp())
SLJIT_S390X_RXYA(ag,    0xe30000000008, 1)
SLJIT_S390X_RXYA(agf,   0xe30000000018, 1)

// ADD HALFWORD
SLJIT_S390X_RXYA(ahy,   0xe3000000007a, have_ldisp())
SLJIT_S390X_RXYA(agh,   0xe30000000038, 0) // TODO(mundaym): misc2?

// ADD LOGICAL
SLJIT_S390X_RXYA(aly,   0xe3000000005e, have_ldisp())
SLJIT_S390X_RXYA(alg,   0xe3000000000a, 1)
SLJIT_S390X_RXYA(algf,  0xe3000000001a, 1)

// ADD LOGICAL WITH CARRY
SLJIT_S390X_RXYA(alc,   0xe30000000098, 1)
SLJIT_S390X_RXYA(alcg,  0xe30000000088, 1)

// AND
SLJIT_S390X_RXYA(ny,    0xe30000000054, have_ldisp())
SLJIT_S390X_RXYA(ng,    0xe30000000080, 1)

// COMPARE
SLJIT_S390X_RXYA(cy,    0xe30000000059, have_ldisp())
SLJIT_S390X_RXYA(cg,    0xe30000000020, 1)
SLJIT_S390X_RXYA(cgf,   0xe30000000030, 1)

// COMPARE HALFWORD
SLJIT_S390X_RXYA(chy,   0xe30000000079, have_ldisp())
SLJIT_S390X_RXYA(cgh,   0xe30000000034, 0) // TODO(mundaym): general1?

// COMPARE LOGICAL
SLJIT_S390X_RXYA(cly,   0xe30000000055, have_ldisp())
SLJIT_S390X_RXYA(clg,   0xe30000000021, 1)
SLJIT_S390X_RXYA(clgf,  0xe30000000031, 1)

// DIVIDE LOGICAL
SLJIT_S390X_RXYA(dl,    0xe30000000097, 1)
SLJIT_S390X_RXYA(dlg,   0xe30000000087, 1)

// DIVIDE SINGLE
SLJIT_S390X_RXYA(dsg,   0xe3000000000d, 1)
SLJIT_S390X_RXYA(dsgf,  0xe3000000001d, 1)

// EXCLUSIVE OR
SLJIT_S390X_RXYA(xy,    0xe30000000057, have_ldisp())
SLJIT_S390X_RXYA(xg,    0xe30000000082, 1)

// INSERT CHARACTER
SLJIT_S390X_RXYA(icy,   0xe30000000073, have_ldisp())

// LOAD
SLJIT_S390X_RXYA(ly,    0xe30000000058, have_ldisp())
SLJIT_S390X_RXYA(lg,    0xe30000000004, 1)
SLJIT_S390X_RXYA(lgf,   0xe30000000014, 1)

// LOAD ADDRESS
SLJIT_S390X_RXYA(lay,   0xe30000000071, have_ldisp())

// LOAD AND TEST
SLJIT_S390X_RXYA(lt,    0xe30000000012, have_eimm())
SLJIT_S390X_RXYA(ltg,   0xe30000000002, have_eimm())
SLJIT_S390X_RXYA(ltgf,  0xe30000000032, 0) // TODO(mundaym): general1?

// LOAD BYTE
SLJIT_S390X_RXYA(lb,    0xe30000000076, have_ldisp())
SLJIT_S390X_RXYA(lgb,   0xe30000000077, have_ldisp())

// LOAD HALFWORD
SLJIT_S390X_RXYA(lhy,   0xe30000000078, have_ldisp())
SLJIT_S390X_RXYA(lgh,   0xe30000000015, 1)

// LOAD LOGICAL
SLJIT_S390X_RXYA(llgf,  0xe30000000016, 1)

// LOAD LOGICAL CHARACTER
SLJIT_S390X_RXYA(llc,   0xe30000000094, have_eimm())
SLJIT_S390X_RXYA(llgc,  0xe30000000090, 1)

// LOAD LOGICAL HALFWORD
SLJIT_S390X_RXYA(llh,   0xe30000000095, have_eimm())
SLJIT_S390X_RXYA(llgh,  0xe30000000091, 1)

// LOAD REVERSED
SLJIT_S390X_RXYA(lrvh,  0xe3000000001f, 1)
SLJIT_S390X_RXYA(lrv,   0xe3000000001e, 1)
SLJIT_S390X_RXYA(lrvg,  0xe3000000000f, 1)

// MULTIPLY
SLJIT_S390X_RXYA(mfy,   0xe3000000005c, 0) // TODO(mundaym): general1?
SLJIT_S390X_RXYA(mg,    0xe30000000084, 0) // TODO(mundaym): misc2?

// MULTIPLY HALFWORD
SLJIT_S390X_RXYA(mhy,   0xe3000000007c, 0) // TODO(mundaym): general1?
SLJIT_S390X_RXYA(mgh,   0xe3000000003c, 0) // TODO(mundaym): misc2?

// MULTIPLY LOGICAL
SLJIT_S390X_RXYA(ml,    0xe30000000096, 1)
SLJIT_S390X_RXYA(mlg,   0xe30000000086, 1)

// MULTIPLY SINGLE
SLJIT_S390X_RXYA(msc,   0xe30000000053, 0) // TODO(mundaym): misc2?
SLJIT_S390X_RXYA(msy,   0xe30000000051, have_ldisp())
SLJIT_S390X_RXYA(msg,   0xe3000000000c, 1)
SLJIT_S390X_RXYA(msgc,  0xe30000000083, 0) // TODO(mundaym): misc2?
SLJIT_S390X_RXYA(msgf,  0xe3000000001c, 0) // TODO(mundaym): misc2?

// OR
SLJIT_S390X_RXYA(oy,    0xe30000000056, have_ldisp())
SLJIT_S390X_RXYA(og,    0xe30000000081, 1)

// STORE
SLJIT_S390X_RXYA(sty,   0xe30000000050, have_ldisp())
SLJIT_S390X_RXYA(stg,   0xe30000000024, 1)

// STORE CHARACTER
SLJIT_S390X_RXYA(stcy,  0xe30000000072, have_ldisp())

// STORE HALFWORD
SLJIT_S390X_RXYA(sthy,  0xe30000000070, have_ldisp())

// STORE REVERSED
SLJIT_S390X_RXYA(strvh, 0xe3000000003f, 1)
SLJIT_S390X_RXYA(strv,  0xe3000000003e, 1)
SLJIT_S390X_RXYA(strvg, 0xe3000000002f, 1)

// SUBTRACT
SLJIT_S390X_RXYA(sy,    0xe3000000005b, have_ldisp())
SLJIT_S390X_RXYA(sg,    0xe30000000009, 1)
SLJIT_S390X_RXYA(sgf,   0xe30000000019, 1)

// SUBTRACT HALFWORD
SLJIT_S390X_RXYA(shy,   0xe3000000007b, have_ldisp())
SLJIT_S390X_RXYA(sgh,   0xe30000000039, 0) // TODO(mundaym): misc2?

// SUBTRACT LOGICAL
SLJIT_S390X_RXYA(sly,   0xe3000000005f, have_ldisp())
SLJIT_S390X_RXYA(slg,   0xe3000000000b, 1)
SLJIT_S390X_RXYA(slgf,  0xe3000000001b, 1)

// SUBTRACT LOGICAL WITH BORROW
SLJIT_S390X_RXYA(slb,   0xe30000000099, 1)
SLJIT_S390X_RXYA(slbg,  0xe30000000089, 1)

#undef SLJIT_S390X_RXYA

// RS-a instructions
#define SLJIT_S390X_RSA(name, pattern) \
SLJIT_S390X_INSTRUCTION(name, sljit_gpr reg, sljit_sw d, sljit_gpr b) \
{ \
	sljit_ins r1 = (sljit_ins)(reg&0xf) << 20; \
	sljit_ins b2 = (sljit_ins)(b&0xf) << 12; \
	sljit_ins d2 = (sljit_ins)(d&0xfff); \
	return pattern | r1 | b2 | d2; \
}

// SHIFT LEFT SINGLE LOGICAL
SLJIT_S390X_RSA(sll, 0x89000000)

// SHIFT RIGHT SINGLE
SLJIT_S390X_RSA(sra, 0x8a000000)

// SHIFT RIGHT SINGLE LOGICAL
SLJIT_S390X_RSA(srl, 0x88000000)

#undef SLJIT_S390X_RSA

// RSY-a instructions
#define SLJIT_S390X_RSYA(name, pattern, cond) \
SLJIT_S390X_INSTRUCTION(name, sljit_gpr dst, sljit_gpr src, sljit_sw d, sljit_gpr b) \
{ \
	SLJIT_ASSERT(cond); \
	sljit_ins r1 = (sljit_ins)(dst&0xf) << 36; \
	sljit_ins r3 = (sljit_ins)(src&0xf) << 32; \
	sljit_ins b2 = (sljit_ins)(b&0xf) << 28; \
	sljit_ins d2 = (sljit_ins)disp_s20(d) << 8; \
	return pattern | r1 | r3 | b2 | d2; \
}

// LOAD MULTIPLE
SLJIT_S390X_RSYA(lmg,   0xeb0000000004, 1)

// SHIFT LEFT LOGICAL
SLJIT_S390X_RSYA(sllg,  0xeb000000000d, 1)

// SHIFT RIGHT SINGLE
SLJIT_S390X_RSYA(srag,  0xeb000000000a, 1)

// SHIFT RIGHT SINGLE LOGICAL
SLJIT_S390X_RSYA(srlg,  0xeb000000000c, 1)

// STORE MULTIPLE
SLJIT_S390X_RSYA(stmg,  0xeb0000000024, 1)

#undef SLJIT_S390X_RSYA

// RIE-g instructions (require load/store-on-condition 2 facility)
#define SLJIT_S390X_RIEG(name, pattern) \
SLJIT_S390X_INSTRUCTION(name, sljit_gpr reg, sljit_sw imm, sljit_uw mask) \
{ \
	SLJIT_ASSERT(have_lscond2()); \
	sljit_ins r1 = (sljit_ins)(reg&0xf) << 36; \
	sljit_ins m3 = (sljit_ins)(mask&0xf) << 32; \
	sljit_ins i2 = (sljit_ins)(imm&0xffffL) << 16; \
	return pattern | r1 | m3 | i2; \
}

// LOAD HALFWORD IMMEDIATE ON CONDITION
SLJIT_S390X_RIEG(lochi,  0xec0000000042)
SLJIT_S390X_RIEG(locghi, 0xec0000000046)

#undef SLJIT_S390X_RIEG

SLJIT_S390X_INSTRUCTION(br, sljit_gpr target)
{
	return 0x07f0 | target;
}

SLJIT_S390X_INSTRUCTION(flogr, sljit_gpr dst, sljit_gpr src)
{
	SLJIT_ASSERT(have_eimm());
	sljit_ins r1 = ((sljit_ins)(dst)&0xf) << 8;
	sljit_ins r2 = ((sljit_ins)(src)&0xf);
	return 0xb9830000 | r1 | r2;
}

#undef SLJIT_S390X_INSTRUCTION

// load 64-bit immediate into register without clobbering flags
static sljit_s32 push_load_imm_inst(struct sljit_compiler *compiler, sljit_gpr target, sljit_sw v)
{
	// 4 byte instructions
	if (v == ((v << 48)>>48)) {
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
		if (v == ((v << 32)>>32)) {
			return push_inst(compiler, lgfi(target, (sljit_s32)v));
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

struct addr {
	sljit_gpr base;
	sljit_gpr index;
	sljit_sw  offset;
};

// transform memory operand into D(X,B) form with a signed 20-bit offset
static sljit_s32 make_addr_bxy(
	struct sljit_compiler *compiler,
	struct addr *addr,
	sljit_s32 mem, sljit_sw off,
	sljit_gpr tmp /* clobbered, must not be R0 */)
{
	SLJIT_ASSERT(tmp != r0);
	sljit_gpr base = r0;
	if (mem & REG_MASK) {
		base = gpr(mem & REG_MASK);
	}
	sljit_gpr index = r0;
	if (mem & OFFS_REG_MASK) {
		index = gpr(OFFS_REG(mem));
		if (off != 0) {
			// shift and put the result into tmp
			SLJIT_ASSERT(0 <= off && off < 64);
			FAIL_IF(push_inst(compiler, sllg(tmp, index, off, 0)));
			index = tmp;
			off = 0; // clear offset
		}
	} else if (!is_s20(off)) {
		FAIL_IF(push_load_imm_inst(compiler, tmp, off));
		index = tmp;
		off = 0; // clear offset
	}
	SLJIT_ASSERT(base == r0 || base != index);
	*addr = (struct addr) {
		.base = base,
		.index = index,
		.offset = off
	};
	return SLJIT_SUCCESS;
}

// transform memory operand into D(X,B) form with an unsigned 12-bit offset
static sljit_s32 make_addr_bx(
	struct sljit_compiler *compiler,
	struct addr *addr,
	sljit_s32 mem, sljit_sw off,
	sljit_gpr tmp /* clobbered, must not be R0 */)
{
	SLJIT_ASSERT(tmp != r0);
	sljit_gpr base = r0;
	if (mem & REG_MASK) {
		base = gpr(mem & REG_MASK);
	}
	sljit_gpr index = r0;
	if (mem & OFFS_REG_MASK) {
		index = gpr(OFFS_REG(mem));
		if (off != 0) {
			// shift and put the result into tmp
			SLJIT_ASSERT(0 <= off && off < 64);
			FAIL_IF(push_inst(compiler, sllg(tmp, index, off, 0)));
			index = tmp;
			off = 0; // clear offset
		}
	} else if (!is_u12(off)) {
		FAIL_IF(push_load_imm_inst(compiler, tmp, off));
		index = tmp;
		off = 0; // clear offset
	}
	SLJIT_ASSERT(base == r0 || base != index);
	*addr = (struct addr) {
		.base = base,
		.index = index,
		.offset = off
	};
	return SLJIT_SUCCESS;
}

static sljit_s32 load_word(struct sljit_compiler *compiler, sljit_gpr dst,
		sljit_s32 src, sljit_sw srcw,
		sljit_gpr tmp /* clobbered */, sljit_s32 is_32bit)
{
	SLJIT_ASSERT(src & SLJIT_MEM);
	struct addr addr;
	if (have_ldisp() || !is_32bit) {
		FAIL_IF(make_addr_bxy(compiler, &addr, src, srcw, tmp));
	} else {
		FAIL_IF(make_addr_bx(compiler, &addr, src, srcw, tmp));
	}
	sljit_ins ins = 0;
	if (is_32bit) {
		ins = is_u12(addr.offset) ?
			l(dst, addr.offset, addr.index, addr.base) :
			ly(dst, addr.offset, addr.index, addr.base);
	} else {
		ins = lg(dst, addr.offset, addr.index, addr.base);
	}
	return push_inst(compiler, ins);
}

static sljit_s32 store_word(struct sljit_compiler *compiler, sljit_gpr src,
		sljit_s32 dst, sljit_sw dstw,
		sljit_gpr tmp /* clobbered */, sljit_s32 is_32bit)
{
	SLJIT_ASSERT(dst & SLJIT_MEM);
	struct addr addr;
	if (have_ldisp() || !is_32bit) {
		FAIL_IF(make_addr_bxy(compiler, &addr, dst, dstw, tmp));
	} else {
		FAIL_IF(make_addr_bx(compiler, &addr, dst, dstw, tmp));
	}
	sljit_ins ins = 0;
	if (is_32bit) {
		ins = is_u12(addr.offset) ?
			st(src, addr.offset, addr.index, addr.base) :
			sty(src, addr.offset, addr.index, addr.base);
	} else {
		ins = stg(src, addr.offset, addr.index, addr.base);
	}
	return push_inst(compiler, ins);
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
	sljit_s32 flags, mem_flags;
	sljit_s32 op_flags = GET_ALL_FLAGS(op);

	CHECK_ERROR();
	CHECK(check_sljit_emit_op1(compiler, op, dst, dstw, src, srcw));
	//TODO(mundaym): re-enable
	//ADJUST_LOCAL_OFFSET(dst, dstw);
	//ADJUST_LOCAL_OFFSET(src, srcw);

	sljit_s32 opcode = GET_OPCODE(op);
	if ((dst == SLJIT_UNUSED) && !HAS_FLAGS(op)) {
		// TODO(mundaym): implement prefetch?
		return SLJIT_SUCCESS;
	}
	if (opcode >= SLJIT_MOV && opcode <= SLJIT_MOV_P) {
		// LOAD REGISTER
		if (FAST_IS_REG(dst) && FAST_IS_REG(src)) {
			// TODO(mundaym): sign/zero extension
			return push_inst(compiler, lgr(gpr(dst), gpr(src)));
		}
		// LOAD IMMEDIATE
		if (FAST_IS_REG(dst) && (src & SLJIT_IMM)) {
			return push_load_imm_inst(compiler, gpr(dst), srcw);
		}
		// LOAD
		if (FAST_IS_REG(dst) && (src & SLJIT_MEM)) {
			sljit_gpr reg = gpr(dst);
			struct addr mem;
			FAIL_IF(make_addr_bxy(compiler, &mem, src, srcw, tmp1));
			switch (opcode) {
			case SLJIT_MOV_U8:
			case SLJIT_MOV_S8:
				abort(); // TODO(mundaym): implement
			case SLJIT_MOV_U16:
			case SLJIT_MOV_S16:
				abort(); // TODO(mundaym): implement
			case SLJIT_MOV_U32:
			case SLJIT_MOV_S32:
				abort(); // TODO(mundaym): implement
			case SLJIT_MOV_P:
			case SLJIT_MOV:
				return push_inst(compiler,
					lg(reg, mem.offset, mem.index, mem.base));
			default:
				SLJIT_UNREACHABLE();
			}
		}
		// STORE and STORE IMMEDIATE
		if ((dst & SLJIT_MEM) &&
			(FAST_IS_REG(src) || (src & SLJIT_IMM))) {
			sljit_gpr reg = FAST_IS_REG(src) ? gpr(src) : tmp0;
			if (src & SLJIT_IMM) {
				// TODO(mundaym): MOVE IMMEDIATE?
				FAIL_IF(push_load_imm_inst(compiler, reg, srcw));
			}
			struct addr mem;
			FAIL_IF(make_addr_bxy(compiler, &mem, dst, dstw, tmp1));
			switch (opcode) {
			case SLJIT_MOV_U8:
			case SLJIT_MOV_S8:
				abort(); // TODO(mundaym): implement
			case SLJIT_MOV_U16:
			case SLJIT_MOV_S16:
				abort(); // TODO(mundaym): implement
			case SLJIT_MOV_U32:
			case SLJIT_MOV_S32:
				abort(); // TODO(mundaym): implement
			case SLJIT_MOV_P:
			case SLJIT_MOV:
				return push_inst(compiler,
					stg(reg, mem.offset, mem.index, mem.base));
			default:
				SLJIT_UNREACHABLE();
			}
		}
		// MOVE CHARACTERS
		if ((dst & SLJIT_MEM) && (src & SLJIT_MEM)) {
			struct addr mem;
			FAIL_IF(make_addr_bxy(compiler, &mem, src, srcw, tmp1));
			switch (opcode) {
			case SLJIT_MOV_U8:
			case SLJIT_MOV_S8:
				abort(); // TODO(mundaym): implement
			case SLJIT_MOV_U16:
			case SLJIT_MOV_S16:
				abort(); // TODO(mundaym): implement
			case SLJIT_MOV_U32:
			case SLJIT_MOV_S32:
				abort(); // TODO(mundaym): implement
			case SLJIT_MOV_P:
			case SLJIT_MOV:
				FAIL_IF(push_inst(compiler,
					lg(tmp0, mem.offset, mem.index, mem.base)));
				FAIL_IF(make_addr_bxy(compiler, &mem, dst, dstw, tmp1));
				return push_inst(compiler,
					stg(tmp0, mem.offset, mem.index, mem.base));
			default:
				SLJIT_UNREACHABLE();
			}
		}
		abort();
	}

	SLJIT_ASSERT((src & SLJIT_IMM) == 0); // no immediates

	sljit_gpr dst_r = SLOW_IS_REG(dst) ? gpr(REG_MASK & dst) : tmp0;
	sljit_gpr src_r = FAST_IS_REG(src) ? gpr(REG_MASK & src) : tmp0;
	if (src & SLJIT_MEM) {
		FAIL_IF(load_word(compiler, src_r, src, srcw, tmp1, src & SLJIT_I32_OP));
	}

	// TODO(mundaym): optimize loads and stores
	switch (opcode | (op & SLJIT_I32_OP)) {
	case SLJIT_NOT:
		// emulate ~x with x^-1
		FAIL_IF(push_load_imm_inst(compiler, tmp1, -1));
		if (src_r != dst_r) {
			FAIL_IF(push_inst(compiler, lgr(dst_r, src_r)));
		}
		FAIL_IF(push_inst(compiler, xgr(dst_r, tmp1)));
		break;
	case SLJIT_NOT32:
		// emulate ~x with x^-1
		if (have_eimm()) {
			FAIL_IF(push_inst(compiler, xilf(dst_r, -1)));
		} else {
			FAIL_IF(push_load_imm_inst(compiler, tmp1, -1));
			if (src_r != dst_r) {
				FAIL_IF(push_inst(compiler, lr(dst_r, src_r)));
			}
			FAIL_IF(push_inst(compiler, xr(dst_r, tmp1)));
		}
		break;
	case SLJIT_NEG:
		FAIL_IF(push_inst(compiler, lcgr(dst_r, src_r)));
		break;
	case SLJIT_NEG32:
		FAIL_IF(push_inst(compiler, lcr(dst_r, src_r)));
		break;
	case SLJIT_CLZ:
		if (have_eimm()) {
			FAIL_IF(push_inst(compiler, flogr(dst_r, src_r)));
		} else {
			abort(); // TODO(mundaym): no eimm (?)
		}
		break;
	case SLJIT_CLZ32:
		if (have_eimm()) {
			FAIL_IF(push_inst(compiler, sllg(tmp1, src_r, 32, 0)));
			FAIL_IF(push_inst(compiler, iilf(tmp1, 0xffffffff)));
			FAIL_IF(push_inst(compiler, flogr(dst_r, src_r)));
		} else {
			abort(); // TODO(mundaym): no eimm (?)
		}
		break;
	default:
		SLJIT_UNREACHABLE();
	}

	if ((dst != SLJIT_UNUSED) && (dst & SLJIT_MEM)) {
		FAIL_IF(store_word(compiler, dst_r, dst, dstw, tmp1, op & SLJIT_I32_OP));
	}

	return SLJIT_SUCCESS;
}

static int is_commutative(sljit_s32 op)
{
	switch (GET_OPCODE(op)) {
	case SLJIT_ADD:
	case SLJIT_ADDC:
	case SLJIT_MUL:
	case SLJIT_AND:
	case SLJIT_OR:
	case SLJIT_XOR:
		return 1;
	}
	return 0;
}

static int is_shift(sljit_s32 op) {
	sljit_s32 v = GET_OPCODE(op);
	return v == SLJIT_SHL ||
		v == SLJIT_ASHR ||
		v == SLJIT_LSHR
		? 1 : 0;
}

// have instruction for:
//	op dst src imm
// where dst and src are separate registers
static int have_op_3_imm(sljit_s32 op, sljit_sw imm) {
	return 0; // TODO(mundaym): implement
}

// have instruction for:
//	op reg imm
// where reg is both a source and the destination
static int have_op_2_imm(sljit_s32 op, sljit_sw imm) {
	switch (GET_OPCODE(op) | (op & SLJIT_I32_OP)) {
	case SLJIT_ADD32:
	case SLJIT_ADD:
		if (op & SLJIT_SET_CARRY) {
			return have_eimm() && is_u32(imm);
		}
		return have_eimm() ? is_s32(imm) : is_s16(imm);
	case SLJIT_MUL32:
	case SLJIT_MUL:
		// TODO(mundaym): general extension check
		// for ms{,g}fi
		return is_s16(imm);
	case SLJIT_OR32:
	case SLJIT_XOR32:
	case SLJIT_AND32:
		// only use if have extended immediate facility
		// this ensures flags are set correctly
		return have_eimm();
	case SLJIT_AND:
	case SLJIT_OR:
	case SLJIT_XOR:
		// TODO(mundaym): make this more flexible
		// avoid using immediate variations, flags
		// won't be set correctly
		return 0;
	case SLJIT_ADDC32:
	case SLJIT_ADDC:
		// no ADD LOGICAL WITH CARRY IMMEDIATE
		return 0;
	case SLJIT_SUB:
	case SLJIT_SUB32:
	case SLJIT_SUBC:
	case SLJIT_SUBC32:
		// no SUBTRACT IMMEDIATE
		// TODO(mundaym): SUBTRACT LOGICAL IMMEDIATE
		return 0;
	}
	return 0;
}

SLJIT_API_FUNC_ATTRIBUTE sljit_s32 sljit_emit_op2(struct sljit_compiler *compiler, sljit_s32 op,
	sljit_s32 dst, sljit_sw dstw,
	sljit_s32 src1, sljit_sw src1w,
	sljit_s32 src2, sljit_sw src2w)
{
	CHECK_ERROR();
	CHECK(check_sljit_emit_op2(compiler, op, dst, dstw, src1, src1w, src2, src2w));
	//TODO(mundaym): implement
	//ADJUST_LOCAL_OFFSET(dst, dstw);
	//ADJUST_LOCAL_OFFSET(src1, src1w);
	//ADJUST_LOCAL_OFFSET(src2, src2w);

	if (dst == SLJIT_UNUSED && !HAS_FLAGS(op))
		return SLJIT_SUCCESS;

	sljit_gpr dst_r = SLOW_IS_REG(dst) ? gpr(dst & REG_MASK) : tmp0;

	// convert SUB(x, imm) to ADD(x, -imm)
	if ((src2 & SLJIT_IMM) && !(op & SLJIT_SET_CARRY)) {
		if ((GET_OPCODE(op) == SLJIT_SUB) && (src2w != (-1L<<63))) {
			op &= ~SLJIT_SUB;
			op |= SLJIT_ADD;
			src2w = -src2w;
		}
	}

	if (is_commutative(op)) {
		#define SWAP_ARGS \
		do {                         \
			sljit_s32 t = src1;  \
			sljit_sw tw = src1w; \
			src1 = src2;         \
			src1w = src2w;       \
			src2 = t;            \
			src2w = tw;          \
		} while(0);

		// prefer immediate in src2
		if (src1 & SLJIT_IMM) {
			SWAP_ARGS
		}

		// prefer to have src1 use same register as dst
		if (FAST_IS_REG(src2) && gpr(src2 & REG_MASK) == dst_r) {
			SWAP_ARGS
		}

		// prefer memory argument in src2
		if (FAST_IS_REG(src2) && (src1 & SLJIT_MEM)) {
			SWAP_ARGS
		}
	}

	// src1 must be in a register
	sljit_gpr src1_r = FAST_IS_REG(src1) ? gpr(src1 & REG_MASK) : tmp0;
	if (src1 & SLJIT_IMM) {
		FAIL_IF(push_load_imm_inst(compiler, src1_r, src1w));
	}
	if (src1 & SLJIT_MEM) {
		FAIL_IF(load_word(compiler, src1_r, src1, src1w, tmp1, op & SLJIT_I32_OP));
	}

	if (is_shift(op)) {
		// handle shifts first, they have more constraints than other operations
		sljit_sw d = 0;
		sljit_gpr b = FAST_IS_REG(src2) ? gpr(src2 & REG_MASK) : r0;
		if (src2 & SLJIT_IMM) {
			d = src2w & ((op & SLJIT_I32_OP) ? 31 : 63);
		}
		if (src2 & SLJIT_MEM) {
			// shift amount (b) cannot be in r0 (i.e. tmp0)
			FAIL_IF(load_word(compiler, tmp1, src2, src2w, tmp1, op & SLJIT_I32_OP));
			b = tmp1;
		}
		// src1 and dst share the same register in the base 32-bit ISA
		// TODO(mundaym): not needed when distinct-operand facility is available
		int workaround_alias = op & SLJIT_I32_OP && src1_r != dst_r;
		if (workaround_alias) {
			// put src1 into tmp0 so we can overwrite it
			FAIL_IF(push_inst(compiler, lr(tmp0, src1_r)));
			src1_r = tmp0;
		}
		switch (GET_OPCODE(op) | (op & SLJIT_I32_OP)) {
		case SLJIT_SHL:
			FAIL_IF(push_inst(compiler, sllg(dst_r, src1_r, d, b)));
			break;
		case SLJIT_SHL32:
			FAIL_IF(push_inst(compiler, sll(src1_r, d, b)));
			break;
		case SLJIT_LSHR:
			FAIL_IF(push_inst(compiler, srlg(dst_r, src1_r, d, b)));
			break;
		case SLJIT_LSHR32:
			FAIL_IF(push_inst(compiler, srl(src1_r, d, b)));
			break;
		case SLJIT_ASHR:
			FAIL_IF(push_inst(compiler, srag(dst_r, src1_r, d, b)));
			break;
		case SLJIT_ASHR32:
			FAIL_IF(push_inst(compiler, sra(src1_r, d, b)));
			break;
		default:
			SLJIT_UNREACHABLE();
		}
		if (workaround_alias && dst_r != src1_r) {
			FAIL_IF(push_inst(compiler, lr(dst_r, src1_r)));
		}
	} else if ((src2 & SLJIT_IMM) && (src1_r == dst_r) && have_op_2_imm(op, src2w)) {
		switch (GET_OPCODE(op) | (op & SLJIT_I32_OP)) {
		case SLJIT_ADD:
			if (op & SLJIT_SET_CARRY) {
				// carry if UNSIGNED overflow occurs
				FAIL_IF(push_inst(compiler, algfi(dst_r, src2w)));
			} else {
				FAIL_IF(push_inst(compiler, is_s16(src2w) ?
					aghi(dst_r, src2w) :
					agfi(dst_r, src2w)
				));
			}
			break;
		case SLJIT_ADD32:
			if (op & SLJIT_SET_CARRY) {
				// carry if UNSIGNED overflow occurs
				FAIL_IF(push_inst(compiler, alfi(dst_r, src2w)));
			} else {
				FAIL_IF(push_inst(compiler, is_s16(src2w) ?
					ahi(dst_r, src2w) :
					afi(dst_r, src2w)
				));
			}
			break;
		case SLJIT_MUL:
			FAIL_IF(push_inst(compiler, mhi(dst_r, src2w)));
			break;
		case SLJIT_MUL32:
			FAIL_IF(push_inst(compiler, mghi(dst_r, src2w)));
			break;
		case SLJIT_OR32:
			FAIL_IF(push_inst(compiler, oilf(dst_r, src2w)));
			break;
		case SLJIT_XOR32:
			FAIL_IF(push_inst(compiler, xilf(dst_r, src2w)));
			break;
		case SLJIT_AND32:
			FAIL_IF(push_inst(compiler, nilf(dst_r, src2w)));
			break;
		default:
			SLJIT_UNREACHABLE();
		}
	} else if ((src2 & SLJIT_IMM) && have_op_3_imm(op, src2w)) {
		abort(); // TODO(mundaym): implement
	} else if ((src2 & SLJIT_MEM) && (dst_r == src1_r)) {
		// most 32-bit instructions can only handle 12-bit immediate offsets
		int need_u12 = !have_ldisp() &&
			(op & SLJIT_I32_OP) &&
			(GET_OPCODE(op) != SLJIT_ADDC) &&
			(GET_OPCODE(op) != SLJIT_SUBC);
		struct addr mem;
		if (need_u12) {
			FAIL_IF(make_addr_bx(compiler, &mem, src2, src2w, tmp1));
		} else {
			FAIL_IF(make_addr_bxy(compiler, &mem, src2, src2w, tmp1));
		}

		int can_u12 = is_u12(mem.offset) ? 1 : 0;
		sljit_ins ins = 0;

		// use logical ops (alg rather than ag) to ensure carry bit is set
		// correctly if required
		switch (GET_OPCODE(op) | (op & SLJIT_I32_OP)) {
		// 64-bit ops
#define EVAL(op) op(dst_r, mem.offset, mem.index, mem.base)
		case SLJIT_ADD:  ins = EVAL( alg); break;
		case SLJIT_ADDC: ins = EVAL(alcg); break;
		case SLJIT_SUB:  ins = EVAL( slg); break;
		case SLJIT_SUBC: ins = EVAL(slbg); break;
		case SLJIT_MUL:  ins = EVAL( msg); break;
		case SLJIT_OR:   ins = EVAL(  og); break;
		case SLJIT_XOR:  ins = EVAL(  xg); break;
		case SLJIT_AND:  ins = EVAL(  ng); break;
		// 32-bit ops
		case SLJIT_ADDC32: ins = EVAL(alc); break;
		case SLJIT_SUBC32: ins = EVAL(slb); break;
		case SLJIT_ADD32:  ins = can_u12 ? EVAL(al) : EVAL(aly); break;
		case SLJIT_SUB32:  ins = can_u12 ? EVAL(sl) : EVAL(sly); break;
		case SLJIT_MUL32:  ins = can_u12 ? EVAL(ms) : EVAL(msy); break;
		case SLJIT_OR32:   ins = can_u12 ? EVAL( o) : EVAL( oy); break;
		case SLJIT_XOR32:  ins = can_u12 ? EVAL( x) : EVAL( xy); break;
		case SLJIT_AND32:  ins = can_u12 ? EVAL( n) : EVAL( ny); break;
#undef EVAL
		default:
			SLJIT_UNREACHABLE();
		}
		FAIL_IF(push_inst(compiler, ins));
	} else {
		sljit_gpr src2_r = FAST_IS_REG(src2) ? gpr(src2 & REG_MASK) : tmp1;
		if (src2 & SLJIT_IMM) {
			// load src2 into register
			FAIL_IF(push_load_imm_inst(compiler, src2_r, src2w));
		}
		if (src2 & SLJIT_MEM) {
			// load src2 into register
			FAIL_IF(load_word(compiler, src2_r, src2, src2w, tmp1, op & SLJIT_I32_OP));
		}
		// TODO(mundaym): distinct operand facility where needed
		if (src1_r != dst_r && src1_r != tmp0) {
			FAIL_IF(push_inst(compiler, (op & SLJIT_I32_OP) ?
				lr(tmp0, src1_r) : lgr(tmp0, src1_r)));
			src1_r = tmp0;
		}
		sljit_ins ins = 0;
		// use logical ops (algr rather than agr) to ensure carry bit is set
		// correctly if required
		switch (GET_OPCODE(op) | (op & SLJIT_I32_OP)) {
		// 64-bit ops
		case SLJIT_ADD:  ins =  algr(src1_r, src2_r); break;
		case SLJIT_ADDC: ins = alcgr(src1_r, src2_r); break;
		case SLJIT_SUB:  ins =  slgr(src1_r, src2_r); break;
		case SLJIT_SUBC: ins = slbgr(src1_r, src2_r); break;
		case SLJIT_MUL:  ins =  msgr(src1_r, src2_r); break;
		case SLJIT_AND:  ins =   ngr(src1_r, src2_r); break;
		case SLJIT_OR:   ins =   ogr(src1_r, src2_r); break;
		case SLJIT_XOR:  ins =   xgr(src1_r, src2_r); break;
		// 32-bit ops
		case SLJIT_ADD32:  ins =  alr(src1_r, src2_r); break;
		case SLJIT_ADDC32: ins = alcr(src1_r, src2_r); break;
		case SLJIT_SUB32:  ins =  slr(src1_r, src2_r); break;
		case SLJIT_SUBC32: ins = slbr(src1_r, src2_r); break;
		case SLJIT_MUL32:  ins =  msr(src1_r, src2_r); break;
		case SLJIT_AND32:  ins =   nr(src1_r, src2_r); break;
		case SLJIT_OR32:   ins =   or(src1_r, src2_r); break;
		case SLJIT_XOR32:  ins =   xr(src1_r, src2_r); break;
		default:
			SLJIT_UNREACHABLE();
		}
		FAIL_IF(push_inst(compiler, ins));
		if (src1_r != dst_r) {
			FAIL_IF(push_inst(compiler, (op & SLJIT_I32_OP) ?
				lr(dst_r, src1_r) : lgr(dst_r, src1_r)));
		}
	}

	// finally write the result to memory if required
	if (dst & SLJIT_MEM) {
		SLJIT_ASSERT(dst_r != tmp1);
		FAIL_IF(store_word(compiler, dst_r, dst, dstw, tmp1, op & SLJIT_I32_OP));
	}

	return SLJIT_SUCCESS;
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

// map the given type to a 4-bit condition code mask
static sljit_uw get_cc(sljit_s32 type) {
	const sljit_uw eq = 1 << 3; // equal {,to zero}
	const sljit_uw lt = 1 << 2; // less than {,zero}
	const sljit_uw gt = 1 << 1; // greater than {,zero}
	const sljit_uw ov = 1 << 0; // {overflow,NaN}
	const sljit_uw mask = 0xf;

	switch (type) {
	case SLJIT_EQUAL:
	case SLJIT_EQUAL_F64:
		return mask & eq;

	case SLJIT_NOT_EQUAL:
	case SLJIT_NOT_EQUAL_F64:
		return mask & ~eq;

	case SLJIT_LESS:
	case SLJIT_SIG_LESS:
	case SLJIT_LESS_F64:
		return mask & lt;

	case SLJIT_LESS_EQUAL:
	case SLJIT_SIG_LESS_EQUAL:
	case SLJIT_LESS_EQUAL_F64:
		return mask & (lt | eq);

	case SLJIT_GREATER:
	case SLJIT_SIG_GREATER:
	case SLJIT_GREATER_F64:
		return mask & gt;

	case SLJIT_GREATER_EQUAL:
	case SLJIT_SIG_GREATER_EQUAL:
	case SLJIT_GREATER_EQUAL_F64:
		return mask & (gt | eq);

	case SLJIT_OVERFLOW:
	case SLJIT_MUL_OVERFLOW:
	case SLJIT_UNORDERED_F64:
		return mask & ov;

	case SLJIT_NOT_OVERFLOW:
	case SLJIT_MUL_NOT_OVERFLOW:
	case SLJIT_ORDERED_F64:
		return mask & ~ov;
	}
	SLJIT_UNREACHABLE();
}

SLJIT_API_FUNC_ATTRIBUTE sljit_s32 sljit_emit_op_flags(struct sljit_compiler *compiler, sljit_s32 op,
	sljit_s32 dst, sljit_sw dstw,
	sljit_s32 type)
{
	CHECK_ERROR();
	CHECK(check_sljit_emit_op_flags(compiler, op, dst, dstw, type));

	sljit_gpr dst_r = FAST_IS_REG(dst) ? gpr(dst & REG_MASK) : tmp0;
	sljit_gpr loc_r = tmp1;
	switch (GET_OPCODE(op)) {
	case SLJIT_AND:
	case SLJIT_OR:
	case SLJIT_XOR:
		// dst is also source operand
		if (dst & SLJIT_MEM) {
			FAIL_IF(load_word(compiler, dst_r, dst, dstw, tmp1, op & SLJIT_I32_OP));
		}
		break;
	case SLJIT_MOV:
		// can write straight into destination
		loc_r = dst_r;
		break;
	default:
		SLJIT_UNREACHABLE();
	}

	sljit_uw mask = get_cc(type);
	// TODO(mundaym): fold into cmov helper function?
	if (have_lscond2()) {
		FAIL_IF(push_load_imm_inst(compiler, loc_r, 0));
		FAIL_IF(push_inst(compiler, (op & SLJIT_I32_OP) ?
			lochi(loc_r, 1, mask) :
			locghi(loc_r, 1, mask)));
	} else {
		// TODO(mundaym): no load/store-on-condition 2 facility (ipm? branch-and-set?)
		abort();
	}

	// apply bitwise op and set condition codes
	switch (GET_OPCODE(op)) {
	case SLJIT_AND:
		FAIL_IF(push_inst(compiler, (op & SLJIT_I32_OP) ?
			nr(dst_r, loc_r) :
			ngr(dst_r, loc_r)));
		break;
	case SLJIT_OR:
		FAIL_IF(push_inst(compiler, (op & SLJIT_I32_OP) ?
			or(dst_r, loc_r) :
			ogr(dst_r, loc_r)));
		break;
	case SLJIT_XOR:
		FAIL_IF(push_inst(compiler, (op & SLJIT_I32_OP) ?
			xr(dst_r, loc_r) :
			xgr(dst_r, loc_r)));
		break;
	}

	// store result to memory if required
	if (dst & SLJIT_MEM) {
		FAIL_IF(store_word(compiler, dst_r, dst, dstw, tmp1, op & SLJIT_I32_OP));
	}

	return SLJIT_SUCCESS;
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