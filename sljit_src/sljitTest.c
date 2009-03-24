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

#include "sljitLir.h"

#ifndef SLJIT_INDIRECT_CALL
union executable_code {
	void* code;
	SLJIT_CALL sljit_w (*func0)(void);
	SLJIT_CALL sljit_w (*func1)(sljit_w a);
	SLJIT_CALL sljit_w (*func2)(sljit_w a, sljit_w b);
	SLJIT_CALL sljit_w (*func3)(sljit_w a, sljit_w b, sljit_w c);
};
typedef union executable_code executable_code;
#else
struct executable_code {
	void* code;
	union {
		SLJIT_CALL sljit_w (*func0)(void);
		SLJIT_CALL sljit_w (*func1)(sljit_w a);
		SLJIT_CALL sljit_w (*func2)(sljit_w a, sljit_w b);
		SLJIT_CALL sljit_w (*func3)(sljit_w a, sljit_w b, sljit_w c);
		void** code_ptr;
	};
};
typedef struct executable_code executable_code;
#endif

#define FAILED(cond, text) \
	if (cond) { \
		printf(text); \
		return; \
	}

#define T(value) \
	if ((value) != SLJIT_NO_ERROR) { \
		printf("Compiler error: %d\n", compiler->error); \
		sljit_free_compiler(compiler); \
		return; \
	}

#define TP(value) \
	if ((value) == NULL) { \
		printf("Compiler error: %d\n", compiler->error); \
		sljit_free_compiler(compiler); \
		return; \
	}

static void test1(void)
{
	// Enter and return from an sljit function
	executable_code code;
	struct sljit_compiler* compiler = sljit_create_compiler();

	FAILED(!compiler, "cannot create compiler\n");

	// 3 arguments passed, 3 arguments used
	T(sljit_emit_enter(compiler, 3, 3, 0));
	T(sljit_emit_return(compiler, SLJIT_GENERAL_REG2));

	code.code = sljit_generate_code(compiler);
#ifdef SLJIT_INDIRECT_CALL
	code.code_ptr = &code.code;
#endif
	FAILED(!code.code, "code generation error\n");
	sljit_free_compiler(compiler);

	FAILED(code.func3(3, -21, 86) != -21, "test1 case 1 failed\n");
	FAILED(code.func3(4789, 47890, 997) != 47890, "test1 case 1 failed\n");
	sljit_free_code(code.code);
	printf("test1 ok\n");
}

static void test2(void)
{
	// Test mov
	executable_code code;
	struct sljit_compiler* compiler = sljit_create_compiler();
	sljit_w buf[4];

	FAILED(!compiler, "cannot create compiler\n");

	buf[0] = 5678;
	buf[1] = 0;
	buf[2] = 0;
	buf[3] = 0;
	T(sljit_emit_enter(compiler, 1, 2, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_NO_REG, 0, SLJIT_MEM0(), (sljit_w)&buf));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 9999));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_GENERAL_REG2, 0, SLJIT_GENERAL_REG1, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG2), sizeof(sljit_w), SLJIT_TEMPORARY_REG1, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG2, 0, SLJIT_IMM, sizeof(sljit_w)));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG3, 0, SLJIT_MEM2(SLJIT_GENERAL_REG2, SLJIT_TEMPORARY_REG2), 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM2(SLJIT_GENERAL_REG2, SLJIT_TEMPORARY_REG2), sizeof(sljit_w), SLJIT_MEM2(SLJIT_GENERAL_REG2, SLJIT_TEMPORARY_REG2), 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM2(SLJIT_GENERAL_REG2, SLJIT_TEMPORARY_REG2), sizeof(sljit_w) * 2, SLJIT_MEM0(), (sljit_w)&buf));
	T(sljit_emit_return(compiler, SLJIT_TEMPORARY_REG3));

	code.code = sljit_generate_code(compiler);
#ifdef SLJIT_INDIRECT_CALL
	code.code_ptr = &code.code;
#endif
	FAILED(!code.code, "code generation error\n");
	sljit_free_compiler(compiler);

	FAILED(code.func1((sljit_w)&buf) != 9999, "test2 case 1 failed\n");
	FAILED(buf[1] != 9999, "test2 case 2 failed\n");
	FAILED(buf[2] != 9999, "test2 case 3 failed\n");
	FAILED(buf[3] != 5678, "test2 case 4 failed\n");
	sljit_free_code(code.code);
	printf("test2 ok\n");
}

static void test3(void)
{
	// Test not
	executable_code code;
	struct sljit_compiler* compiler = sljit_create_compiler();
	sljit_w buf[4];

	FAILED(!compiler, "cannot create compiler\n");
	buf[0] = 1234;
	buf[1] = 0;
	buf[2] = 9876;
	buf[3] = 0;

	T(sljit_emit_enter(compiler, 1, 2, 0));
	T(sljit_emit_op1(compiler, SLJIT_NOT, SLJIT_NO_REG, 0, SLJIT_MEM0(), (sljit_w)&buf));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w), SLJIT_MEM1(SLJIT_GENERAL_REG1), 0));
	T(sljit_emit_op1(compiler, SLJIT_NOT, SLJIT_MEM0(), (sljit_w)&buf[1], SLJIT_MEM0(), (sljit_w)&buf[1]));
	T(sljit_emit_op1(compiler, SLJIT_NOT, SLJIT_PREF_RET_REG, 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0));
	T(sljit_emit_op1(compiler, SLJIT_NOT, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 3, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 2));
	T(sljit_emit_return(compiler, SLJIT_PREF_RET_REG));

	code.code = sljit_generate_code(compiler);
#ifdef SLJIT_INDIRECT_CALL
	code.code_ptr = &code.code;
#endif
	FAILED(!code.code, "code generation error\n");
	sljit_free_compiler(compiler);

	FAILED(code.func1((sljit_w)&buf) != ~1234, "test3 case 1 failed\n");
	FAILED(buf[1] != ~1234, "test3 case 2 failed\n");
	FAILED(buf[3] != ~9876, "test3 case 3 failed\n");

	sljit_free_code(code.code);
	printf("test3 ok\n");
}

static void test4(void)
{
	// Test not
	executable_code code;
	struct sljit_compiler* compiler = sljit_create_compiler();
	sljit_w buf[4];

	FAILED(!compiler, "cannot create compiler\n");
	buf[0] = 0;
	buf[1] = 1234;
	buf[2] = 0;
	buf[3] = 0;

	T(sljit_emit_enter(compiler, 2, 2, 0));
	T(sljit_emit_op1(compiler, SLJIT_NEG, SLJIT_NO_REG, 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0));
	T(sljit_emit_op1(compiler, SLJIT_NEG, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 2, SLJIT_GENERAL_REG2, 0));
	T(sljit_emit_op1(compiler, SLJIT_NEG, SLJIT_MEM0(), (sljit_w)&buf[0], SLJIT_MEM0(), (sljit_w)&buf[1]));
	T(sljit_emit_op1(compiler, SLJIT_NEG, SLJIT_PREF_RET_REG, 0, SLJIT_GENERAL_REG2, 0));
	T(sljit_emit_op1(compiler, SLJIT_NEG, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 3, SLJIT_IMM, 299));
	T(sljit_emit_return(compiler, SLJIT_PREF_RET_REG));

	code.code = sljit_generate_code(compiler);
#ifdef SLJIT_INDIRECT_CALL
	code.code_ptr = &code.code;
#endif
	FAILED(!code.code, "code generation error\n");
	sljit_free_compiler(compiler);

	FAILED(code.func2((sljit_w)&buf, 4567) != -4567, "test4 case 1 failed\n");
	FAILED(buf[0] != -1234, "test4 case 2 failed\n");
	FAILED(buf[2] != -4567, "test4 case 3 failed\n");
	FAILED(buf[3] != -299, "test4 case 4 failed\n");

	sljit_free_code(code.code);
	printf("test4 ok\n");
}

static void test5(void)
{
	// Test add
	executable_code code;
	struct sljit_compiler* compiler = sljit_create_compiler();
	sljit_w buf[6];

	FAILED(!compiler, "cannot create compiler\n");
	buf[0] = 100;
	buf[1] = 200;
	buf[2] = 300;
	buf[3] = 0;
	buf[4] = 0;
	buf[5] = 0;

	T(sljit_emit_enter(compiler, 1, 2, 0));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_NO_REG, 0, SLJIT_IMM, 16, SLJIT_IMM, 16));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_NO_REG, 0, SLJIT_IMM, 255, SLJIT_IMM, 255));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_NO_REG, 0, SLJIT_GENERAL_REG1, 0, SLJIT_GENERAL_REG1, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, sizeof(sljit_w) * 2));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG2, 0, SLJIT_IMM, 50));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_MEM2(SLJIT_GENERAL_REG1, SLJIT_TEMPORARY_REG1), 0, SLJIT_MEM2(SLJIT_GENERAL_REG1, SLJIT_TEMPORARY_REG1), 0, SLJIT_MEM2(SLJIT_GENERAL_REG1, SLJIT_TEMPORARY_REG1), 0 - sizeof(sljit_w)));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_TEMPORARY_REG1, 0, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 2));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_TEMPORARY_REG2, 0, SLJIT_TEMPORARY_REG2, 0, SLJIT_IMM, 50));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_TEMPORARY_REG1, 0, SLJIT_TEMPORARY_REG1, 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0, SLJIT_TEMPORARY_REG1, 0));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 4, SLJIT_TEMPORARY_REG1, 0));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_TEMPORARY_REG2, 0, SLJIT_IMM, 50, SLJIT_TEMPORARY_REG2, 0));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_MEM1(SLJIT_GENERAL_REG1), 5 * sizeof(sljit_w), SLJIT_IMM, 50, SLJIT_MEM1(SLJIT_GENERAL_REG1), 5 * sizeof(sljit_w)));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_TEMPORARY_REG2, 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), 5 * sizeof(sljit_w), SLJIT_TEMPORARY_REG2, 0));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_MEM1(SLJIT_GENERAL_REG1), 4 * sizeof(sljit_w), SLJIT_TEMPORARY_REG2, 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), 4 * sizeof(sljit_w)));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_MEM1(SLJIT_GENERAL_REG1), 5 * sizeof(sljit_w), SLJIT_MEM1(SLJIT_GENERAL_REG1), 4 * sizeof(sljit_w), SLJIT_MEM1(SLJIT_GENERAL_REG1), 5 * sizeof(sljit_w)));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_MEM1(SLJIT_GENERAL_REG1), 3 * sizeof(sljit_w), SLJIT_MEM1(SLJIT_GENERAL_REG1), 4 * sizeof(sljit_w), SLJIT_TEMPORARY_REG2, 0));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 1000, SLJIT_TEMPORARY_REG1, 0));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_TEMPORARY_REG1, 0, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 1000));
	T(sljit_emit_return(compiler, SLJIT_TEMPORARY_REG1));

	code.code = sljit_generate_code(compiler);
#ifdef SLJIT_INDIRECT_CALL
	code.code_ptr = &code.code;
#endif
	FAILED(!code.code, "code generation error\n");
	sljit_free_compiler(compiler);

	FAILED(code.func1((sljit_w)&buf) != 2106 + 2 * sizeof(sljit_w), "test5 case 1 failed\n");
	FAILED(buf[0] != 202 + 2 * sizeof(sljit_w), "test5 case 2 failed\n");
	FAILED(buf[2] != 500, "test5 case 3 failed\n");
	FAILED(buf[3] != 400, "test5 case 4 failed\n");
	FAILED(buf[4] != 200, "test5 case 5 failed\n");
	FAILED(buf[5] != 250, "test5 case 6 failed\n");

	sljit_free_code(code.code);
	printf("test5 ok\n");
}

static void test6(void)
{
	// Test addc, sub, subc
	executable_code code;
	struct sljit_compiler* compiler = sljit_create_compiler();
	sljit_w buf[7];

	FAILED(!compiler, "cannot create compiler\n");
	buf[0] = 0;
	buf[1] = 0;
	buf[2] = 0;
	buf[3] = 0;
	buf[4] = 0;
	buf[5] = 0;
	buf[6] = 0;

	T(sljit_emit_enter(compiler, 1, 1, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, -1));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_TEMPORARY_REG1, 0, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, -1));
	T(sljit_emit_op2(compiler, SLJIT_ADDC, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0, SLJIT_IMM, 0, SLJIT_IMM, 0));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_TEMPORARY_REG1, 0, SLJIT_TEMPORARY_REG1, 0, SLJIT_TEMPORARY_REG1, 0));
	T(sljit_emit_op2(compiler, SLJIT_ADDC, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w), SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w), SLJIT_IMM, 4));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 100));
	T(sljit_emit_op2(compiler, SLJIT_SUB, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 2, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 50));
	T(sljit_emit_op2(compiler, SLJIT_SUB, SLJIT_TEMPORARY_REG1, 0, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 6000));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 3, SLJIT_IMM, 10));
	T(sljit_emit_op2(compiler, SLJIT_SUBC, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 3, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 3, SLJIT_IMM, 5));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 100));
	T(sljit_emit_op2(compiler, SLJIT_SUB, SLJIT_TEMPORARY_REG1, 0, SLJIT_TEMPORARY_REG1, 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 2));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 4, SLJIT_TEMPORARY_REG1, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 5000));
	T(sljit_emit_op2(compiler, SLJIT_SUB, SLJIT_TEMPORARY_REG2, 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 4, SLJIT_TEMPORARY_REG1, 0));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_TEMPORARY_REG2, 0, SLJIT_TEMPORARY_REG1, 0, SLJIT_TEMPORARY_REG2, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 5, SLJIT_TEMPORARY_REG2, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 5000));
	T(sljit_emit_op2(compiler, SLJIT_SUB, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 6000, SLJIT_TEMPORARY_REG1, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 6, SLJIT_TEMPORARY_REG1, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_PREF_RET_REG, 0, SLJIT_IMM, 10));
	T(sljit_emit_op2(compiler, SLJIT_SUB, SLJIT_PREF_RET_REG, 0, SLJIT_PREF_RET_REG, 0, SLJIT_IMM, 5));
	T(sljit_emit_op2(compiler, SLJIT_SUBC, SLJIT_PREF_RET_REG, 0, SLJIT_PREF_RET_REG, 0, SLJIT_IMM, 2));
	T(sljit_emit_return(compiler, SLJIT_PREF_RET_REG));

	code.code = sljit_generate_code(compiler);
#ifdef SLJIT_INDIRECT_CALL
	code.code_ptr = &code.code;
#endif
	FAILED(!code.code, "code generation error\n");
	sljit_free_compiler(compiler);

	FAILED(code.func1((sljit_w)&buf) != 3, "test6 case 1 failed\n");
	FAILED(buf[0] != 1, "test6 case 2 failed\n");
	FAILED(buf[1] != 5, "test6 case 3 failed\n");
	FAILED(buf[2] != 50, "test6 case 4 failed\n");
	FAILED(buf[3] != 4, "test6 case 5 failed\n");
	FAILED(buf[4] != 50, "test6 case 6 failed\n");
	FAILED(buf[5] != 50, "test6 case 7 failed\n");
	FAILED(buf[6] != 1000, "test6 case 8 failed\n");

	sljit_free_code(code.code);
	printf("test6 ok\n");
}

static void test7(void)
{
	// Test addc, sub, subc
	executable_code code;
	struct sljit_compiler* compiler = sljit_create_compiler();
	sljit_w buf[6];

	FAILED(!compiler, "cannot create compiler\n");
	buf[0] = 0xff80;
	buf[1] = 0x0f808080;
	buf[2] = 0;
	buf[3] = 0xaaaaaa;
	buf[4] = 0;
	buf[5] = 0x4040;

	T(sljit_emit_enter(compiler, 1, 1, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 0xf0C000));
	T(sljit_emit_op2(compiler, SLJIT_OR, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 2, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 0x308f));
	T(sljit_emit_op2(compiler, SLJIT_XOR, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w)));
	T(sljit_emit_op2(compiler, SLJIT_AND, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 3, SLJIT_IMM, 0xf0f0f0, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 3));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 0xC0F0));
	T(sljit_emit_op2(compiler, SLJIT_XOR, SLJIT_TEMPORARY_REG1, 0, SLJIT_TEMPORARY_REG1, 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 5));
	T(sljit_emit_op2(compiler, SLJIT_OR, SLJIT_TEMPORARY_REG1, 0, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 0xff0000));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 4, SLJIT_TEMPORARY_REG1, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG3, 0, SLJIT_IMM, 0xC0F0));
	T(sljit_emit_op2(compiler, SLJIT_AND, SLJIT_TEMPORARY_REG3, 0, SLJIT_TEMPORARY_REG3, 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 5));
	T(sljit_emit_op2(compiler, SLJIT_OR, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 5, SLJIT_TEMPORARY_REG3, 0, SLJIT_IMM, 0xff0000));
	T(sljit_emit_op2(compiler, SLJIT_XOR, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w), SLJIT_IMM, 0xFFFFFF, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w)));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 0xff00ff00));
	T(sljit_emit_op2(compiler, SLJIT_OR, SLJIT_TEMPORARY_REG2, 0, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 0x0f));
	T(sljit_emit_op2(compiler, SLJIT_AND, SLJIT_PREF_RET_REG, 0, SLJIT_IMM, 0x888888, SLJIT_TEMPORARY_REG2, 0));
	T(sljit_emit_return(compiler, SLJIT_PREF_RET_REG));

	code.code = sljit_generate_code(compiler);
#ifdef SLJIT_INDIRECT_CALL
	code.code_ptr = &code.code;
#endif
	FAILED(!code.code, "code generation error\n");
	sljit_free_compiler(compiler);

	FAILED(code.func1((sljit_w)&buf) != 0x8808, "test7 case 1 failed\n");
	FAILED(buf[0] != 0x0F807F00, "test7 case 2 failed\n");
	FAILED(buf[1] != 0x0F7F7F7F, "test7 case 3 failed\n");
	FAILED(buf[2] != 0x00F0F08F, "test7 case 4 failed\n");
	FAILED(buf[3] != 0x00A0A0A0, "test7 case 5 failed\n");
	FAILED(buf[4] != 0x00FF80B0, "test7 case 6 failed\n");
	FAILED(buf[5] != 0x00FF4040, "test7 case 7 failed\n");

	sljit_free_code(code.code);
	printf("test7 ok\n");
}

static void test8(void)
{
	// Test flags (neg, cmp, test)
	executable_code code;
	struct sljit_compiler* compiler = sljit_create_compiler();
	sljit_w buf[7];

	FAILED(!compiler, "cannot create compiler\n");
	buf[0] = 100;
	buf[1] = 3;
	buf[2] = 3;
	buf[3] = 3;
	buf[4] = 3;
	buf[5] = 3;
	buf[6] = 3;

	T(sljit_emit_enter(compiler, 1, 2, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 20));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG2, 0, SLJIT_IMM, 10));
	T(sljit_emit_op2(compiler, SLJIT_SUB, SLJIT_NO_REG, 0, SLJIT_IMM, 6, SLJIT_IMM, 5));
	T(sljit_emit_cond_set(compiler, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w), SLJIT_C_NOT_EQUAL));
	T(sljit_emit_op2(compiler, SLJIT_SUB, SLJIT_NO_REG, 0, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 3000));
	T(sljit_emit_cond_set(compiler, SLJIT_GENERAL_REG2, 0, SLJIT_C_GREATER));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 2, SLJIT_GENERAL_REG2, 0));
	T(sljit_emit_op2(compiler, SLJIT_SUB, SLJIT_NO_REG, 0, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, -15));
	T(sljit_emit_cond_set(compiler, SLJIT_TEMPORARY_REG3, 0, SLJIT_C_SIG_GREATER));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 3, SLJIT_TEMPORARY_REG3, 0));
	T(sljit_emit_op2(compiler, SLJIT_SUB, SLJIT_NO_REG, 0, SLJIT_TEMPORARY_REG1, 0, SLJIT_TEMPORARY_REG2, 0));
	T(sljit_emit_op2(compiler, SLJIT_SUB, SLJIT_NO_REG, 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0, SLJIT_TEMPORARY_REG1, 0));
	T(sljit_emit_op1(compiler, SLJIT_NEG, SLJIT_NO_REG, 0, SLJIT_IMM, (sljit_w)1 << ((sizeof(sljit_w) << 3) - 1)));
	T(sljit_emit_cond_set(compiler, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 4, SLJIT_C_OVERFLOW));
	T(sljit_emit_op2(compiler, SLJIT_AND, SLJIT_NO_REG, 0, SLJIT_IMM, 0xffff, SLJIT_TEMPORARY_REG1, 0));
	T(sljit_emit_op2(compiler, SLJIT_AND, SLJIT_NO_REG, 0, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 0xffff));
	T(sljit_emit_cond_set(compiler, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 5, SLJIT_C_NOT_ZERO));
	T(sljit_emit_op2(compiler, SLJIT_AND, SLJIT_NO_REG, 0, SLJIT_IMM, 0xffff, SLJIT_TEMPORARY_REG2, 0));
	T(sljit_emit_op2(compiler, SLJIT_AND, SLJIT_NO_REG, 0, SLJIT_TEMPORARY_REG2, 0, SLJIT_IMM, 0xffff));
	T(sljit_emit_op2(compiler, SLJIT_AND, SLJIT_NO_REG, 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0, SLJIT_TEMPORARY_REG2, 0));
	T(sljit_emit_op2(compiler, SLJIT_AND, SLJIT_NO_REG, 0, SLJIT_TEMPORARY_REG2, 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0));
	T(sljit_emit_op2(compiler, SLJIT_AND, SLJIT_NO_REG, 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0));
	T(sljit_emit_op2(compiler, SLJIT_AND, SLJIT_NO_REG, 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0, SLJIT_IMM, 0x1));
	T(sljit_emit_cond_set(compiler, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 6, SLJIT_C_NOT_ZERO));
	T(sljit_emit_return(compiler, SLJIT_NO_REG));

	code.code = sljit_generate_code(compiler);
#ifdef SLJIT_INDIRECT_CALL
	code.code_ptr = &code.code;
#endif
	FAILED(!code.code, "code generation error\n");
	sljit_free_compiler(compiler);

	code.func1((sljit_w)&buf);
	FAILED(buf[1] != 1, "test8 case 1 failed\n");
	FAILED(buf[2] != 0, "test8 case 2 failed\n");
	FAILED(buf[3] != 1, "test8 case 3 failed\n");
	FAILED(buf[4] != 1, "test8 case 4 failed\n");
	FAILED(buf[5] != 1, "test8 case 5 failed\n");
	FAILED(buf[6] != 0, "test8 case 6 failed\n");

	sljit_free_code(code.code);
	printf("test8 ok\n");
}

static void test9(void)
{
	// Test shift
	executable_code code;
	struct sljit_compiler* compiler = sljit_create_compiler();
	sljit_w buf[10];

	FAILED(!compiler, "cannot create compiler\n");
	buf[0] = 0;
	buf[1] = 0;
	buf[2] = 0;
	buf[3] = 0;
	buf[4] = 1 << 10;
	buf[5] = 0;
	buf[6] = 0;
	buf[7] = 0;
	buf[8] = 0;
	buf[9] = 3;

	T(sljit_emit_enter(compiler, 1, 2, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 0xf));
	T(sljit_emit_op2(compiler, SLJIT_SHL, SLJIT_TEMPORARY_REG1, 0, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 3));
	T(sljit_emit_op2(compiler, SLJIT_LSHR, SLJIT_TEMPORARY_REG1, 0, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 1));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0, SLJIT_TEMPORARY_REG1, 0));
	T(sljit_emit_op2(compiler, SLJIT_ASHR, SLJIT_NO_REG, 0, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 2));
	T(sljit_emit_op2(compiler, SLJIT_SHL, SLJIT_TEMPORARY_REG2, 0, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 1));
	T(sljit_emit_op2(compiler, SLJIT_SHL, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w), SLJIT_TEMPORARY_REG2, 0, SLJIT_IMM, 1));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, -64));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_PREF_SHIFT_REG, 0, SLJIT_IMM, 2));
	T(sljit_emit_op2(compiler, SLJIT_ASHR, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 2, SLJIT_TEMPORARY_REG1, 0, SLJIT_PREF_SHIFT_REG, 0));

	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_PREF_SHIFT_REG, 0, SLJIT_IMM, 0xff));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 4));
	T(sljit_emit_op2(compiler, SLJIT_SHL, SLJIT_PREF_SHIFT_REG, 0, SLJIT_PREF_SHIFT_REG, 0, SLJIT_TEMPORARY_REG1, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 3, SLJIT_PREF_SHIFT_REG, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_PREF_SHIFT_REG, 0, SLJIT_IMM, 0xff));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 8));
	T(sljit_emit_op2(compiler, SLJIT_LSHR, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 4, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 4, SLJIT_TEMPORARY_REG1, 0));
	T(sljit_emit_op2(compiler, SLJIT_SHL, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 5, SLJIT_PREF_SHIFT_REG, 0, SLJIT_TEMPORARY_REG1, 0));

	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_GENERAL_REG2, 0, SLJIT_IMM, 0xf));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 2));
	T(sljit_emit_op2(compiler, SLJIT_SHL, SLJIT_GENERAL_REG2, 0, SLJIT_GENERAL_REG2, 0, SLJIT_TEMPORARY_REG1, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 6, SLJIT_GENERAL_REG2, 0));
	T(sljit_emit_op2(compiler, SLJIT_SHL, SLJIT_TEMPORARY_REG1, 0, SLJIT_GENERAL_REG2, 0, SLJIT_TEMPORARY_REG1, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 7, SLJIT_TEMPORARY_REG1, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG3, 0, SLJIT_IMM, 0xf00));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 4));
	T(sljit_emit_op2(compiler, SLJIT_LSHR, SLJIT_TEMPORARY_REG2, 0, SLJIT_TEMPORARY_REG3, 0, SLJIT_TEMPORARY_REG1, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 8, SLJIT_TEMPORARY_REG2, 0));

	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, sizeof(sljit_w) * 4));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG2, 0, SLJIT_IMM, sizeof(sljit_w) * 5));
	T(sljit_emit_op2(compiler, SLJIT_SHL, SLJIT_MEM2(SLJIT_TEMPORARY_REG1, SLJIT_TEMPORARY_REG2), (sljit_w)buf, SLJIT_MEM2(SLJIT_TEMPORARY_REG1, SLJIT_TEMPORARY_REG2), (sljit_w)buf, SLJIT_MEM2(SLJIT_TEMPORARY_REG1, SLJIT_TEMPORARY_REG2), (sljit_w)buf));

	T(sljit_emit_return(compiler, SLJIT_NO_REG));

	code.code = sljit_generate_code(compiler);
#ifdef SLJIT_INDIRECT_CALL
	code.code_ptr = &code.code;
#endif
	FAILED(!code.code, "code generation error\n");
	sljit_free_compiler(compiler);

	code.func1((sljit_w)&buf);
	FAILED(buf[0] != 0x3c, "test9 case 1 failed\n");
	FAILED(buf[1] != 0xf0, "test9 case 2 failed\n");
	FAILED(buf[2] != -16, "test9 case 3 failed\n");
	FAILED(buf[3] != 0xff0, "test9 case 4 failed\n");
	FAILED(buf[4] != 4, "test9 case 5 failed\n");
	FAILED(buf[5] != 0xff00, "test9 case 6 failed\n");
	FAILED(buf[6] != 0x3c, "test9 case 7 failed\n");
	FAILED(buf[7] != 0xf0, "test9 case 8 failed\n");
	FAILED(buf[8] != 0xf0, "test9 case 9 failed\n");
	FAILED(buf[9] != 0x18, "test9 case 10 failed\n");

	sljit_free_code(code.code);
	printf("test9 ok\n");
}

static void test10(void)
{
	// Test multiplications
	executable_code code;
	struct sljit_compiler* compiler = sljit_create_compiler();
	sljit_w buf[6];

	FAILED(!compiler, "cannot create compiler\n");
	buf[0] = 3;
	buf[1] = 0;
	buf[2] = 0;
	buf[3] = 6;
	buf[4] = -10;
	buf[5] = 0;

	T(sljit_emit_enter(compiler, 1, 1, 0));

	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_PREF_MUL_DST, 0, SLJIT_IMM, 5));
	T(sljit_emit_op2(compiler, SLJIT_MUL, SLJIT_PREF_MUL_DST, 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0, SLJIT_PREF_MUL_DST, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0, SLJIT_PREF_MUL_DST, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG3, 0, SLJIT_IMM, 7));
	T(sljit_emit_op2(compiler, SLJIT_MUL, SLJIT_PREF_MUL_DST, 0, SLJIT_TEMPORARY_REG3, 0, SLJIT_IMM, 8));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w), SLJIT_PREF_MUL_DST, 0));
	T(sljit_emit_op2(compiler, SLJIT_MUL, SLJIT_PREF_MUL_DST, 0, SLJIT_IMM, -3, SLJIT_IMM, -4));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 2, SLJIT_PREF_MUL_DST, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_PREF_MUL_DST, 0, SLJIT_IMM, -2));
	T(sljit_emit_op2(compiler, SLJIT_MUL, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 3, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 3, SLJIT_PREF_MUL_DST, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_PREF_MUL_DST, 0, SLJIT_IMM, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG2, 0, SLJIT_IMM, 0));
	T(sljit_emit_op2(compiler, SLJIT_MUL, SLJIT_MEM2(SLJIT_TEMPORARY_REG2, SLJIT_PREF_MUL_DST), (sljit_w)&buf[4], SLJIT_MEM2(SLJIT_TEMPORARY_REG2, SLJIT_PREF_MUL_DST), (sljit_w)&buf[4], SLJIT_MEM2(SLJIT_TEMPORARY_REG2, SLJIT_PREF_MUL_DST), (sljit_w)&buf[4]));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_PREF_MUL_DST, 0, SLJIT_IMM, 9));
	T(sljit_emit_op2(compiler, SLJIT_MUL, SLJIT_PREF_MUL_DST, 0, SLJIT_PREF_MUL_DST, 0, SLJIT_PREF_MUL_DST, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 5, SLJIT_PREF_MUL_DST, 0));
	T(sljit_emit_op2(compiler, SLJIT_MUL, SLJIT_PREF_RET_REG, 0, SLJIT_IMM, 11, SLJIT_IMM, 10));
	T(sljit_emit_return(compiler, SLJIT_PREF_RET_REG));

	code.code = sljit_generate_code(compiler);
#ifdef SLJIT_INDIRECT_CALL
	code.code_ptr = &code.code;
#endif
	FAILED(!code.code, "code generation error\n");
	sljit_free_compiler(compiler);

	FAILED(code.func1((sljit_w)&buf) != 110, "test10 case 1 failed\n");
	FAILED(buf[0] != 15, "test10 case 2 failed\n");
	FAILED(buf[1] != 56, "test10 case 3 failed\n");
	FAILED(buf[2] != 12, "test10 case 4 failed\n");
	FAILED(buf[3] != -12, "test10 case 5 failed\n");
	FAILED(buf[4] != 100, "test10 case 6 failed\n");
	FAILED(buf[5] != 81, "test10 case 7 failed\n");

	sljit_free_code(code.code);
	printf("test10 ok\n");
}

static void test11(void)
{
	// Test rewritable constants
	executable_code code;
	struct sljit_compiler* compiler = sljit_create_compiler();
	struct sljit_const* const1;
	struct sljit_const* const2;
	struct sljit_const* const3;
	sljit_uw const1_addr;
	sljit_uw const2_addr;
	sljit_uw const3_addr;
	sljit_w buf[2];

	FAILED(!compiler, "cannot create compiler\n");
	buf[0] = 0;
	buf[1] = 0;

	T(sljit_emit_enter(compiler, 1, 1, 0));

	const1 = sljit_emit_const(compiler, SLJIT_MEM0(), (sljit_w)&buf[0], 12);
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 0));
	const2 = sljit_emit_const(compiler, SLJIT_MEM2(SLJIT_GENERAL_REG1, SLJIT_TEMPORARY_REG1), sizeof(sljit_w), 2345);
	const3 = sljit_emit_const(compiler, SLJIT_PREF_RET_REG, 0, 3456);

	T(sljit_emit_return(compiler, SLJIT_PREF_RET_REG));

	code.code = sljit_generate_code(compiler);
#ifdef SLJIT_INDIRECT_CALL
	code.code_ptr = &code.code;
#endif
	FAILED(!code.code, "code generation error\n");
	const1_addr = sljit_get_const_addr(const1);
	const2_addr = sljit_get_const_addr(const2);
	const3_addr = sljit_get_const_addr(const3);
	sljit_free_compiler(compiler);

	FAILED(code.func1((sljit_w)&buf) != 3456, "test11 case 1 failed\n");
	FAILED(buf[0] != 12, "test11 case 2 failed\n");
	FAILED(buf[1] != 2345, "test11 case 3 failed\n");

	sljit_set_const(const1_addr, 1234567);
	sljit_set_const(const2_addr, 2345678);
	sljit_set_const(const3_addr, 34);

	FAILED(code.func1((sljit_w)&buf) != 34, "test11 case 4 failed\n");
	FAILED(buf[0] != 1234567, "test11 case 5 failed\n");
	FAILED(buf[1] != 2345678, "test11 case 6 failed\n");

	sljit_free_code(code.code);
	printf("test11 ok\n");
}

static void test12(void)
{
	// Test rewriteable jumps
	executable_code code;
	struct sljit_compiler* compiler = sljit_create_compiler();
	struct sljit_label *label1;
	struct sljit_label *label2;
	struct sljit_label *label3;
	struct sljit_jump *jump1;
	struct sljit_jump *jump2;
	struct sljit_jump *jump3;
	sljit_uw jump1_addr;
	sljit_uw label1_addr;
	sljit_uw label2_addr;
	sljit_w buf[1];

	FAILED(!compiler, "cannot create compiler\n");
	buf[0] = 0;

	T(sljit_emit_enter(compiler, 2, 2, 0));
	T(sljit_emit_op2(compiler, SLJIT_SUB, SLJIT_NO_REG, 0, SLJIT_GENERAL_REG2, 0, SLJIT_IMM, 10));
	jump1 = sljit_emit_jump(compiler, SLJIT_LONG_JUMP | SLJIT_C_SIG_GREATER);
	T(compiler->error);
	// Default handler
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0, SLJIT_IMM, 5));
	jump2 = sljit_emit_jump(compiler, SLJIT_JUMP);
	T(compiler->error);
	// Handler 1
	label1 = sljit_emit_label(compiler);
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0, SLJIT_IMM, 6));
	jump3 = sljit_emit_jump(compiler, SLJIT_JUMP);
	T(compiler->error);
	// Handler 2
	label2 = sljit_emit_label(compiler);
	T(compiler->error);
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0, SLJIT_IMM, 7));
	// Exit
	label3 = sljit_emit_label(compiler);
	T(compiler->error);
	sljit_set_label(jump2, label3);
	sljit_set_label(jump3, label3);
	// By default, set to handler 1
	sljit_set_label(jump1, label1);
	T(sljit_emit_return(compiler, SLJIT_NO_REG));

	code.code = sljit_generate_code(compiler);
#ifdef SLJIT_INDIRECT_CALL
	code.code_ptr = &code.code;
#endif
	FAILED(!code.code, "code generation error\n");
	jump1_addr = sljit_get_jump_addr(jump1);
	label1_addr = sljit_get_label_addr(label1);
	label2_addr = sljit_get_label_addr(label2);
	sljit_free_compiler(compiler);

	code.func2((sljit_w)&buf, 4);
	FAILED(buf[0] != 5, "test12 case 1 failed\n");

	code.func2((sljit_w)&buf, 11);
	FAILED(buf[0] != 6, "test12 case 2 failed\n");

	sljit_set_jump_addr(jump1_addr, label2_addr);
	code.func2((sljit_w)&buf, 12);
	FAILED(buf[0] != 7, "test12 case 3 failed\n");

	sljit_set_jump_addr(jump1_addr, label1_addr);
	code.func2((sljit_w)&buf, 13);
	FAILED(buf[0] != 6, "test12 case 4 failed\n");

	sljit_free_code(code.code);
	printf("test12 ok\n");
}

static void test13(void)
{
	// Test fpu monadic functions
	executable_code code;
	struct sljit_compiler* compiler = sljit_create_compiler();
	double buf[6];

	if (!sljit_is_fpu_available()) {
		printf("no fpu available, test13 skipped\n");
		return;
	}

	FAILED(!compiler, "cannot create compiler\n");
	buf[0] = 7.75;
	buf[1] = -4.5;
	buf[2] = 0.0;
	buf[3] = 0.0;
	buf[4] = 0.0;
	buf[5] = 0.0;

	T(sljit_emit_enter(compiler, 1, 1, 0));
	sljit_emit_fop1(compiler, SLJIT_FMOV, SLJIT_MEM0(), (sljit_w)&buf[2], SLJIT_MEM0(), (sljit_w)&buf[1]);
	sljit_emit_fop1(compiler, SLJIT_FABS, SLJIT_MEM1(SLJIT_GENERAL_REG1), 3 * sizeof(double), SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(double));
	sljit_emit_fop1(compiler, SLJIT_FMOV, SLJIT_FLOAT_REG1, 0, SLJIT_MEM0(), (sljit_w)&buf[0]);
	sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 2 * sizeof(double));
	sljit_emit_fop1(compiler, SLJIT_FMOV, SLJIT_FLOAT_REG2, 0, SLJIT_MEM2(SLJIT_GENERAL_REG1, SLJIT_TEMPORARY_REG1), 0);
	sljit_emit_fop1(compiler, SLJIT_FNEG, SLJIT_FLOAT_REG3, 0, SLJIT_FLOAT_REG1, 0);
	sljit_emit_fop1(compiler, SLJIT_FMOV, SLJIT_FLOAT_REG4, 0, SLJIT_FLOAT_REG3, 0);
	sljit_emit_fop1(compiler, SLJIT_FMOV, SLJIT_MEM0(), (sljit_w)&buf[4], SLJIT_FLOAT_REG4, 0);
	sljit_emit_fop1(compiler, SLJIT_FABS, SLJIT_FLOAT_REG3, 0, SLJIT_FLOAT_REG2, 0);
	sljit_emit_fop1(compiler, SLJIT_FMOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), 5 * sizeof(double), SLJIT_FLOAT_REG3, 0);

	T(sljit_emit_return(compiler, SLJIT_NO_REG));

	code.code = sljit_generate_code(compiler);
#ifdef SLJIT_INDIRECT_CALL
	code.code_ptr = &code.code;
#endif
	FAILED(!code.code, "code generation error\n");
	sljit_free_compiler(compiler);

	code.func1((sljit_w)&buf);
	FAILED(buf[2] != -4.5, "test13 case 1 failed\n");
	FAILED(buf[3] != 4.5, "test13 case 2 failed\n");
	FAILED(buf[4] != -7.75, "test13 case 3 failed\n");
	FAILED(buf[5] != 4.5, "test13 case 4 failed\n");

	sljit_free_code(code.code);
	printf("test13 ok\n");
}

static void test14(void)
{
	// Test fpu diadic functions
	executable_code code;
	struct sljit_compiler* compiler = sljit_create_compiler();
	double buf[15];

	if (!sljit_is_fpu_available()) {
		printf("no fpu available, test14 skipped\n");
		return;
	}
	buf[0] = 7.25;
	buf[1] = 3.5;
	buf[2] = 1.75;
	buf[3] = 0.0;
	buf[4] = 0.0;
	buf[5] = 0.0;
	buf[6] = 0.0;
	buf[7] = 0.0;
	buf[8] = 0.0;
	buf[9] = 0.0;
	buf[10] = 0.0;
	buf[11] = 0.0;
	buf[12] = 8.0;
	buf[13] = 4.0;
	buf[14] = 0.0;

	FAILED(!compiler, "cannot create compiler\n");
	T(sljit_emit_enter(compiler, 1, 1, 0));

	// ADD
	sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, sizeof(double));
	sljit_emit_fop1(compiler, SLJIT_FMOV, SLJIT_FLOAT_REG1, 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(double));
	sljit_emit_fop1(compiler, SLJIT_FMOV, SLJIT_FLOAT_REG2, 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(double) * 2);
	sljit_emit_fop2(compiler, SLJIT_FADD, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(double) * 3, SLJIT_MEM2(SLJIT_GENERAL_REG1, SLJIT_TEMPORARY_REG1), 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0);
	sljit_emit_fop2(compiler, SLJIT_FADD, SLJIT_FLOAT_REG1, 0, SLJIT_FLOAT_REG1, 0, SLJIT_FLOAT_REG2, 0);
	sljit_emit_fop2(compiler, SLJIT_FADD, SLJIT_FLOAT_REG2, 0, SLJIT_FLOAT_REG1, 0, SLJIT_FLOAT_REG2, 0);
	sljit_emit_fop1(compiler, SLJIT_FMOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(double) * 4, SLJIT_FLOAT_REG1, 0);
	sljit_emit_fop1(compiler, SLJIT_FMOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(double) * 5, SLJIT_FLOAT_REG2, 0);

	// SUB
	sljit_emit_fop1(compiler, SLJIT_FMOV, SLJIT_FLOAT_REG3, 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0);
	sljit_emit_fop1(compiler, SLJIT_FMOV, SLJIT_FLOAT_REG4, 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(double) * 2);
	sljit_emit_fop2(compiler, SLJIT_FSUB, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(double) * 6, SLJIT_FLOAT_REG4, 0, SLJIT_MEM2(SLJIT_GENERAL_REG1, SLJIT_TEMPORARY_REG1), sizeof(double));
	sljit_emit_fop2(compiler, SLJIT_FSUB, SLJIT_FLOAT_REG3, 0, SLJIT_FLOAT_REG3, 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(double) * 2);
	sljit_emit_fop2(compiler, SLJIT_FSUB, SLJIT_FLOAT_REG4, 0, SLJIT_FLOAT_REG3, 0, SLJIT_FLOAT_REG4, 0);
	sljit_emit_fop1(compiler, SLJIT_FMOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(double) * 7, SLJIT_FLOAT_REG3, 0);
	sljit_emit_fop1(compiler, SLJIT_FMOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(double) * 8, SLJIT_FLOAT_REG4, 0);

	// MUL
	sljit_emit_fop2(compiler, SLJIT_FMUL, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(double) * 9, SLJIT_MEM2(SLJIT_GENERAL_REG1, SLJIT_TEMPORARY_REG1), 0, SLJIT_FLOAT_REG2, 0);
	sljit_emit_fop2(compiler, SLJIT_FMUL, SLJIT_FLOAT_REG2, 0, SLJIT_FLOAT_REG2, 0, SLJIT_FLOAT_REG3, 0);
	sljit_emit_fop2(compiler, SLJIT_FMUL, SLJIT_FLOAT_REG3, 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(double) * 2, SLJIT_FLOAT_REG3, 0);
	sljit_emit_fop1(compiler, SLJIT_FMOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(double) * 10, SLJIT_FLOAT_REG2, 0);
	sljit_emit_fop1(compiler, SLJIT_FMOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(double) * 11, SLJIT_FLOAT_REG3, 0);

	// DIV
	sljit_emit_fop1(compiler, SLJIT_FMOV, SLJIT_FLOAT_REG1, 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(double) * 12);
	sljit_emit_fop1(compiler, SLJIT_FMOV, SLJIT_FLOAT_REG2, 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(double) * 13);
	sljit_emit_fop1(compiler, SLJIT_FMOV, SLJIT_FLOAT_REG3, 0, SLJIT_FLOAT_REG1, 0);
	sljit_emit_fop2(compiler, SLJIT_FDIV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(double) * 12, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(double) * 12, SLJIT_FLOAT_REG2, 0);
	sljit_emit_fop2(compiler, SLJIT_FDIV, SLJIT_FLOAT_REG1, 0, SLJIT_FLOAT_REG1, 0, SLJIT_FLOAT_REG2, 0);
	sljit_emit_fop2(compiler, SLJIT_FDIV, SLJIT_FLOAT_REG3, 0, SLJIT_FLOAT_REG2, 0, SLJIT_FLOAT_REG3, 0);
	sljit_emit_fop1(compiler, SLJIT_FMOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(double) * 13, SLJIT_FLOAT_REG1, 0);
	sljit_emit_fop1(compiler, SLJIT_FMOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(double) * 14, SLJIT_FLOAT_REG3, 0);

	T(sljit_emit_return(compiler, SLJIT_NO_REG));

	code.code = sljit_generate_code(compiler);
#ifdef SLJIT_INDIRECT_CALL
	code.code_ptr = &code.code;
#endif
	FAILED(!code.code, "code generation error\n");
	sljit_free_compiler(compiler);

	code.func1((sljit_w)&buf);
	FAILED(buf[3] != 10.75, "test14 case 1 failed\n");
	FAILED(buf[4] != 5.25, "test14 case 2 failed\n");
	FAILED(buf[5] != 7.0, "test14 case 3 failed\n");
	FAILED(buf[6] != 0.0, "test14 case 4 failed\n");
	FAILED(buf[7] != 5.5, "test14 case 5 failed\n");
	FAILED(buf[8] != 3.75, "test14 case 6 failed\n");
	FAILED(buf[9] != 24.5, "test14 case 7 failed\n");
	FAILED(buf[10] != 38.5, "test14 case 8 failed\n");
	FAILED(buf[11] != 9.625, "test14 case 9 failed\n");
	FAILED(buf[12] != 2.0, "test14 case 10 failed\n");
	FAILED(buf[13] != 2.0, "test14 case 11 failed\n");
	FAILED(buf[14] != 0.5, "test14 case 11 failed\n");

	sljit_free_code(code.code);
	printf("test14 ok\n");
}

static sljit_w SLJIT_CALL func(sljit_w a, sljit_w b)
{
	return a + b + 5;
}

static void test15(void)
{
	// Test function call
	executable_code code;
	struct sljit_compiler* compiler = sljit_create_compiler();
	sljit_w buf[2];

	FAILED(!compiler, "cannot create compiler\n");
	buf[0] = 0;
	buf[1] = 0;

	T(sljit_emit_enter(compiler, 1, 1, 0));

	sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 5);
	sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG2, 0, SLJIT_IMM, 7);
	sljit_emit_ijump(compiler, SLJIT_CALL2, SLJIT_IMM, (sljit_w)&func);
	sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0, SLJIT_PREF_RET_REG, 0);

	sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 10);
	sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG2, 0, SLJIT_IMM, 16);
	sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG3, 0, SLJIT_IMM, (sljit_w)&func);
	sljit_emit_ijump(compiler, SLJIT_CALL2, SLJIT_TEMPORARY_REG3, 0);
	sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w), SLJIT_PREF_RET_REG, 0);

	T(sljit_emit_return(compiler, SLJIT_PREF_RET_REG));

	code.code = sljit_generate_code(compiler);
#ifdef SLJIT_INDIRECT_CALL
	code.code_ptr = &code.code;
#endif
	FAILED(!code.code, "code generation error\n");
	sljit_free_compiler(compiler);

	FAILED(code.func1((sljit_w)&buf) != 31, "test15 case 1 failed\n");
	FAILED(buf[0] != 17, "test15 case 2 failed\n");
	FAILED(buf[1] != 31, "test15 case 3 failed\n");

	sljit_free_code(code.code);
	printf("test15 ok\n");
}

static void test16(void)
{
	// Ackermann benchmark
	executable_code code;
	struct sljit_compiler* compiler = sljit_create_compiler();
	struct sljit_label *entry;
	struct sljit_label *label;
	struct sljit_jump *jump;
	struct sljit_jump *jump1;
	struct sljit_jump *jump2;

	FAILED(!compiler, "cannot create compiler\n");

	entry = sljit_emit_label(compiler);
	T(sljit_emit_enter(compiler, 2, 2, 0));
	// if x == 0
	T(sljit_emit_op2(compiler, SLJIT_SUB, SLJIT_NO_REG, 0, SLJIT_GENERAL_REG1, 0, SLJIT_IMM, 0));
	jump1 = sljit_emit_jump(compiler, SLJIT_C_EQUAL); TP(jump1);
	// if y == 0
	T(sljit_emit_op2(compiler, SLJIT_SUB, SLJIT_NO_REG, 0, SLJIT_GENERAL_REG2, 0, SLJIT_IMM, 0));
	jump2 = sljit_emit_jump(compiler, SLJIT_C_EQUAL); TP(jump2);

	// Ack(x,y-1)
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_GENERAL_REG1, 0));
	T(sljit_emit_op2(compiler, SLJIT_SUB, SLJIT_TEMPORARY_REG2, 0, SLJIT_GENERAL_REG2, 0, SLJIT_IMM, 1));
	jump = sljit_emit_jump(compiler, SLJIT_CALL2); TP(jump);
	sljit_set_label(jump, entry);

	// return Ack(x-1, Ack(x,y-1))
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG2, 0, SLJIT_PREF_RET_REG, 0));
	T(sljit_emit_op2(compiler, SLJIT_SUB, SLJIT_TEMPORARY_REG1, 0, SLJIT_GENERAL_REG1, 0, SLJIT_IMM, 1));
	jump = sljit_emit_jump(compiler, SLJIT_CALL2); TP(jump);
	sljit_set_label(jump, entry);
	T(sljit_emit_return(compiler, SLJIT_PREF_RET_REG));

	// return y+1
	label = sljit_emit_label(compiler); TP(label);
	sljit_set_label(jump1, label);
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_PREF_RET_REG, 0, SLJIT_GENERAL_REG2, 0, SLJIT_IMM, 1));
	T(sljit_emit_return(compiler, SLJIT_PREF_RET_REG));

	// return Ack(x-1,1)
	label = sljit_emit_label(compiler); TP(label);
	sljit_set_label(jump2, label);
	T(sljit_emit_op2(compiler, SLJIT_SUB, SLJIT_TEMPORARY_REG1, 0, SLJIT_GENERAL_REG1, 0, SLJIT_IMM, 1));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG2, 0, SLJIT_IMM, 1));
	jump = sljit_emit_jump(compiler, SLJIT_CALL2); TP(jump);
	sljit_set_label(jump, entry);
	T(sljit_emit_return(compiler, SLJIT_PREF_RET_REG));

	code.code = sljit_generate_code(compiler);
#ifdef SLJIT_INDIRECT_CALL
	code.code_ptr = &code.code;
#endif
	FAILED(!code.code, "code generation error\n");
	sljit_free_compiler(compiler);

	FAILED(code.func2(3, 3) != 61, "test16 case 1 failed\n");
	// For benchmarking
	//FAILED(code.func2(3, 11) != 16381, "test16 case 1 failed\n");

	sljit_free_code(code.code);
	printf("test16 ok\n");
}

static void test17(void)
{
	// Test arm constant pool
	executable_code code;
	struct sljit_compiler* compiler = sljit_create_compiler();
	int i;
	sljit_w buf[5];

	FAILED(!compiler, "cannot create compiler\n");
	buf[0] = 0;
	buf[1] = 0;
	buf[2] = 0;
	buf[3] = 0;
	buf[4] = 0;

	T(sljit_emit_enter(compiler, 1, 1, 0));
	for (i = 0; i <= 0xfff; i++) {
		T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 0x81818000 | i));
		T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 0x81818000 | i));
		if ((i & 0x3ff) == 0)
			T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), (i >> 10) * sizeof(sljit_w), SLJIT_TEMPORARY_REG1, 0));
	}
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), 4 * sizeof(sljit_w), SLJIT_TEMPORARY_REG1, 0));
	T(sljit_emit_return(compiler, SLJIT_NO_REG));

	code.code = sljit_generate_code(compiler);
#ifdef SLJIT_INDIRECT_CALL
	code.code_ptr = &code.code;
#endif
	FAILED(!code.code, "code generation error\n");
	sljit_free_compiler(compiler);

	code.func1((sljit_w)&buf);
	FAILED(buf[0] != 0x81818000, "test17 case 1 failed\n");
	FAILED(buf[1] != 0x81818400, "test17 case 2 failed\n");
	FAILED(buf[2] != 0x81818800, "test17 case 3 failed\n");
	FAILED(buf[3] != 0x81818c00, "test17 case 4 failed\n");
	FAILED(buf[4] != 0x81818fff, "test17 case 5 failed\n");

	sljit_free_code(code.code);
	printf("test17 ok\n");
}

static void test18(void)
{
	// Test 64 bit
	executable_code code;
	struct sljit_compiler* compiler = sljit_create_compiler();
	sljit_w buf[11];

	FAILED(!compiler, "cannot create compiler\n");
	buf[0] = 0;
	buf[1] = 0;
	buf[2] = 0;
	buf[3] = 0;
	buf[4] = 0;
	buf[5] = 100;
	buf[6] = 100;
	buf[7] = 100;
	buf[8] = 100;
	buf[9] = 0;
	buf[10] = 1;

	T(sljit_emit_enter(compiler, 1, 2, 0));

#ifdef SLJIT_CONFIG_X86_64
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0, SLJIT_IMM, 0x1122334455667788));
	T(sljit_emit_op1(compiler, SLJIT_MOV | SLJIT_32BIT_OPERATION, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w), SLJIT_IMM, 0x1122334455667788));

	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 1000000000000));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 2, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 1000000000000));
	T(sljit_emit_op2(compiler, SLJIT_SUB, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 3, SLJIT_IMM, 5000000000000, SLJIT_TEMPORARY_REG1, 0));

	T(sljit_emit_op1(compiler, SLJIT_MOV | SLJIT_32BIT_OPERATION, SLJIT_TEMPORARY_REG2, 0, SLJIT_IMM, 0x1108080808));
	T(sljit_emit_op2(compiler, SLJIT_ADD | SLJIT_32BIT_OPERATION, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 4, SLJIT_TEMPORARY_REG2, 0, SLJIT_IMM, 0x1120202020));

	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 0x1108080808));
	T(sljit_emit_op2(compiler, SLJIT_AND, SLJIT_NO_REG, 0, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 0x1120202020));
	T(sljit_emit_cond_set(compiler, SLJIT_GENERAL_REG2, 0, SLJIT_C_ZERO));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 5, SLJIT_GENERAL_REG2, 0));
	T(sljit_emit_op2(compiler, SLJIT_AND | SLJIT_32BIT_OPERATION, SLJIT_NO_REG, 0, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 0x1120202020));
	T(sljit_emit_cond_set(compiler, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 6, SLJIT_C_ZERO));

	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 0x1108080808));
	T(sljit_emit_op2(compiler, SLJIT_SUB, SLJIT_NO_REG, 0, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 0x2208080808));
	T(sljit_emit_cond_set(compiler, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 7, SLJIT_C_LESS));
	T(sljit_emit_op2(compiler, SLJIT_AND | SLJIT_32BIT_OPERATION, SLJIT_NO_REG, 0, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 0x2208080808));
	T(sljit_emit_cond_set(compiler, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 8, SLJIT_C_LESS));

	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 4));
	T(sljit_emit_op2(compiler, SLJIT_SHL | SLJIT_32BIT_OPERATION, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 9, SLJIT_IMM, 0xffff0000, SLJIT_TEMPORARY_REG1, 0));

	T(sljit_emit_op2(compiler, SLJIT_MUL | SLJIT_32BIT_OPERATION, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 10, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 10, SLJIT_IMM, -1));
#else
	// 32 bit operations

	T(sljit_emit_op1(compiler, SLJIT_MOV | SLJIT_32BIT_OPERATION, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0, SLJIT_IMM, 0x11223344));
	T(sljit_emit_op2(compiler, SLJIT_ADD | SLJIT_32BIT_OPERATION, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w), SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w), SLJIT_IMM, 0x44332211));

#endif

	T(sljit_emit_return(compiler, SLJIT_NO_REG));

	code.code = sljit_generate_code(compiler);
#ifdef SLJIT_INDIRECT_CALL
	code.code_ptr = &code.code;
#endif
	FAILED(!code.code, "code generation error\n");
	sljit_free_compiler(compiler);

	code.func1((sljit_w)&buf);
#ifdef SLJIT_CONFIG_X86_64
	FAILED(buf[0] != 0x1122334455667788, "test18 case 1 failed\n");
	FAILED(buf[1] != 0x55667788, "test18 case 2 failed\n");
	FAILED(buf[2] != 2000000000000, "test18 case 3 failed\n");
	FAILED(buf[3] != 4000000000000, "test18 case 4 failed\n");
	FAILED(buf[4] != 0x28282828, "test18 case 5 failed\n");
	FAILED(buf[5] != 0, "test18 case 6 failed\n");
	FAILED(buf[6] != 1, "test18 case 7 failed\n");
	FAILED(buf[7] != 1, "test18 case 8 failed\n");
	FAILED(buf[8] != 0, "test18 case 9 failed\n");
	FAILED(buf[9] != 0xfff00000, "test18 case 10 failed\n");
	FAILED(buf[10] != 0xffffffff, "test18 case 11 failed\n");
#else
	FAILED(buf[0] != 0x11223344, "test18 case 1 failed\n");
	FAILED(buf[1] != 0x44332211, "test18 case 2 failed\n");
#endif

	sljit_free_code(code.code);
	printf("test18 ok\n");
}

static void test19(void)
{
	// Test arm partial instruction caching
	executable_code code;
	struct sljit_compiler* compiler = sljit_create_compiler();
	sljit_w buf[10];

	FAILED(!compiler, "cannot create compiler\n");
	buf[0] = 6;
	buf[1] = 4;
	buf[2] = 0;
	buf[3] = 0;
	buf[4] = 0;
	buf[5] = 0;
	buf[6] = 2;
	buf[7] = 0;

	T(sljit_emit_enter(compiler, 1, 1, 0));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w)));
#ifdef SLJIT_CONFIG_ARM
	SLJIT_ASSERT(compiler->cache_arg == 0);
#endif
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_MEM0(), (sljit_w)&buf[2], SLJIT_MEM0(), (sljit_w)&buf[1], SLJIT_MEM0(), (sljit_w)&buf[0]));
#ifdef SLJIT_CONFIG_ARM
	SLJIT_ASSERT(compiler->cache_arg > 0);
#endif
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG2, 0, SLJIT_IMM, sizeof(sljit_w)));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 3, SLJIT_MEM1(SLJIT_TEMPORARY_REG1), (sljit_w)&buf[0], SLJIT_MEM1(SLJIT_TEMPORARY_REG2), (sljit_w)&buf[0]));
#ifdef SLJIT_CONFIG_ARM
	SLJIT_ASSERT(compiler->cache_arg > 0);
#endif
	T(sljit_emit_op2(compiler, SLJIT_SUB, SLJIT_MEM2(SLJIT_GENERAL_REG1, SLJIT_TEMPORARY_REG2), sizeof(sljit_w) * 3, SLJIT_MEM2(SLJIT_GENERAL_REG1, SLJIT_TEMPORARY_REG2), -(sljit_w)sizeof(sljit_w), SLJIT_IMM, 2));
#ifdef SLJIT_CONFIG_ARM
	SLJIT_ASSERT(compiler->cache_arg > 0);
#endif
	T(sljit_emit_op2(compiler, SLJIT_SUB, SLJIT_MEM2(SLJIT_GENERAL_REG1, SLJIT_TEMPORARY_REG2), sizeof(sljit_w) * 4, SLJIT_MEM2(SLJIT_GENERAL_REG1, SLJIT_TEMPORARY_REG2), sizeof(sljit_w), SLJIT_MEM2(SLJIT_GENERAL_REG1, SLJIT_TEMPORARY_REG1), 4 * sizeof(sljit_w)));
#ifdef SLJIT_CONFIG_ARM
	SLJIT_ASSERT(compiler->cache_arg > 0);
#endif
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 7, SLJIT_IMM, 10));
	// The last SLJIT_MEM2 is intentionally reversed
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_MEM2(SLJIT_TEMPORARY_REG2, SLJIT_TEMPORARY_REG1), (sljit_w)&buf[5], SLJIT_MEM2(SLJIT_TEMPORARY_REG2, SLJIT_TEMPORARY_REG1), (sljit_w)&buf[6], SLJIT_MEM2(SLJIT_TEMPORARY_REG1, SLJIT_TEMPORARY_REG2), (sljit_w)&buf[5]));
#ifdef SLJIT_CONFIG_ARM
	SLJIT_ASSERT(compiler->cache_arg > 0);
#endif

	T(sljit_emit_return(compiler, SLJIT_NO_REG));

	code.code = sljit_generate_code(compiler);
#ifdef SLJIT_INDIRECT_CALL
	code.code_ptr = &code.code;
#endif
	FAILED(!code.code, "code generation error\n");
	sljit_free_compiler(compiler);

	code.func1((sljit_w)&buf);
	FAILED(buf[0] != 10, "test19 case 1 failed\n");
	FAILED(buf[1] != 4, "test19 case 2 failed\n");
	FAILED(buf[2] != 14, "test19 case 3 failed\n");
	FAILED(buf[3] != 14, "test19 case 4 failed\n");
	FAILED(buf[4] != 8, "test19 case 5 failed\n");
	FAILED(buf[5] != 6, "test19 case 6 failed\n");
	FAILED(buf[6] != 12, "test19 case 7 failed\n");
	FAILED(buf[7] != 10, "test19 case 8 failed\n");

	sljit_free_code(code.code);
	printf("test19 ok\n");
}

static void test20(void)
{
	// Test stack
	executable_code code;
	struct sljit_compiler* compiler = sljit_create_compiler();
	sljit_w buf[4];

	FAILED(!compiler, "cannot create compiler\n");
	buf[0] = 5;
	buf[1] = 12;
	buf[2] = 0;
	buf[3] = 0;

	T(sljit_emit_enter(compiler, 1, 2, 4 * sizeof(sljit_w)));

	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_TEMPORARY_REG1, 0, SLJIT_IMM, sizeof(sljit_uw)));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM2(SLJIT_STACK_PTR_REG, SLJIT_TEMPORARY_REG1), 0, SLJIT_MEM1(SLJIT_GENERAL_REG1), 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM2(SLJIT_STACK_PTR_REG, SLJIT_TEMPORARY_REG1), -(int)sizeof(sljit_uw), SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_uw)));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_GENERAL_REG1), 2 * sizeof(sljit_uw), SLJIT_MEM1(SLJIT_STACK_PTR_REG), sizeof(sljit_uw)));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_MEM1(SLJIT_GENERAL_REG1), 3 * sizeof(sljit_uw), SLJIT_MEM2(SLJIT_TEMPORARY_REG1, SLJIT_STACK_PTR_REG), 0, SLJIT_MEM1(SLJIT_STACK_PTR_REG), 0));

	T(sljit_emit_return(compiler, SLJIT_PREF_RET_REG));

	code.code = sljit_generate_code(compiler);
#ifdef SLJIT_INDIRECT_CALL
	code.code_ptr = &code.code;
#endif
	FAILED(!code.code, "code generation error\n");
	sljit_free_compiler(compiler);

	code.func1((sljit_w)&buf);

	FAILED(buf[2] != 5, "test20 case 1 failed\n");
	FAILED(buf[3] != 17, "test20 case 2 failed\n");

	sljit_free_code(code.code);
	printf("test20 ok\n");
}

static void test21(void)
{
	// Test fake enter. The parts of the jit code can
	// be separated in the memory
	executable_code code1;
	executable_code code2;
	struct sljit_compiler* compiler = sljit_create_compiler();
	struct sljit_jump* jump;
	sljit_uw addr;
	sljit_w buf[4];

	FAILED(!compiler, "cannot create compiler\n");
	buf[0] = 9;
	buf[1] = -6;
	buf[2] = 0;
	buf[3] = 0;

	T(sljit_emit_enter(compiler, 1, 2, 2 * sizeof(sljit_w)));

	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_MEM1(SLJIT_STACK_PTR_REG), 0, SLJIT_IMM, 10));
	T(sljit_emit_op2(compiler, SLJIT_ADD, SLJIT_MEM1(SLJIT_STACK_PTR_REG), sizeof(sljit_w), SLJIT_MEM1(SLJIT_GENERAL_REG1), 0, SLJIT_MEM1(SLJIT_STACK_PTR_REG), 0));
	jump = sljit_emit_jump(compiler, SLJIT_JUMP | SLJIT_LONG_JUMP);
	T(compiler->error);
	sljit_set_target(jump, 0);

	code1.code = sljit_generate_code(compiler);
#ifdef SLJIT_INDIRECT_CALL
	code1.code_ptr = &code1.code;
#endif
	FAILED(!code1.code, "code generation error\n");
	addr = sljit_get_jump_addr(jump);
	sljit_free_compiler(compiler);

	compiler = sljit_create_compiler();
	FAILED(!compiler, "cannot create compiler\n");

	// Other part of the jit code
	sljit_fake_enter(compiler, 1, 2, 2 * sizeof(sljit_w));

	T(sljit_emit_op2(compiler, SLJIT_SUB, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 2, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w), SLJIT_MEM1(SLJIT_STACK_PTR_REG), 0));
	T(sljit_emit_op2(compiler, SLJIT_MUL, SLJIT_MEM1(SLJIT_GENERAL_REG1), sizeof(sljit_w) * 3, SLJIT_MEM1(SLJIT_STACK_PTR_REG), 0, SLJIT_MEM1(SLJIT_STACK_PTR_REG), 0));
	T(sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_PREF_RET_REG, 0, SLJIT_MEM1(SLJIT_STACK_PTR_REG), sizeof(sljit_w)));

	T(sljit_emit_return(compiler, SLJIT_PREF_RET_REG));

	code2.code = sljit_generate_code(compiler);
#ifdef SLJIT_INDIRECT_CALL
	code2.code_ptr = &code2.code;
#endif
	FAILED(!code2.code, "code generation error\n");
	sljit_free_compiler(compiler);

	sljit_set_jump_addr(addr, (sljit_uw)code2.code);

	FAILED(code1.func1((sljit_w)&buf) != 19, "test21 case 1 failed\n");
	FAILED(buf[2] != -16, "test21 case 2 failed\n");
	FAILED(buf[3] != 100, "test21 case 3 failed\n");

	sljit_free_code(code1.code);
	sljit_free_code(code2.code);
	printf("test21 ok\n");
}

void sljit_test(void)
{
	test1();
	test2();
	test3();
	test4();
	test5();
	test6();
	test7();
	test8();
	test9();
	test10();
	test11();
	test12();
	test13();
	test14();
	test15();
	test16();
	test17();
	test18();
	test19();
	test20();
	test21();
}

