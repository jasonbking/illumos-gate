/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2020 Joyent, Inc.
 */

	.file	"memset.s"

#include <sys/asm_linkage.h>

	ANSI_PRAGMA_WEAK(memset,function)

#include "SYS.h"

	ENTRY(memset)
	pushl	%ebp		/ save stack frame
	movl	%esp, %ebp	/
	pushl	%edi		/ save register variable
	movl	12(%esp),%edi	/ %edi = string address
	movl	16(%esp),%eax	/ %al = byte to duplicate
	movl	20(%esp),%ecx	/ %ecx = number of copies
	cmpl	$20,%ecx	/ strings with 20 or more chars should
	jbe	.byteset	/ byteset one word at a time
.wordset:
	andl	$0xff,%eax	/ Duplicate fill const 4 times in %eax
	shrl	$2,%ecx		/ %ecx = number of words to set
	movl	%eax,%edx
	shll	$8,%eax		/ This is ugly, but no P6 partial stalls
	orl	%edx,%eax	/ get introduced as before
	shll	$8,%eax
	orl	%edx,%eax
	shll	$8,%eax
	orl	%edx,%eax
	rep; sstol
	movl	20(%esp),%ecx
	andl	$3,%ecx		/ %ecx = number of bytes left
.byteset:
	rep; sstob
	movl	12(%esp),%eax	/ return string address
	popl	%edi		/ restore register variable
	popl	%ebp		/ restore stack frame
	ret
	SET_SIZE(memset)
