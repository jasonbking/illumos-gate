/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

#include <sys/debug.h>
#include "tpm_ddi.h"

uint32_t
tpm_cc(const tpm_cmd_t *cmd)
{
	return (BE_IN32(&cmd->tcmd_buf[TPM_COMMAND_CODE_OFFSET]));
}

uint32_t
tpm_cmdlen(const tpm_cmd_t *cmd)
{
	return (BE_IN32(&cmd->tcmd_buf[TPM_PARAMSIZE_OFFSET]));
}

uint16_t
tpm_tag(const tpm_cmd_t *cmd)
{
	return (BE_IN16(&cmd->tcmd_buf[TPM_TAG_OFFSET]));
}

uint16_t
tpm_getbuf16(const tpm_cmd_t *cmd, uint32_t offset)
{
	VERIFY3U(offset, <, tpm_cmdlen(cmd));
	return (BE_IN16(&cmd->tcmd_buf[offset]));
}

uint32_t
tpm_getbuf32(const tpm_cmd_t *cmd, uint32_t offset)
{
	VERIFY3U(offset, <, tpm_cmdlen(cmd));
	return (BE_IN32(&cmd->tcmd_buf[offset]));
}

void
tpm_cmd_getbuf(const tpm_cmd_t *cmd, uint32_t offset, uint32_t len, void *dst)
{
	uint32_t cmdlen = tpm_cmdlen(cmd);
	VERIFY3U(offset, <, cmdlen);
	VERIFY3U(offset + len, <, cmdlen);

	bcopy(cmd->tcmd_buf + offset, dst, len);
}

uint16_t
tpm_cmd_sess(const tpm_cmd_t *cmd)
{
	return (BE_IN16(&cmd->tcmd_buf[0]));
}

uint32_t
tpm_cmd_rc(const tpm_cmd_t *cmd)
{
	return (BE_IN32(&cmd->tcmd_buf[TPM_RETURN_OFFSET]));
}

void
tpm_cmd_init(tpm_cmd_t *cmd, uint32_t code, uint16_t sessions)
{
	uint8_t *buf = cmd->tcmd_buf;

	bzero(buf, sizeof (cmd->tcmd_buf));

	BE_OUT16(buf, sessions);
	buf += sizeof (uint16_t);

	/* The initial length is just the size of the header */
	BE_OUT32(buf, TPM_HEADER_SIZE);
	buf += sizeof (uint32_t);

	BE_OUT32(buf, code);
}

void
tpm_cmd_resp(tpm_cmd_t *cmd, uint32_t rc, uint16_t sess)
{
	return (tpm_cmd_init(cmd, rc, sess));
}

static void
tpm_cmd_setlen(tpm_cmd_t *cmd, uint32_t len)
{
	uint8_t *ptr = &cmd->tcmd_buf[TPM_PARAMSIZE_OFFSET];

	BE_OUT32(ptr, len);
}

void
tpm_cmd_put8(tpm_cmd_t *cmd, uint8_t val)
{
	uint32_t len = tpm_cmdlen(cmd);

	VERIFY3U(len + sizeof (val), <, sizeof (cmd->tcmd_buf));
	cmd->tcmd_buf[len++] = val;
	tpm_cmd_setlen(cmd, len);
}

void
tpm_cmd_put16(tpm_cmd_t *cmd, uint16_t val)
{
	uint32_t len = tpm_cmdlen(cmd);
	uint8_t *ptr = &cmd->tcmd_buf[len];

	VERIFY3U(len + sizeof (val), <, sizeof (cmd->tcmd_buf));
	BE_OUT16(ptr, len);
	len += sizeof (val);
	tpm_cmd_setlen(cmd, len);
}

void
tpm_cmd_put32(tpm_cmd_t *cmd, uint32_t val)
{
	uint32_t len = tpm_cmdlen(cmd);
	uint8_t *ptr = &cmd->tcmd_buf[len];

	VERIFY3U(len + sizeof (val), <, sizeof (cmd->tcmd_buf));
	BE_OUT32(ptr, len);
	len += sizeof (val);
	tpm_cmd_setlen(cmd, len);
}

void
tpm_cmd_copy(tpm_cmd_t *cmd, const void *src, uint32_t srclen)
{
	uint32_t len = tpm_cmdlen(cmd);
	uint8_t *ptr = &cmd->tcmd_buf[len];

	VERIFY3U(len + srclen, <, sizeof (cmd->tcmd_buf));
	bcopy(src, ptr, srclen);
	len += srclen;
	tpm_cmd_setlen(cmd, len);
}

void
trdr_init(tpm_cmd_reader_t *r, tpm_cmd_t *cmd)
{
	r->tcr_buf = cmd->tcmd_buf + TPM_HEADER_SIZE;
	r->tcr_remaining = tpm_cmdlen(cmd) - TPM_HEADER_SIZE;
}

bool
trdr_get8(tpm_cmd_reader_t *r, uint8_t *vp)
{
	if (r->tcr_remaining == 0) {
		return (false);
	}

	if (vp != NULL) {
		*vp = *r->tcr_buf;
	}

	r->tcr_buf++;
	r->tcr_remaining--;
	return (true);
}

bool
trdr_get16(tpm_cmd_reader_t *r, uint16_t *vp)
{
	if (r->tcr_remaining < sizeof (uint16_t)) {
		return (false);
	}

	if (vp != NULL) {
		*vp = BE_IN16(r->tcr_buf);
	}

	r->tcr_buf += sizeof (uint16_t);
	r->tcr_remaining -= sizeof (uint16_t);
	return (true);
}

bool
trdr_get32(tpm_cmd_reader_t *r, uint32_t *vp)
{
	if (r->tcr_remaining < sizeof (uint32_t)) {
		return (false);
	}

	if (vp != NULL) {
		*vp = BE_IN32(r->tcr_buf);
	}

	r->tcr_buf += sizeof (uint32_t);
	r->tcr_remaining -= sizeof (uint32_t);
	return (true);
}

bool
trdr_skip(tpm_cmd_reader_t *r, uint32_t amt)
{
	if (r->tcr_remaining < amt) {
		return (false);
	}

	r->tcr_buf += amt;
	r->tcr_remaining -= amt;
	return (true);
}
