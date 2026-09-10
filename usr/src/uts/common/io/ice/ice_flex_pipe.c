/* SPDX-License-Identifier: BSD-3-Clause */
/*  Copyright (c) 2024, Intel Corporation
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *   1. Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *   3. Neither the name of the Intel Corporation nor the names of its
 *      contributors may be used to endorse or promote products derived from
 *      this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright 2026 RackTop Systems, Inc.
 */

#include "ice.h"

static const uint32_t
ice_sect_lkup[ICE_BLK_COUNT][ICE_SECT_COUNT] = {
	/* SWITCH */
	{
		ICE_SID_XLT0_SW,
		ICE_SID_XLT_KEY_BUILDER_SW,
		ICE_SID_XLT1_SW,
		ICE_SID_XLT2_SW,
		ICE_SID_PROFID_TCAM_SW,
		ICE_SID_PROFID_REDIR_SW,
		ICE_SID_FLD_VEC_SW,
		ICE_SID_CDID_KEY_BUILDER_SW,
		ICE_SID_CDID_REDIR_SW
	},

	/* ACL */
	{
		ICE_SID_XLT0_ACL,
		ICE_SID_XLT_KEY_BUILDER_ACL,
		ICE_SID_XLT1_ACL,
		ICE_SID_XLT2_ACL,
		ICE_SID_PROFID_TCAM_ACL,
		ICE_SID_PROFID_REDIR_ACL,
		ICE_SID_FLD_VEC_ACL,
		ICE_SID_CDID_KEY_BUILDER_ACL,
		ICE_SID_CDID_REDIR_ACL
	},

	/* FD */
	{
		ICE_SID_XLT0_FD,
		ICE_SID_XLT_KEY_BUILDER_FD,
		ICE_SID_XLT1_FD,
		ICE_SID_XLT2_FD,
		ICE_SID_PROFID_TCAM_FD,
		ICE_SID_PROFID_REDIR_FD,
		ICE_SID_FLD_VEC_FD,
		ICE_SID_CDID_KEY_BUILDER_FD,
		ICE_SID_CDID_REDIR_FD
	},

	/* RSS */
	{
		ICE_SID_XLT0_RSS,
		ICE_SID_XLT_KEY_BUILDER_RSS,
		ICE_SID_XLT1_RSS,
		ICE_SID_XLT2_RSS,
		ICE_SID_PROFID_TCAM_RSS,
		ICE_SID_PROFID_REDIR_RSS,
		ICE_SID_FLD_VEC_RSS,
		ICE_SID_CDID_KEY_BUILDER_RSS,
		ICE_SID_CDID_REDIR_RSS
	},

	/* PE */
	{
		ICE_SID_XLT0_PE,
		ICE_SID_XLT_KEY_BUILDER_PE,
		ICE_SID_XLT1_PE,
		ICE_SID_XLT2_PE,
		ICE_SID_PROFID_TCAM_PE,
		ICE_SID_PROFID_REDIR_PE,
		ICE_SID_FLD_VEC_PE,
		ICE_SID_CDID_KEY_BUILDER_PE,
		ICE_SID_CDID_REDIR_PE
	}
};

typedef struct ice_blk_size_details {
	uint16_t ibsd_xlt1;		/* # XLT1 entries */
	uint16_t ibsd_xlt2;		/* # XLT2 entries */
	uint16_t ibsd_prof_tcam;	/* # profile ID TCAM entries */
	uint16_t ibsd_prof_id;		/* # profile IDs */
	uint8_t ibsd_prof_cdid_bits;	/* # CDID one-hot bits used in key */
	uint16_t ibsd_prof_redir;	/* # profile redirection entries */
	uint16_t ibsd_es;		/* # extraction sequence entries */
	uint16_t ibsd_fvw;		/* # field vector words */
	uint8_t ibsd_overwrite;		/* overwrite existing entries allowed */
	uint8_t ibsd_reverse;		/* reverse FV order */
} ice_blk_size_details_t;

static const ice_blk_size_details_t blk_sizes[ICE_BLK_COUNT] = {
        /*
         * Table Definitions
         * XLT1 - Number of entries in XLT1 table
         * XLT2 - Number of entries in XLT2 table
         * TCAM - Number of entries Profile ID TCAM table
         * CDID - Control Domain ID of the hardware block
         * PRED - Number of entries in the Profile Redirection Table
         * FV   - Number of entries in the Field Vector
         * FVW  - Width (in WORDs) of the Field Vector
         * OVR  - Overwrite existing table entries
         * REV  - Reverse FV
         */
        /*          XLT1        , XLT2        ,TCAM, PID,CDID,PRED,   FV, FVW */
        /*          Overwrite   , Reverse FV */
        /* SW  */ { ICE_XLT1_CNT, ICE_XLT2_CNT, 512, 256,   0,  256, 256,  48,
                    false, false },
        /* ACL */ { ICE_XLT1_CNT, ICE_XLT2_CNT, 512, 128,   0,  128, 128,  32,
                    false, false },
        /* FD  */ { ICE_XLT1_CNT, ICE_XLT2_CNT, 512, 128,   0,  128, 128,  24,
                    false, true  },
        /* RSS */ { ICE_XLT1_CNT, ICE_XLT2_CNT, 512, 128,   0,  128, 128,  24,
                    true,  true  },
        /* PE  */ { ICE_XLT1_CNT, ICE_XLT2_CNT,  64,  32,   0,   32,  32,  24,
                    false, false },
};

static uint32_t
ice_sect_id(ice_block_t blk, ice_sect_t sect)
{
	return (ice_sect_lkup[blk][sect];
}


