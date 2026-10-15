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

/*
 * Copyright 2026 Jason King
 */

/*
 * Names for the IANA dot3MauType values (the last arc of the dot3MauType
 * OID) from IANA-MAU-MIB (https://www.iana.org/assignments/ianamau-mib), as
 * received in the Operational MAU Type field of the IEEE 802.3 MAC/PHY
 * Configuration/Status TLV. (lldp_ether_media_to_mau(), in lldp_mau.c, maps
 * the other way, from our media types to MAU types.)
 *
 * The names follow those libdladm uses for the 'media' link property
 * (dladm_ether_media_vals[], from mac_ether_media_t), so the same medium
 * reads the same in 'dladm show-linkprop' and 'lldp show-neighbors': e.g.
 * '1000BASE-T', '10GBASE-SR', '2500BASE-T' (IEEE's 2.5GBASE-T), and
 * '100GBASE-KR' (IEEE's 100GBASE-KR1). For MAU types with no corresponding
 * media type, the IEEE 802.3 name is used, written the same way (2.5 and 5
 * Gbit/s single-rate PHYs as 2500 and 5000, as dladm does).
 *
 * Where IANA defines separate half- and full-duplex MAU types for a medium
 * (e.g. dot3MauType1000BaseTHD and dot3MauType1000BaseTFD), both have the
 * medium's name, and the duplex is returned separately; 10BASE-T1S also has
 * a multidrop mode. The duplex of any other MAU type isn't specified by the
 * type itself (most are full duplex only).
 *
 * The values through 214 are from their OBJECT-IDENTITY definitions; those
 * from 215 on are from the IANAifMauTypeListBits names (bit N corresponds
 * to dot3MauType N), current as of the 2026-07-15 revision of the MIB.
 */

#include <stddef.h>
#include <sys/sysmacros.h>
#include <liblldp.h>

typedef struct mau_name {
	const char	*mn_name;
	lldp_mau_mode_t	mn_mode;
} mau_name_t;

#define	HD	LLDP_MAU_MODE_HALF
#define	FD	LLDP_MAU_MODE_FULL
#define	MD	LLDP_MAU_MODE_MULTIDROP

static const mau_name_t mau_names[] = {
	[1] =	{ "AUI" },
	[2] =	{ "10BASE5" },
	[3] =	{ "FOIRL" },
	[4] =	{ "10BASE2" },
	[5] =	{ "10BASE-T" },
	[6] =	{ "10BASE-FP" },
	[7] =	{ "10BASE-FB" },
	[8] =	{ "10BASE-FL" },
	[9] =	{ "10BROAD36" },
	[10] =	{ "10BASE-T", HD },
	[11] =	{ "10BASE-T", FD },
	[12] =	{ "10BASE-FL", HD },
	[13] =	{ "10BASE-FL", FD },
	[14] =	{ "100BASE-T4" },
	[15] =	{ "100BASE-TX", HD },
	[16] =	{ "100BASE-TX", FD },
	[17] =	{ "100BASE-FX", HD },
	[18] =	{ "100BASE-FX", FD },
	[19] =	{ "100BASE-T2", HD },
	[20] =	{ "100BASE-T2", FD },
	[21] =	{ "1000BASE-X", HD },
	[22] =	{ "1000BASE-X", FD },
	[23] =	{ "1000BASE-LX", HD },
	[24] =	{ "1000BASE-LX", FD },
	[25] =	{ "1000BASE-SX", HD },
	[26] =	{ "1000BASE-SX", FD },
	[27] =	{ "1000BASE-CX", HD },
	[28] =	{ "1000BASE-CX", FD },
	[29] =	{ "1000BASE-T", HD },
	[30] =	{ "1000BASE-T", FD },
	[31] =	{ "10GBASE-X" },
	[32] =	{ "10GBASE-LX4" },
	[33] =	{ "10GBASE-R" },
	[34] =	{ "10GBASE-ER" },
	[35] =	{ "10GBASE-LR" },
	[36] =	{ "10GBASE-SR" },
	[37] =	{ "10GBASE-W" },
	[38] =	{ "10GBASE-EW" },
	[39] =	{ "10GBASE-LW" },
	[40] =	{ "10GBASE-SW" },
	[41] =	{ "10GBASE-CX4" },
	[42] =	{ "2BASE-TL" },
	[43] =	{ "10PASS-TS" },
	[44] =	{ "100BASE-BX10-D" },
	[45] =	{ "100BASE-BX10-U" },
	[46] =	{ "100BASE-LX10" },
	[47] =	{ "1000BASE-BX10-D" },
	[48] =	{ "1000BASE-BX10-U" },
	[49] =	{ "1000BASE-LX10" },
	[50] =	{ "1000BASE-PX10-D" },
	[51] =	{ "1000BASE-PX10-U" },
	[52] =	{ "1000BASE-PX20-D" },
	[53] =	{ "1000BASE-PX20-U" },
	[54] =	{ "10GBASE-T" },
	[55] =	{ "10GBASE-LRM" },
	[56] =	{ "1000BASE-KX" },
	[57] =	{ "10GBASE-KX4" },
	[58] =	{ "10GBASE-KR" },
	[59] =	{ "10/1GBASE-PRX-D1" },
	[60] =	{ "10/1GBASE-PRX-D2" },
	[61] =	{ "10/1GBASE-PRX-D3" },
	[62] =	{ "10/1GBASE-PRX-U1" },
	[63] =	{ "10/1GBASE-PRX-U2" },
	[64] =	{ "10/1GBASE-PRX-U3" },
	[65] =	{ "10GBASE-PR-D1" },
	[66] =	{ "10GBASE-PR-D2" },
	[67] =	{ "10GBASE-PR-D3" },
	[68] =	{ "10GBASE-PR-U1" },
	[69] =	{ "10GBASE-PR-U3" },
	[70] =	{ "40GBASE-KR4" },
	[71] =	{ "40GBASE-CR4" },
	[72] =	{ "40GBASE-SR4" },
	[73] =	{ "40GBASE-FR" },
	[74] =	{ "40GBASE-LR4" },
	[75] =	{ "100GBASE-CR10" },
	[76] =	{ "100GBASE-SR10" },
	[77] =	{ "100GBASE-LR4" },
	[78] =	{ "100GBASE-ER4" },
	[79] =	{ "1000BASE-T1" },
	[80] =	{ "1000BASE-PX30-D" },
	[81] =	{ "1000BASE-PX30-U" },
	[82] =	{ "1000BASE-PX40-D" },
	[83] =	{ "1000BASE-PX40-U" },
	[84] =	{ "10/1GBASE-PRX-D4" },
	[85] =	{ "10/1GBASE-PRX-U4" },
	[86] =	{ "10GBASE-PR-D4" },
	[87] =	{ "10GBASE-PR-U4" },
	[88] =	{ "25GBASE-CR" },
	[89] =	{ "25GBASE-CR-S" },
	[90] =	{ "25GBASE-KR" },
	[91] =	{ "25GBASE-KR-S" },
	[92] =	{ "25GBASE-R" },
	[93] =	{ "25GBASE-SR" },
	[94] =	{ "25GBASE-T" },
	[95] =	{ "40GBASE-ER4" },
	[96] =	{ "40GBASE-R" },
	[97] =	{ "40GBASE-T" },
	[98] =	{ "100GBASE-CR4" },
	[99] =	{ "100GBASE-KR4" },
	[100] =	{ "100GBASE-KP4" },
	[101] =	{ "100GBASE-R" },
	[102] =	{ "100GBASE-SR4" },
	[103] =	{ "2500BASE-T" },
	[104] =	{ "5000BASE-T" },
	[105] =	{ "100BASE-T1" },
	[106] =	{ "1000BASE-RHA" },
	[107] =	{ "1000BASE-RHB" },
	[108] =	{ "1000BASE-RHC" },
	[109] =	{ "2500BASE-KX" },
	[110] =	{ "2500BASE-X" },
	[111] =	{ "5000BASE-KR" },
	[112] =	{ "5000BASE-R" },
	[113] =	{ "10GPASS-XR" },
	[114] =	{ "25GBASE-LR" },
	[115] =	{ "25GBASE-ER" },
	[116] =	{ "50GBASE-R" },
	[117] =	{ "50GBASE-CR" },
	[118] =	{ "50GBASE-KR" },
	[119] =	{ "50GBASE-SR" },
	[120] =	{ "50GBASE-FR" },
	[121] =	{ "50GBASE-LR" },
	[122] =	{ "50GBASE-ER" },
	[123] =	{ "100GBASE-CR2" },
	[124] =	{ "100GBASE-KR2" },
	[125] =	{ "100GBASE-SR2" },
	[126] =	{ "100GBASE-DR" },
	[127] =	{ "200GBASE-R" },
	[128] =	{ "200GBASE-DR4" },
	[129] =	{ "200GBASE-FR4" },
	[130] =	{ "200GBASE-LR4" },
	[131] =	{ "200GBASE-CR4" },
	[132] =	{ "200GBASE-KR4" },
	[133] =	{ "200GBASE-SR4" },
	[134] =	{ "200GBASE-ER4" },
	[135] =	{ "400GBASE-R" },
	[136] =	{ "400GBASE-SR16" },
	[137] =	{ "400GBASE-DR4" },
	[138] =	{ "400GBASE-FR8" },
	[139] =	{ "400GBASE-LR8" },
	[140] =	{ "400GBASE-ER8" },
	[141] =	{ "10BASE-T1L" },
	[142] =	{ "10BASE-T1S", HD },
	[143] =	{ "10BASE-T1S", MD },
	[144] =	{ "10BASE-T1S", FD },
	[145] =	{ "100GBASE-FR" },	/* 100GBASE-FR1 */
	[146] =	{ "100GBASE-LR" },	/* 100GBASE-LR1 */
	[147] =	{ "400GBASE-FR4" },
	[148] =	{ "400GBASE-LR4-6" },
	[149] =	{ "400GBASE-SR8" },
	[150] =	{ "400GBASE-SR4.2" },
	[151] =	{ "2500BASE-T1" },
	[152] =	{ "5000BASE-T1" },
	[153] =	{ "10GBASE-T1" },
	[154] =	{ "25/10GBASE-PQG-D2" },
	[155] =	{ "25/10GBASE-PQG-D3" },
	[156] =	{ "25/10GBASE-PQG-U2" },
	[157] =	{ "25/10GBASE-PQG-U3" },
	[158] =	{ "25/10GBASE-PQX-D2" },
	[159] =	{ "25/10GBASE-PQX-D3" },
	[160] =	{ "25/10GBASE-PQX-U2" },
	[161] =	{ "25/10GBASE-PQX-U3" },
	[162] =	{ "25GBASE-PQG-D2" },
	[163] =	{ "25GBASE-PQG-D3" },
	[164] =	{ "25GBASE-PQG-U2" },
	[165] =	{ "25GBASE-PQG-U3" },
	[166] =	{ "25GBASE-PQX-D2" },
	[167] =	{ "25GBASE-PQX-D3" },
	[168] =	{ "25GBASE-PQX-U2" },
	[169] =	{ "25GBASE-PQX-U3" },
	[170] =	{ "50/10GBASE-PQG-D2" },
	[171] =	{ "50/10GBASE-PQG-D3" },
	[172] =	{ "50/10GBASE-PQG-U2" },
	[173] =	{ "50/10GBASE-PQG-U3" },
	[174] =	{ "50/10GBASE-PQX-D2" },
	[175] =	{ "50/10GBASE-PQX-D3" },
	[176] =	{ "50/10GBASE-PQX-U2" },
	[177] =	{ "50/10GBASE-PQX-U3" },
	[178] =	{ "50/25GBASE-PQG-D2" },
	[179] =	{ "50/25GBASE-PQG-D3" },
	[180] =	{ "50/25GBASE-PQG-U2" },
	[181] =	{ "50/25GBASE-PQG-U3" },
	[182] =	{ "50/25GBASE-PQX-D2" },
	[183] =	{ "50/25GBASE-PQX-D3" },
	[184] =	{ "50/25GBASE-PQX-U2" },
	[185] =	{ "50/25GBASE-PQX-U3" },
	[186] =	{ "50GBASE-PQG-D2" },
	[187] =	{ "50GBASE-PQG-D3" },
	[188] =	{ "50GBASE-PQG-U2" },
	[189] =	{ "50GBASE-PQG-U3" },
	[190] =	{ "50GBASE-PQX-D2" },
	[191] =	{ "50GBASE-PQX-D3" },
	[192] =	{ "50GBASE-PQX-U2" },
	[193] =	{ "50GBASE-PQX-U3" },
	[194] =	{ "100GBASE-ZR" },
	[195] =	{ "10GBASE-BR10-D" },
	[196] =	{ "10GBASE-BR10-U" },
	[197] =	{ "10GBASE-BR20-D" },
	[198] =	{ "10GBASE-BR20-U" },
	[199] =	{ "10GBASE-BR40-D" },
	[200] =	{ "10GBASE-BR40-U" },
	[201] =	{ "25GBASE-BR10-D" },
	[202] =	{ "25GBASE-BR10-U" },
	[203] =	{ "25GBASE-BR20-D" },
	[204] =	{ "25GBASE-BR20-U" },
	[205] =	{ "25GBASE-BR40-D" },
	[206] =	{ "25GBASE-BR40-U" },
	[207] =	{ "50GBASE-BR10-D" },
	[208] =	{ "50GBASE-BR10-U" },
	[209] =	{ "50GBASE-BR20-D" },
	[210] =	{ "50GBASE-BR20-U" },
	[211] =	{ "50GBASE-BR40-D" },
	[212] =	{ "50GBASE-BR40-U" },
	[213] =	{ "2500BASE-AU" },
	[214] =	{ "5000BASE-AU" },
	[215] =	{ "10GBASE-AU" },
	[216] =	{ "25GBASE-AU" },
	[217] =	{ "50GBASE-AU" },
	[218] =	{ "25GBASE-T1" },
	[219] =	{ "400GBASE-DR4-2" },
	[220] =	{ "800GBASE-CR8" },
	[221] =	{ "800GBASE-DR8" },
	[222] =	{ "800GBASE-DR8-2" },
	[223] =	{ "800GBASE-KR8" },
	[224] =	{ "800GBASE-R" },
	[225] =	{ "800GBASE-SR8" },
	[226] =	{ "800GBASE-VR8" },
	[227] =	{ "10GBASE-SP1-D" },
	[228] =	{ "10GBASE-SP1-U" },
	[229] =	{ "10/2.5GBASE-SP1-D" },
	[230] =	{ "10/2.5GBASE-SP1-U" },
	[231] =	{ "100GBASE-SR" },	/* 100GBASE-SR1 */
	[232] =	{ "100GBASE-VR1" },
	[233] =	{ "200GBASE-SR2" },
	[234] =	{ "200GBASE-VR2" },
	[235] =	{ "400GBASE-SR4" },
	[236] =	{ "400GBASE-VR4" },
	[237] =	{ "100GBASE-CR" },	/* 100GBASE-CR1 */
	[238] =	{ "100GBASE-KR" },	/* 100GBASE-KR1 */
	[239] =	{ "200GBASE-CR2" },
	[240] =	{ "200GBASE-KR2" },
	[241] =	{ "400GBASE-CR4" },
	[242] =	{ "400GBASE-KR4" },
	[243] =	{ "10BASE-T1M" },
	[244] =	{ "100GBASE-BR10-D" },
	[245] =	{ "100GBASE-BR10-U" },
	[246] =	{ "100GBASE-BR20-D" },
	[247] =	{ "100GBASE-BR20-U" },
	[248] =	{ "100GBASE-BR40-D" },
	[249] =	{ "100GBASE-BR40-U" },
	[250] =	{ "100BASE-T1L" },
};

/*
 * Return the name of a dot3MauType value (e.g. "1000BASE-T"), or NULL if
 * the value isn't one we know (including LLDP_MAU_UNKNOWN). If modep is
 * non-NULL, it's set to the duplex mode the MAU type specifies, if any.
 */
const char *
lldp_mau_str(uint16_t mau, lldp_mau_mode_t *modep)
{
	const mau_name_t *mn;

	if (modep != NULL)
		*modep = LLDP_MAU_MODE_UNSPECIFIED;

	if (mau >= ARRAY_SIZE(mau_names))
		return (NULL);

	mn = &mau_names[mau];
	if (mn->mn_name == NULL)
		return (NULL);

	if (modep != NULL)
		*modep = mn->mn_mode;
	return (mn->mn_name);
}

const char *
lldp_mau_mode_str(lldp_mau_mode_t mode)
{
	switch (mode) {
	case LLDP_MAU_MODE_UNSPECIFIED:
		return (NULL);
	case LLDP_MAU_MODE_HALF:
		return ("half duplex");
	case LLDP_MAU_MODE_FULL:
		return ("full duplex");
	case LLDP_MAU_MODE_MULTIDROP:
		return ("multidrop");
	}
	return (NULL);
}
