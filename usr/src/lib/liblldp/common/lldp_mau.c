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
 * Map mac_ether_media_t (sys/mac_ether.h) values to the IANA dot3MauType
 * values (the last arc of the dot3MauType OID) from IANA-MAU-MIB
 * (https://www.iana.org/assignments/ianamau-mib), as used in the
 * Operational MAU Type field of the IEEE 802.3 MAC/PHY
 * Configuration/Status TLV.
 *
 * Where IANA defines separate half- and full-duplex MAU types for a
 * medium (e.g. dot3MauType1000BaseSXHD / dot3MauType1000BaseSXFD), the
 * full-duplex type is used, since mac_ether_media_t doesn't distinguish
 * duplex and essentially every modern link is full duplex.
 *
 * Media are mapped to the MAU type of the same name where one exists.
 * Media that aren't an IEEE 802.3 PMD (direct attach cables, active
 * optical cables, chip-to-chip/module interfaces like SFI or CAUI-4,
 * non-IEEE variants like 50GBASE-KR2) are mapped to the generic MAU type
 * for their PCS (e.g. dot3MauType10GigBaseR, "R PCS/PMA, unknown PMD")
 * when there is one. Anything else is LLDP_MAU_UNKNOWN (0).
 *
 * The switch below deliberately has no default case, so that the
 * compiler flags any media type added to mac_ether_media_t without a
 * corresponding entry here.
 */

#include <liblldp.h>

uint16_t
lldp_ether_media_to_mau(mac_ether_media_t media)
{
	switch (media) {
	case ETHER_MEDIA_UNKNOWN:
	case ETHER_MEDIA_NONE:
		return (LLDP_MAU_UNKNOWN);

	/* 10 Mbit/s */
	case ETHER_MEDIA_10BASE_T:
		return (11);		/* dot3MauType10BaseTFD */
	case ETHER_MEDIA_10BASE_T1:
		/* Could be 10BASE-T1L or one of the 10BASE-T1S types */
		return (LLDP_MAU_UNKNOWN);

	/* 100 Mbit/s */
	case ETHER_MEDIA_100BASE_T4:
		return (14);		/* dot3MauType100BaseT4 */
	case ETHER_MEDIA_100BASE_TX:
		return (16);		/* dot3MauType100BaseTXFD */
	case ETHER_MEDIA_100BASE_FX:
		return (18);		/* dot3MauType100BaseFXFD */
	case ETHER_MEDIA_100BASE_T2:
		return (20);		/* dot3MauType100BaseT2FD */
	case ETHER_MEDIA_100BASE_T1:
		return (105);		/* dot3MauType100baseT1 */
	case ETHER_MEDIA_100BASE_X:
	case ETHER_MEDIA_100_SGMII:
		return (LLDP_MAU_UNKNOWN);

	/* 1 Gbit/s */
	case ETHER_MEDIA_1000BASE_X:
		return (22);		/* dot3MauType1000BaseXFD */
	case ETHER_MEDIA_1000BASE_LX:
		return (24);		/* dot3MauType1000BaseLXFD */
	case ETHER_MEDIA_1000BASE_SX:
		return (26);		/* dot3MauType1000BaseSXFD */
	case ETHER_MEDIA_1000BASE_CX:
		return (28);		/* dot3MauType1000BaseCXFD */
	case ETHER_MEDIA_1000BASE_T:
		return (30);		/* dot3MauType1000BaseTFD */
	case ETHER_MEDIA_1000BASE_KX:
		return (56);		/* dot3MauType1000baseKX */
	case ETHER_MEDIA_1000BASE_T1:
		return (79);		/* dot3MauType1000baseT1 */
	case ETHER_MEDIA_1000BASE_BX:
		/* MAU types are per-direction (BX10-D/BX10-U) */
	case ETHER_MEDIA_1000_SGMII:
		return (LLDP_MAU_UNKNOWN);

	/* 2.5 and 5 Gbit/s */
	case ETHER_MEDIA_2500BASE_T:
		return (103);		/* dot3MauType2p5GigT */
	case ETHER_MEDIA_2500BASE_KX:
		return (109);		/* dot3MauType2p5GbaseKX */
	case ETHER_MEDIA_2500BASE_X:
		return (110);		/* dot3MauType2p5GbaseX */
	case ETHER_MEDIA_5000BASE_T:
		return (104);		/* dot3MauType5GigT */
	case ETHER_MEDIA_5000BASE_KR:
		return (111);		/* dot3MauType5GbaseKR */

	/* 10 Gbit/s */
	case ETHER_MEDIA_10GBASE_T:
		return (54);		/* dot3MauType10GbaseT */
	case ETHER_MEDIA_10GBASE_SR:
		return (36);		/* dot3MauType10GigBaseSR */
	case ETHER_MEDIA_10GBASE_LR:
		return (35);		/* dot3MauType10GigBaseLR */
	case ETHER_MEDIA_10GBASE_LRM:
		return (55);		/* dot3MauType10GbaseLRM */
	case ETHER_MEDIA_10GBASE_ER:
		return (34);		/* dot3MauType10GigBaseER */
	case ETHER_MEDIA_10GBASE_KR:
		return (58);		/* dot3MauType10GbaseKR */
	case ETHER_MEDIA_10GBASE_CX4:
		return (41);		/* dot3MauType10GigBaseCX4 */
	case ETHER_MEDIA_10GBASE_KX4:
		return (57);		/* dot3MauType10GbaseKX4 */
	case ETHER_MEDIA_10G_XAUI:
		return (31);		/* dot3MauType10GigBaseX */
	case ETHER_MEDIA_10GBASE_AOC:
	case ETHER_MEDIA_10GBASE_ACC:
	case ETHER_MEDIA_10GBASE_CR:
	case ETHER_MEDIA_10G_SFI:
	case ETHER_MEDIA_10G_XFI:
		return (33);		/* dot3MauType10GigBaseR */

	/* 25 Gbit/s */
	case ETHER_MEDIA_25GBASE_T:
		return (94);		/* dot3MauType25GbaseT */
	case ETHER_MEDIA_25GBASE_SR:
		return (93);		/* dot3MauType25GbaseSR */
	case ETHER_MEDIA_25GBASE_LR:
		return (114);		/* dot3MauType25GbaseLR */
	case ETHER_MEDIA_25GBASE_ER:
		return (115);		/* dot3MauType25GbaseER */
	case ETHER_MEDIA_25GBASE_KR:
		return (90);		/* dot3MauType25GbaseKR */
	case ETHER_MEDIA_25GBASE_CR:
		return (88);		/* dot3MauType25GbaseCR */
	case ETHER_MEDIA_25GBASE_AOC:
	case ETHER_MEDIA_25GBASE_ACC:
	case ETHER_MEDIA_25G_AUI:
		return (92);		/* dot3MauType25GbaseR */

	/* 40 Gbit/s */
	case ETHER_MEDIA_40GBASE_T:
		return (97);		/* dot3MauType40GbaseT */
	case ETHER_MEDIA_40GBASE_CR4:
		return (71);		/* dot3MauType40GbaseCR4 */
	case ETHER_MEDIA_40GBASE_KR4:
		return (70);		/* dot3MauType40GbaseKR4 */
	case ETHER_MEDIA_40GBASE_LR4:
		return (74);		/* dot3MauType40GbaseLR4 */
	case ETHER_MEDIA_40GBASE_SR4:
		return (72);		/* dot3MauType40GbaseSR4 */
	case ETHER_MEDIA_40GBASE_ER4:
		return (95);		/* dot3MauType40GbaseER4 */
	case ETHER_MEDIA_40GBASE_LM4:
	case ETHER_MEDIA_40GBASE_AOC4:
	case ETHER_MEDIA_40GBASE_ACC4:
	case ETHER_MEDIA_40G_XLAUI:
	case ETHER_MEDIA_40G_XLPPI:
		return (96);		/* dot3MauType40GbaseR */

	/* 50 Gbit/s */
	case ETHER_MEDIA_50GBASE_KR:
		return (118);		/* dot3MauType50GbaseKR */
	case ETHER_MEDIA_50GBASE_CR:
		return (117);		/* dot3MauType50GbaseCR */
	case ETHER_MEDIA_50GBASE_SR:
		return (119);		/* dot3MauType50GbaseSR */
	case ETHER_MEDIA_50GBASE_LR:
		return (121);		/* dot3MauType50GbaseLR */
	case ETHER_MEDIA_50GBASE_FR:
		return (120);		/* dot3MauType50GbaseFR */
	case ETHER_MEDIA_50GBASE_ER:
		return (122);		/* dot3MauType50GbaseER */
	case ETHER_MEDIA_50GBASE_KR2:
	case ETHER_MEDIA_50GBASE_CR2:
	case ETHER_MEDIA_50GBASE_SR2:
	case ETHER_MEDIA_50GBASE_LR2:
	case ETHER_MEDIA_50GBASE_AOC2:
	case ETHER_MEDIA_50GBASE_ACC2:
	case ETHER_MEDIA_50GBASE_AOC:
	case ETHER_MEDIA_50GBASE_ACC:
		return (116);		/* dot3MauType50GbaseR */

	/* 100 Gbit/s */
	case ETHER_MEDIA_100GBASE_CR10:
		return (75);		/* dot3MauType100GbaseCR10 */
	case ETHER_MEDIA_100GBASE_SR10:
		return (76);		/* dot3MauType100GbaseSR10 */
	case ETHER_MEDIA_100GBASE_SR4:
		return (102);		/* dot3MauType100GbaseSR4 */
	case ETHER_MEDIA_100GBASE_LR4:
		return (77);		/* dot3MauType100GbaseLR4 */
	case ETHER_MEDIA_100GBASE_ER4:
		return (78);		/* dot3MauType100GbaseER4 */
	case ETHER_MEDIA_100GBASE_KR4:
		return (99);		/* dot3MauType100GbaseKR4 */
	case ETHER_MEDIA_100GBASE_CR4:
		return (98);		/* dot3MauType100GbaseCR4 */
	case ETHER_MEDIA_100GBASE_KR2:
		return (124);		/* dot3MauType100GbaseKR2 */
	case ETHER_MEDIA_100GBASE_CR2:
		return (123);		/* dot3MauType100GbaseCR2 */
	case ETHER_MEDIA_100GBASE_SR2:
		return (125);		/* dot3MauType100GbaseSR2 */
	case ETHER_MEDIA_100GBASE_DR:
		return (126);		/* dot3MauType100GbaseDR */
	case ETHER_MEDIA_100GBASE_LR:
		return (146);		/* dot3MauType100GbaseLR1 */
	case ETHER_MEDIA_100GBASE_FR:
		return (145);		/* dot3MauType100GbaseFR1 */
	case ETHER_MEDIA_100GBASE_CAUI4:
	case ETHER_MEDIA_100GBASE_AOC4:
	case ETHER_MEDIA_100GBASE_ACC4:
	case ETHER_MEDIA_100GBASE_KR:
	case ETHER_MEDIA_100GBASE_CR:
	case ETHER_MEDIA_100GBASE_SR:
		return (101);		/* dot3MauType100GbaseR */

	/* 200 Gbit/s */
	case ETHER_MEDIA_200GBASE_CR4:
		return (131);		/* dot3MauType200GbaseCR4 */
	case ETHER_MEDIA_200GBASE_KR4:
		return (132);		/* dot3MauType200GbaseKR4 */
	case ETHER_MEDIA_200GBASE_SR4:
		return (133);		/* dot3MauType200GbaseSR4 */
	case ETHER_MEDIA_200GBASE_DR4:
		return (128);		/* dot3MauType200GbaseDR4 */
	case ETHER_MEDIA_200GBASE_FR4:
		return (129);		/* dot3MauType200GbaseFR4 */
	case ETHER_MEDIA_200GBASE_LR4:
		return (130);		/* dot3MauType200GbaseLR4 */
	case ETHER_MEDIA_200GBASE_ER4:
		return (134);		/* dot3MauType200GbaseER4 */
	case ETHER_MEDIA_200GAUI_4:
	case ETHER_MEDIA_200GAUI_2:
	case ETHER_MEDIA_200GBASE_KR2:
	case ETHER_MEDIA_200GBASE_CR2:
	case ETHER_MEDIA_200GBASE_SR2:
		return (127);		/* dot3MauType200GbaseR */

	/* 400 Gbit/s */
	case ETHER_MEDIA_400GBASE_FR8:
		return (138);		/* dot3MauType400GbaseFR8 */
	case ETHER_MEDIA_400GBASE_LR8:
		return (139);		/* dot3MauType400GbaseLR8 */
	case ETHER_MEDIA_400GBASE_ER8:
		return (140);		/* dot3MauType400GbaseER8 */
	case ETHER_MEDIA_400GBASE_DR4:
		return (137);		/* dot3MauType400GbaseDR4 */
	case ETHER_MEDIA_400GBASE_FR4:
		return (147);		/* dot3MauType400GbaseFR4 */
	case ETHER_MEDIA_400GAUI_8:
	case ETHER_MEDIA_400GBASE_KR8:
	case ETHER_MEDIA_400GAUI_4:
	case ETHER_MEDIA_400GBASE_KR4:
	case ETHER_MEDIA_400GBASE_CR4:
	case ETHER_MEDIA_400GBASE_SR4:
		/*
		 * 400GBASE-SR4 (802.3db) is not 400GBASE-SR4.2, and there
		 * are no MAU types for the others.
		 */
		return (135);		/* dot3MauType400GbaseR */
	}

	return (LLDP_MAU_UNKNOWN);
}
