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
 * Copyright 2019, Joyent, Inc.
 * Copyright 2026 RackTop Systems, Inc.
 */

/*
 * NVM related functions. At the moment this only has routines that deal with
 * reading and initializing the NVM, it doesn't do anything with writing to it.
 */

#include "ice.h"

/*
 * XXX Not concurrency safe
 */
bool
ice_nvm_read_uint16(ice_t *ice, uint16_t offset, uint16_t *datap)
{
	bool ret;
	uint16_t len = 2;
	uint16_t data;

	if ((ice->ice_nvm.in_flags & ICE_NVM_PRESENT) == 0 ||
	    (ice->ice_nvm.in_flags & ICE_NVM_BLANK) != 0) {
		ice_error(ice, "invalid NVM flags present, can't read NVM");
		return (false);
	}

	if (!ice_cmd_acquire_nvm(ice, false)) {
		ice_error(ice, "failed to acquire NVM");
		return (false);
	}

	ret = ice_cmd_nvm_read(ice, ICE_NVM_MODULE_TYPE_MEMORY, offset * 2,
	    &len, &data, true, false);
	(void) ice_cmd_release_nvm(ice);
	if (ret) {
		*datap = LE_16(data);
	}
	return (ret);
}

/*
 * Attempt to read the PBA string from the NVM.
 */
bool
ice_nvm_read_pba(ice_t *ice)
{
	bool ret;
	uint16_t pba_len, len;
	void *buf;

	if ((ice->ice_nvm.in_flags & ICE_NVM_PRESENT) == 0 ||
	    (ice->ice_nvm.in_flags & ICE_NVM_BLANK) != 0) {
		ice_error(ice, "invalid NVM flags present, can't read NVM");
		return (false);
	}

	if (!ice_cmd_acquire_nvm(ice, false)) {
		ice_error(ice, "failed to acquire NVM");
		return (false);
	}

	len = 2;
	ret = ice_cmd_nvm_read(ice, ICE_NVM_MODULE_TYPE_PBA, 0, &len, &pba_len,
	    false, false);
	if (ret || len != 2 || pba_len == 0) {
		ret = false;
		goto out;
	}

	pba_len--;
	buf = kmem_zalloc(pba_len * 2 + 1, KM_SLEEP);
	len = pba_len * 2;
	ret = ice_cmd_nvm_read(ice, ICE_NVM_MODULE_TYPE_PBA, 2, &len, buf,
	    true, false);
	if (ret || len != pba_len * 2) {
		kmem_free(buf, pba_len * 2 + 1);
		ret = false;
		goto out;
	}

	ice->ice_device->id_pba_len = pba_len * 2 + 1;
	ice->ice_device->id_pba = buf;

out:
	(void) ice_cmd_release_nvm(ice);
	return (ret);
}

void
ice_nvm_fini(ice_t *ice)
{
	ice_nvm_t *nvm = &ice->ice_nvm;
	mutex_destroy(&nvm->in_lock);
}

/*
 * Read a single word from the given absolute (flat) byte offset in flash,
 * bypassing the shadow ram window. The NVM resource must already be held by
 * the caller.
 */
static bool
ice_nvm_read_flash_raw_word(ice_t *ice, uint32_t byte_off, uint16_t *datap)
{
	uint16_t len = 2;
	uint16_t data;

	if (!ice_cmd_nvm_read(ice, ICE_NVM_MODULE_TYPE_MEMORY, byte_off, &len,
	    &data, true, true) || len != 2) {
		return (false);
	}

	*datap = LE_16(data);
	return (true);
}

/*
 * Read an arbitrary length buffer from the given absolute (flat) byte offset
 * in flash, bypassing the shadow ram window, chunking the read so that no
 * individual command crosses a flash sector boundary. The NVM resource must
 * already be held by the caller.
 */
static bool
ice_nvm_read_flash_raw(ice_t *ice, uint32_t byte_off, void *buf,
    uint32_t buflen)
{
	uint8_t *p = buf;

	while (buflen > 0) {
		uint32_t sec_off = byte_off & (ice->ice_nvm.in_sector - 1);
		uint32_t chunk = MIN(buflen,
		    ice->ice_nvm.in_sector - sec_off);
		uint16_t len = (uint16_t)chunk;

		if (!ice_cmd_nvm_read(ice, ICE_NVM_MODULE_TYPE_MEMORY,
		    byte_off, &len, (uint16_t *)(void *)p, true, true) ||
		    len != chunk) {
			return (false);
		}

		p += chunk;
		byte_off += chunk;
		buflen -= chunk;
	}

	return (true);
}

/*
 * Read the shadow ram control word and the given bank pointer/size words,
 * decoding them into a flash bank descriptor. See ICE_SR_NVM_CTRL_WORD and
 * friends in ice_hw.h for details on the encoding.
 */
static bool
ice_nvm_read_bank_info(ice_t *ice, uint16_t ptr_word, uint16_t size_word,
    uint16_t ctrl_bit, ice_flash_bank_t *bankp)
{
	uint16_t ctrl, ptr, size;

	if (!ice_nvm_read_uint16(ice, ICE_SR_NVM_CTRL_WORD, &ctrl)) {
		ice_error(ice, "!failed to read shadow ram control word");
		return (false);
	}

	if (ICE_SR_CTRL_WORD_1(ctrl) != ICE_SR_CTRL_WORD_VALID) {
		ice_error(ice, "!shadow ram control word is invalid");
		return (false);
	}

	if (!ice_nvm_read_uint16(ice, ptr_word, &ptr) ||
	    !ice_nvm_read_uint16(ice, size_word, &size)) {
		ice_error(ice, "!failed to read flash bank pointer/size");
		return (false);
	}

	bankp->ifb_bank2_active = (ctrl & ctrl_bit) != 0;
	if ((ptr & ICE_SR_NVM_PTR_4KB_UNITS) != 0) {
		bankp->ifb_ptr = (uint32_t)(ptr & ~ICE_SR_NVM_PTR_4KB_UNITS) *
		    ICE_NVM_SECTOR_SIZE;
	} else {
		bankp->ifb_ptr = (uint32_t)ptr * 2;
	}
	bankp->ifb_size = (uint32_t)size * ICE_NVM_SECTOR_SIZE;

	return (true);
}

/*
 * Return the absolute (flat) byte offset of the requested (active or
 * inactive) copy of the given flash bank.
 */
static uint32_t
ice_nvm_bank_offset(const ice_flash_bank_t *bankp, ice_bank_select_t which)
{
	bool bank2 = bankp->ifb_bank2_active;

	if (which == ICE_BANK_INACTIVE) {
		bank2 = !bank2;
	}

	return (bankp->ifb_ptr + (bank2 ? bankp->ifb_size : 0));
}

/*
 * The main NVM module (as opposed to the OROM and netlist modules) does not
 * expose its version fields via a fixed flat offset the way those other two
 * do; instead they live in a copy of the shadow ram embedded just after a
 * variable length CSS header at the start of the module. The active bank's
 * copy is also kept in sync with the device's live shadow ram window (which
 * is what ice_nvm_read_uint16() uses), but reading the version out of the
 * inactive bank -- e.g. to see if a pending update has been staged -- can
 * only be done this way. See the datasheet's description of the NVM CSS
 * header for details on the encoding.
 */
static bool
ice_nvm_read_css_hdr_len(ice_t *ice, uint32_t bank_off, uint32_t *hdr_lenp)
{
	uint16_t low, high;

	if (!ice_nvm_read_flash_raw_word(ice,
	    bank_off + ICE_NVM_CSS_HDR_LEN_L * 2, &low) ||
	    !ice_nvm_read_flash_raw_word(ice,
	    bank_off + ICE_NVM_CSS_HDR_LEN_H * 2, &high)) {
		return (false);
	}

	*hdr_lenp = P2ROUNDUP((((uint32_t)high << 16) | low) * 2 +
	    ICE_NVM_AUTH_HEADER_LEN, 32);

	return (true);
}

/*
 * Read a single word from the shadow ram copy embedded in the requested
 * (active or inactive) main NVM module bank. The NVM resource must already
 * be held by the caller.
 */
static bool
ice_nvm_read_sr_copy_word(ice_t *ice, ice_bank_select_t which,
    uint16_t offset, uint16_t *datap)
{
	ice_flash_bank_t *bank = &ice->ice_nvm.in_nvm_bank;
	uint32_t base, hdr_len;

	if (bank->ifb_size == 0) {
		return (false);
	}

	base = ice_nvm_bank_offset(bank, which);

	if (!ice_nvm_read_css_hdr_len(ice, base, &hdr_len)) {
		return (false);
	}

	return (ice_nvm_read_flash_raw_word(ice,
	    base + (hdr_len + offset) * 2, datap));
}

/*
 * Read the NVM Dev Starter Version and EETRACK ID from the requested
 * (active or inactive) main NVM module bank. This is primarily used to
 * expose the version of a pending, but not yet activated, NVM update via
 * UFM, so it's best-effort.
 */
static bool
ice_nvm_read_ver_info(ice_t *ice, ice_bank_select_t which,
    ice_nvm_ver_info_t *verp)
{
	uint16_t low, high;
	bool ret = false;

	if (!ice_cmd_acquire_nvm(ice, false)) {
		return (false);
	}

	if (!ice_nvm_read_sr_copy_word(ice, which, ICE_NVM_DEV_STARTER_VER,
	    &verp->invi_dev_start)) {
		goto out;
	}

	if (!ice_nvm_read_sr_copy_word(ice, which, ICE_NVM_EETRACK_1,
	    &low) ||
	    !ice_nvm_read_sr_copy_word(ice, which, ICE_NVM_EETRACK_2,
	    &high)) {
		goto out;
	}
	verp->invi_eetrack = ((uint32_t)high << 16) | low;

	ret = true;

out:
	(void) ice_cmd_release_nvm(ice);
	return (ret);
}

/*
 * The Option ROM combo image version is stored in a '$CIV' (CIVD) data
 * block that lives somewhere within the active Option ROM bank, aligned to
 * 512 bytes. Scan the bank for it, verifying the simple checksum described
 * in the datasheet.
 */
typedef struct ice_orom_civd {
	uint8_t		icv_sig[4];
	uint8_t		icv_checksum;
	uint32_t	icv_combo_ver;
	uint8_t		icv_name_len;
	uint16_t	icv_name[32];
} __packed ice_orom_civd_t;
CTASSERT(sizeof (ice_orom_civd_t) == 74);

#define	ICE_OROM_CIVD_SCAN_STEP	512

static bool
ice_nvm_find_orom_civd(ice_t *ice, uint32_t orom_off, uint32_t orom_size,
    ice_orom_civd_t *civdp)
{
	uint32_t off;
	bool found = false;

	/*
	 * The Option ROM bank can be many megabytes in size, so scanning it
	 * 512 bytes at a time can require thousands of individual flash
	 * reads. Since we can only hold the NVM resource for a fixed amount
	 * of time, holding it for the entire scan can risk losing the lock
	 * and reads failing with EBUSY.
	 *
	 * Instead, we acquire and release the lock around each read since
	 * that should never exceed the amount of bounded hold time enforced
	 * by the NIC. If we wanted to get fancier, we could track the time
	 * and only drop/reacquire the lock from the HW once we're close to
	 * exceeded the limit, but since this is just used during attach
	 * for reporting the version via UFM, it's probably not worth it
	 * at this time.
	 */
	for (off = 0; off + sizeof (*civdp) <= orom_size;
	    off += ICE_OROM_CIVD_SCAN_STEP) {
		uint32_t sig;
		uint8_t sum = 0;
		uint_t i;
		bool ok;

		if (!ice_cmd_acquire_nvm(ice, false)) {
			break;
		}
		ok = ice_nvm_read_flash_raw(ice, orom_off + off, &sig,
		    sizeof (sig));
		(void) ice_cmd_release_nvm(ice);
		if (!ok) {
			break;
		}

		if (memcmp(&sig, "$CIV", sizeof (sig)) != 0) {
			continue;
		}

		if (!ice_cmd_acquire_nvm(ice, false)) {
			break;
		}
		ok = ice_nvm_read_flash_raw(ice, orom_off + off, civdp,
		    sizeof (*civdp));
		(void) ice_cmd_release_nvm(ice);
		if (!ok) {
			break;
		}

		for (i = 0; i < sizeof (*civdp); i++) {
			sum += ((uint8_t *)civdp)[i];
		}

		if (sum == 0) {
			found = true;
			break;
		}
	}

	return (found);
}

static bool
ice_nvm_read_orom_version(ice_t *ice, ice_bank_select_t which,
    ice_orom_info_t *outp)
{
	ice_flash_bank_t *bank = &ice->ice_nvm.in_orom_bank;
	ice_orom_civd_t civd;
	uint32_t orom_off, combo_ver;

	if (bank->ifb_size == 0) {
		return (false);
	}

	orom_off = ice_nvm_bank_offset(bank, which);

	if (!ice_nvm_find_orom_civd(ice, orom_off, bank->ifb_size, &civd)) {
		/* This is best effort, so emit this as a notice */
		dev_err(ice->ice_dip, CE_NOTE,
		    "!failed to locate Option ROM CIVD data");
		return (false);
	}

	combo_ver = LE_32(civd.icv_combo_ver);
	outp->ioi_major = ICE_OROM_VER_MAJOR(combo_ver);
	outp->ioi_patch = ICE_OROM_VER_PATCH(combo_ver);
	outp->ioi_build = ICE_OROM_VER_BUILD(combo_ver);

	return (true);
}

static bool
ice_nvm_read_netlist_version(ice_t *ice, ice_bank_select_t which,
    ice_netlist_info_t *netlist)
{
	ice_flash_bank_t *bank = &ice->ice_nvm.in_netlist_bank;
	uint32_t base, idoff;
	uint16_t module_id, length, node_count;
	uint16_t idblk[ICE_NETLIST_ID_BLK_SIZE];
	uint_t i;
	bool ret = false;

	if (bank->ifb_size == 0) {
		return (false);
	}

	base = ice_nvm_bank_offset(bank, which);

	if (!ice_cmd_acquire_nvm(ice, false)) {
		return (false);
	}

	if (!ice_nvm_read_flash_raw_word(ice,
	    base + ICE_NETLIST_TYPE_OFFSET * 2, &module_id)) {
		goto out;
	}

	if (module_id != ICE_NETLIST_LINK_TOPO_MOD_ID) {
		/*
		 * 0xffff indicates that this NVM image simply has no netlist
		 * (link topology) module present; this is normal on some
		 * devices/NVM images, so we don't generate an error
		 */
		if (module_id != 0xffff) {
			ice_error(ice, "!unexpected netlist module id 0x%x, "
			    "expected 0x%x", module_id,
			    ICE_NETLIST_LINK_TOPO_MOD_ID);
		}
		goto out;
	}

	if (!ice_nvm_read_flash_raw_word(ice,
	    base + ICE_LINK_TOPO_MODULE_LEN * 2, &length)) {
		goto out;
	}

	if (length < ICE_NETLIST_ID_BLK_SIZE) {
		ice_error(ice, "!netlist link topology module too small: "
		    "%u words", length);
		goto out;
	}

	if (!ice_nvm_read_flash_raw_word(ice,
	    base + ICE_LINK_TOPO_NODE_COUNT * 2, &node_count)) {
		goto out;
	}
	node_count &= ICE_LINK_TOPO_NODE_COUNT_MASK;

	idoff = base + ICE_NETLIST_ID_BLK_OFFSET(node_count) * 2;
	if (!ice_nvm_read_flash_raw(ice, idoff, idblk, sizeof (idblk))) {
		goto out;
	}

	for (i = 0; i < ICE_NETLIST_ID_BLK_SIZE; i++) {
		idblk[i] = LE_16(idblk[i]);
	}

	netlist->ini_major =
	    ((uint32_t)idblk[ICE_NETLIST_ID_BLK_MAJOR_VER_HIGH] << 16) |
	    idblk[ICE_NETLIST_ID_BLK_MAJOR_VER_LOW];
	netlist->ini_minor =
	    ((uint32_t)idblk[ICE_NETLIST_ID_BLK_MINOR_VER_HIGH] << 16) |
	    idblk[ICE_NETLIST_ID_BLK_MINOR_VER_LOW];
	netlist->ini_type =
	    ((uint32_t)idblk[ICE_NETLIST_ID_BLK_TYPE_HIGH] << 16) |
	    idblk[ICE_NETLIST_ID_BLK_TYPE_LOW];
	netlist->ini_rev =
	    ((uint32_t)idblk[ICE_NETLIST_ID_BLK_REV_HIGH] << 16) |
	    idblk[ICE_NETLIST_ID_BLK_REV_LOW];
	netlist->ini_cust_ver = idblk[ICE_NETLIST_ID_BLK_CUST_VER];
	netlist->ini_hash =
	    ((uint32_t)idblk[ICE_NETLIST_ID_BLK_SHA_HASH_WORD(15)] << 16) |
	    idblk[ICE_NETLIST_ID_BLK_SHA_HASH_WORD(14)];

	ret = true;

out:
	(void) ice_cmd_release_nvm(ice);
	return (ret);
}

bool
ice_nvm_init(ice_t *ice, bool owner)
{
	uint32_t reg;
	uint16_t high, low;
	ice_nvm_t *nvm = &ice->ice_nvm;
	ice_fw_info_t *ifi = &ice->ice_device->id_fwinfo;

	mutex_init(&nvm->in_lock, NULL, MUTEX_DRIVER, NULL);

	/*
	 * NVM's missing. I guess not much more to do then.
	 */
	reg = ice_reg_read(ice, ICE_REG_GLNVM_GENS);
	if ((reg & ICE_REG_GLNVM_GENS_NVM_PRES) == 0) {
		return (true);
	}
	nvm->in_flags |= ICE_NVM_PRESENT;

	nvm->in_sector = ICE_NVM_SECTOR_SIZE;
	nvm->in_size = (1 << ICE_REG_GLNVM_GENS_SR_SIZE(reg)) * 1024;
	reg = ice_reg_read(ice, ICE_REG_GLNVM_FLA);
	if (ICE_REG_GLNVM_FLA_LOCKED(reg) == 0) {
		nvm->in_flags |= ICE_NVM_BLANK;
	}

	/*
	 * The version information decoded below is a property of the
	 * device as a whole and lives in ice_device, not here. If we're not
	 * the PF responsible for populating it (see ice_device_fw_enter()),
	 * skip decoding it ourselves -- everything above this point (the
	 * NVM presence/blank flags and in_sector/in_size) is per-PF state
	 * that ice_cmd_nvm_read() needs regardless, so it's always read.
	 */
	if (!owner) {
		return (true);
	}

	if (!ice_nvm_read_uint16(ice, ICE_NVM_DEV_STARTER_VER,
	    &ifi->ifi_nvm_dev_start)) {
		ice_error(ice, "failed to read NVM Starter version");
		goto err;
	}

	if (!ice_nvm_read_uint16(ice, ICE_NVM_MAP_VERSION,
	    &ifi->ifi_nvm_map_ver)) {
		ice_error(ice, "failed to read NVM map version");
		goto err;
	}

	if (!ice_nvm_read_uint16(ice, ICE_NVM_IMAGE_VERSION,
	    &ifi->ifi_nvm_img_ver)) {
		ice_error(ice, "failed to read NVM image version");
		goto err;
	}

	if (!ice_nvm_read_uint16(ice, ICE_NVM_STRUCTURE_VERSION,
	    &ifi->ifi_nvm_struct_ver)) {
		ice_error(ice, "failed to read NVM structure version");
		goto err;
	}

	if (!ice_nvm_read_uint16(ice, ICE_NVM_EETRACK_1, &low)) {
		ice_error(ice, "failed to read NVM structure version");
		goto err;
	}

	if (!ice_nvm_read_uint16(ice, ICE_NVM_EETRACK_2, &high)) {
		ice_error(ice, "failed to read NVM structure version");
		goto err;
	}
	ifi->ifi_nvm_eetrack = (high << 16) | low;

	if (!ice_nvm_read_uint16(ice, ICE_NVM_EETRACK_ORIG_1, &low)) {
		ice_error(ice, "failed to read NVM structure version");
		goto err;
	}

	if (!ice_nvm_read_uint16(ice, ICE_NVM_EETRACK_ORIG_2, &high)) {
		ice_error(ice, "failed to read NVM structure version");
		goto err;
	}
	ifi->ifi_nvm_eetrack_orig = (high << 16) | low;

	/*
	 * The Option ROM and Netlist versions, as well as all of the
	 * inactive-bank ("pending") version information below, are read on
	 * a best-effort basis for UFM so failures are ignored.
	 */
	if (ice_nvm_read_bank_info(ice, ICE_SR_1ST_NVM_BANK_PTR,
	    ICE_SR_NVM_BANK_SIZE, ICE_SR_CTRL_WORD_NVM_BANK,
	    &nvm->in_nvm_bank)) {
		ice->ice_device->id_nvm_pending_valid = ice_nvm_read_ver_info(
		    ice, ICE_BANK_INACTIVE, &ice->ice_device->id_nvm_pending);
	}

	if (ice_nvm_read_bank_info(ice, ICE_SR_1ST_OROM_BANK_PTR,
	    ICE_SR_OROM_BANK_SIZE, ICE_SR_CTRL_WORD_OROM_BANK,
	    &nvm->in_orom_bank)) {
		ice->ice_device->id_orom_valid = ice_nvm_read_orom_version(
		    ice, ICE_BANK_ACTIVE, &ice->ice_device->id_orom);
		ice->ice_device->id_orom_pending_valid =
		    ice_nvm_read_orom_version(ice, ICE_BANK_INACTIVE,
		    &ice->ice_device->id_orom_pending);
	}

	if (ice_nvm_read_bank_info(ice, ICE_SR_NETLIST_BANK_PTR,
	    ICE_SR_NETLIST_BANK_SIZE, ICE_SR_CTRL_WORD_NETLIST_BANK,
	    &nvm->in_netlist_bank)) {
		ice->ice_device->id_netlist_valid =
		    ice_nvm_read_netlist_version(ice, ICE_BANK_ACTIVE,
		    &ice->ice_device->id_netlist);
		ice->ice_device->id_netlist_pending_valid =
		    ice_nvm_read_netlist_version(ice, ICE_BANK_INACTIVE,
		    &ice->ice_device->id_netlist_pending);
	}

	return (true);

err:
	ice_nvm_fini(ice);
	return (false);
}
