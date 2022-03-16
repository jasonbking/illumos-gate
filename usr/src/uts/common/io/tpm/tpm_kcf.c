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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2022 Jason King
 */

/*
 * KCF Provider for a TPM device. Currently only the RNG function of a TPM
 * is exposed to KCF. Historically, TPM1.2 KCF RNG support was only ever
 * built with special compilation flags (that were never used in illumos).
 * As such, we currently only register TPM2.0 devices with KCF.
 */

#define	IDENT_TPMRNG	"TPM Random Number Generator"

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/crypto/common.h>
#include <sys/crypto/impl.h>
#include <sys/crypto/spi.h>

/*
 * CSPI information (entry points, provider info, etc.)
 */
static void tpmrng_provider_status(crypto_provider_handle_t, uint_t *);

static crypto_control_ops_t tpmrng_control_ops = {
	.provider_status = tpmrng_provider_status,
};

static int tpmrng_seed_random(crypto_provider_handle_t, crypto_session_id_t,
    uchar_t *, size_t, uint_t, uint32_t, crypto_req_handle_t);

static int tpmrng_generate_random(crypto_provider_handle_t,
    crypto_session_id_t, uchar_t *, size_t, crypto_req_handle_t);

static crypto_random_number_ops_t tpmrng_random_number_ops = {
	.seed_random =		tpmrng_seed_random,
	.generate_random =	tpmrng_generate_random,
};

static int tpmrng_ext_info(crypto_provider_handle_t,
	crypto_provider_ext_info_t *, crypto_req_handle_t);

static crypto_provider_management_ops_t tpmrng_extinfo_op = {
	.ext_info =	tpmrng_ext_info,
};

static int tpmrng_register(tpm_state_t *);
static int tpmrng_unregister(tpm_state_t *);

static crypto_ops_t tpmrng_crypto_ops = {
	.co_control_ops =	&tpmrng_control_ops,
	.co_random_ops =	&tpmrng_random_number_ops,
	.co_provider_ops =	&tpmrng_extinfo_op,
};

static crypto_provider_info_t tpmrng_prov_info = {
	.pi_interface_version =		CRYPTO_SPI_VERSION_2,
	.pi_provider_description =	"TPM Provider",
	.pi_provider_type =		CRYPTO_HW_PROVIDER,
	.pi_ops_vector =		&tpmrng_crypto_ops,
};

/*
 * Random number generator entry points
 */
static void
strncpy_spacepad(uchar_t *s1, char *s2, int n)
{
	int s2len = strlen(s2);

	(void) strncpy((char *)s1, s2, n);
	if (s2len < n)
		(void) memset(s1 + s2len, ' ', n - s2len);
}

static int
tpmrng_ext_info(crypto_provider_handle_t prov,
    crypto_provider_ext_info_t *ext_info,
    crypto_req_handle_t cfreq __unused)
{
	tpm_state_t *tpm = (tpm_state_t *)prov;
	char buf[64];

	if (tpm == NULL)
		return (DDI_FAILURE);

	strncpy_spacepad(ext_info->ei_manufacturerID,
	    (char *)tpm->vers_info.tpmVendorID,
	    sizeof (ext_info->ei_manufacturerID));

	strncpy_spacepad(ext_info->ei_model, "0",
	    sizeof (ext_info->ei_model));
	strncpy_spacepad(ext_info->ei_serial_number, "0",
	    sizeof (ext_info->ei_serial_number));

	ext_info->ei_flags = CRYPTO_EXTF_RNG | CRYPTO_EXTF_SO_PIN_LOCKED;
	ext_info->ei_max_session_count = CRYPTO_EFFECTIVELY_INFINITE;
	ext_info->ei_max_pin_len = 0;
	ext_info->ei_min_pin_len = 0;
	ext_info->ei_total_public_memory = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_free_public_memory = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_total_private_memory = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_free_public_memory = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_time[0] = 0;

	ext_info->ei_hardware_version.cv_major = tpm->vers_info.version.major;
	ext_info->ei_hardware_version.cv_minor = tpm->vers_info.version.minor;
	ext_info->ei_firmware_version.cv_major =
	    tpm->vers_info.version.revMajor;
	ext_info->ei_firmware_version.cv_minor =
	    tpm->vers_info.version.revMinor;

	(void) snprintf(buf, sizeof (buf), "tpmrng TPM RNG");

	strncpy_spacepad(ext_info->ei_label, buf, sizeof (ext_info->ei_label));

	return (CRYPTO_SUCCESS);
}

static int
tpmrng_register(tpm_state_t *tpm)
{
	int			ret;
	char			id[64];
	crypto_mech_name_t	*rngmech;

	ASSERT(tpm != NULL);

	(void) snprintf(id, sizeof (id), "tpmrng %s", IDENT_TPMRNG);

	tpmrng_prov_info.pi_provider_description = ID;
	tpmrng_prov_info.pi_provider_dev.pd_hw = tpm->dip;
	tpmrng_prov_info.pi_provider_handle = tpm;

	ret = crypto_register_provider(&tpmrng_prov_info, &tpm->n_prov);
	if (ret != CRYPTO_SUCCESS) {
		tpm->n_prov = NULL;
		return (DDI_FAILURE);
	}

	crypto_provider_notification(tpm->n_prov, CRYPTO_PROVIDER_READY);

	rngmech = strdup("random");
	ret = crypto_load_dev_disabled("tpm", ddi_get_instance(tpm->dip),
	    1, rngmech);
#ifdef DEBUG
	if (ret != CRYPTO_SUCCESS)
		cmn_err(CE_WARN, "!crypto_load_dev_disabled failed (%d)", ret);
#endif
	return (DDI_SUCCESS);
}

static int
tpmrng_unregister(tpm_state_t *tpm)
{
	int ret;
	ASSERT(tpm != NULL);
	if (tpm->n_prov) {
		ret = crypto_unregister_provider(tpm->n_prov);
		tpm->n_prov = NULL;
		if (ret != CRYPTO_SUCCESS)
			return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

static void
tpmrng_provider_status(crypto_provider_handle_t provider __unused,
    uint_t *status)
{
	*status = CRYPTO_PROVIDER_READY;
}

static int
tpmrng_seed_random(crypto_provider_handle_t provider, crypto_session_id_t sid,
    uchar_t *buf, size_t len, uint_t entropy_est __unused,
    uint32_t flags __unused, crypto_req_handle_t req __unused)
{
	tpm_state_t *tpm = (tpm_state_t *)provider;

	return (tpm12_seed_random(tpm, buf, len));
}

/* ARGSUSED */
static int
tpmrng_generate_random(crypto_provider_handle_t provider,
    crypto_session_id_t sid, uchar_t *buf, size_t len, crypto_req_handle_t req)
{
	tpm_state_t *tpm = (tpm_state_t *)provider;

	return (tpm12_generate_random(tpm, buf, len));
}
