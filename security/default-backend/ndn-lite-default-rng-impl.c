/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include <stddef.h>
#include "ndn-lite-default-rng-impl.h"
#include "../ndn-lite-rng.h"
#include "../../ndn-error-code.h"

/* always fails and return 0 */
static int ndn_lite_default_rng(uint8_t *dest, unsigned size)
{
  (void) dest, size;

  return 0;
}

void
ndn_lite_default_rng_load_backend(void)
{
  ndn_rng_backend_t* backend = ndn_rng_get_backend();
  backend->rng = ndn_lite_default_rng;
}
