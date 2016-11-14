/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "prinrval.h"
#include "prthread.h"

/* This doesn't even try to deal with the existence of threads.... */
/* Also this will fail on non-ELF platforms, and several tests need it. */

static PRIntervalTime now;

PR_IMPLEMENT(PRIntervalTime) PR_IntervalNow(void)
{
  return now;
}

PR_IMPLEMENT(PRStatus) PR_Sleep(PRIntervalTime amount)
{
  now += amount;
  return PR_SUCCESS;
}
