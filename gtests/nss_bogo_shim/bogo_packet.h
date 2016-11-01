/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "prio.h"

class BoGoPacket {
public:
  static PRFileDesc* Import(PRFileDesc* tcp);
  static BoGoPacket* FromDesc(PRFileDesc* desc);
  virtual uint64_t NSecUntilReadable() = 0;
  virtual void TimeHasElapsed(uint64_t nsec) = 0;
};
