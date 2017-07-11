/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "nspr.h"
#include <unistd.h>

#include "bogo_packet.h"

class BoGoPacketImpl final : public BoGoPacket {
public:
  bool ReceivedTimeout() override {
    return received_timeout_;
  }

  static BoGoPacketImpl* FromDesc(PRFileDesc* fd) {
    Initialize();
    fd = PR_GetIdentitiesLayer(fd, sIdentity);
    if (fd && fd->secret) {
      return reinterpret_cast<BoGoPacketImpl*>(fd->secret);
    }
    return nullptr;
  }

  static PRFileDesc* MakeLayer() {
    Initialize();
    const auto fd = PR_CreateIOLayerStub(sIdentity, &sMethods);
    fd->secret = reinterpret_cast<PRFilePrivate*>(new BoGoPacketImpl());
    return fd;
  }

private:
  BoGoPacketImpl() : received_timeout_(false) { }

  ~BoGoPacketImpl() { }

  static BoGoPacketImpl* FromDescTop(PRFileDesc* fd) {
    const auto ident = PR_GetLayersIdentity(fd);
    PR_ASSERT(ident == sIdentity);
    if (ident == sIdentity) {
      return reinterpret_cast<BoGoPacketImpl*>(fd->secret);
    }
    return nullptr;
  }

  static PRStatus Close(PRFileDesc* fd) {
    delete FromDescTop(fd);
    fd->secret = nullptr;

    sDefaultMethods->shutdown(fd, PR_SHUTDOWN_SEND);
    char buf[64];
    while (sDefaultMethods->read(fd, buf, sizeof(buf)) > 0)
      /* discard */;
    return sDefaultMethods->close(fd);
  }

  static PRInt32 RecvPacket(PRFileDesc* fd, void* buf, PRInt32 amount,
			    PRIntn flags, PRIntervalTime timeout) {
    // Check flags and ignore timeout.
    PR_ASSERT(flags == 0);
    if (flags != 0) {
      PR_SetError(PR_INVALID_ARGUMENT_ERROR, 0);
      return -1;
    }

    return ReadPacket(fd, buf, amount);
  }

  static PRInt32 SendPacket(PRFileDesc* fd, const void* buf, PRInt32 amount,
			    PRIntn flags, PRIntervalTime timeout) {
    // Check flags and ignore timeout.
    PR_ASSERT(flags == 0);
    if (flags != 0) {
      PR_SetError(PR_INVALID_ARGUMENT_ERROR, 0);
      return -1;
    }

    return WritePacket(fd, buf, amount);
  }

  static bool ReadAll(PRFileDesc *fd, void* buf, PRInt32 amount) {
    while (amount > 0) {
      const PRInt32 result = sDefaultMethods->read(fd, buf, amount);
      if (result < 0) {
	return false;
      }
      if (result == 0) {
	// Datagram sockets don't have "end of file", so something went
	// wrong with the protocol?
	PR_SetError(PR_END_OF_FILE_ERROR, 0);
	return false;
      }
      amount -= result;
      buf = static_cast<char*>(buf) + result;
    }
    return true;
  }

  static bool WriteAll(PRFileDesc *fd, const void* buf, PRInt32 amount) {
    while (amount > 0) {
      const PRInt32 result = sDefaultMethods->write(fd, buf, amount);
      PR_ASSERT(result != 0);
      if (result < 0) {
	return false;
      }
      amount -= result;
      buf = static_cast<const char*>(buf) + result;
    }
    return true;
  }

  static bool Discard(PRFileDesc* fd, PRInt32 amount) {
    if (amount == 0) {
      return true;
    }
    char* const buf = new char[amount];
    const bool ok = ReadAll(fd, buf, amount);
    delete[] buf;
    return ok;
  }

  static bool ReadBE(PRFileDesc* fd, size_t octets, uint64_t* result) {
    PR_ASSERT(octets <= 8);
    uint8_t buf[octets];
    if (!ReadAll(fd, &buf, octets)) {
      return false;
    }
    *result = 0;
    for (size_t i = 0; i < octets; ++i) {
      *result <<= 8;
      *result += buf[i];
    }
    return true;
  }

  static bool WriteBE(PRFileDesc* fd, size_t octets, uint64_t value) {
    PR_ASSERT(octets <= 8);
    uint8_t buf[octets];

    for (size_t i = octets; i > 0; --i) {
      buf[i - 1] = static_cast<uint8_t>(value);
      value >>= 8;
    }
    return WriteAll(fd, &buf, octets);
  }

  static PRInt32 ReadPacket(PRFileDesc* fd, void* buf, PRInt32 amount) {
    const auto self = FromDescTop(fd);

    if (self->ReceivedTimeout()) {
      PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
      return -1;
    }

    char opcode;
    // A blocking read isn't quite right here. What happens during the
    // DTLS-Retransmit-*-1 tests:
    // * NSS sends ClientHello
    // * BoGo drops it and sends a 1-second timeout
    // * NSS shim waits 1s
    // * ssl3_GatherCompleteHandshake tries to read *before* checking timeouts
    //   (dtls_GatherData before dtls_CheckTimer)
    // * BoGo is still waiting for the retransmit
    // * Deadlock and test failure.
    // However, using a nonblocking read (PR_Recv with PR_INTERVAL_NO_WAIT)
    // causes a number of other tests to break.  This need to be investigated.
    if (!ReadAll(fd, &opcode, 1)) {
      return -1;
    }

    if (opcode == kOpcodePacket) {
      uint64_t ulen;
      if (!ReadBE(fd, 4, &ulen)) {
        return -1;
      }
      const PRInt32 len = static_cast<PRInt32>(ulen);
      // The LargeCiphertext-DTLS test deliberately generates a packet
      // that's larger than a conforming implementation should expect.
      // This follows the normal datagram-socket behavior and
      // truncates it, allowing for test coverage of the parts of NSS
      // that handle that case.
      const PRInt32 to_read = amount < len ? amount : len;
      const bool ok = ReadAll(fd, buf, to_read) && Discard(fd, len - to_read);
      return ok ? to_read : -1;
    }

    if (opcode == kOpcodeTimeout) {
      uint64_t nsec;
      if (!ReadBE(fd, 8, &nsec)) {
        return -1;
      }
      if (!WriteAll(fd, &kOpcodeTimeoutAck, 1)) {
        return -1;
      }
      self->received_timeout_ = true;
      PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
      return -1;
    }

    // Bad opcode.
    PR_ASSERT(false);
    PR_SetError(PR_IO_ERROR, 0);
    return -1;
  }

  static PRInt32 WritePacket(PRFileDesc* fd, const void* buf, PRInt32 amount) {
    const bool success =
      WriteAll(fd, &kOpcodePacket, 1) &&
      WriteBE(fd, 4, static_cast<uint64_t>(amount)) &&
      WriteAll(fd, buf, amount);
    return success ? amount : -1;
  }

  static PRStatus GetSocketOption(PRFileDesc* fd,
                                  PRSocketOptionData* data) {
    if (data->option == PR_SockOpt_Nonblocking) {
      data->value.non_blocking = PR_TRUE;
      return PR_SUCCESS;
    }
    PR_ASSERT(false);
    PR_SetError(PR_NOT_IMPLEMENTED_ERROR, 0);
    return PR_FAILURE;
  }

  static void Initialize(void) {
    if (sIdentity != PR_INVALID_IO_LAYER) {
      return;
    }
    sIdentity = PR_GetUniqueIdentity("bogo_packet");
    PR_ASSERT(sIdentity != PR_INVALID_IO_LAYER);

    sDefaultMethods = PR_GetDefaultIOMethods();

    // This can't be PR_DESC_SOCKET_UDP; pl_TopClose insists.
    sMethods.file_type = PR_DESC_LAYERED;
    sMethods.close = Close;
    sMethods.read = ReadPacket;
    sMethods.write = WritePacket;
    sMethods.recv = RecvPacket;
    sMethods.send = SendPacket;
    sMethods.getsocketoption = GetSocketOption;
    sMethods.getsockname = sDefaultMethods->getsockname;
    sMethods.getpeername = sDefaultMethods->getpeername;
  }

  static const char kOpcodePacket;
  static const char kOpcodeTimeout;
  static const char kOpcodeTimeoutAck;

  static PRDescIdentity sIdentity;
  static PRIOMethods sMethods;
  static const PRIOMethods* sDefaultMethods;

  // In the future, this will have more state to actually deal with
  // timeouts and let simulated time elapse.
  bool received_timeout_;
};

/* static */ const char BoGoPacketImpl::kOpcodePacket = 'P';
/* static */ const char BoGoPacketImpl::kOpcodeTimeout = 'T';
/* static */ const char BoGoPacketImpl::kOpcodeTimeoutAck = 't';

/* static */ PRDescIdentity BoGoPacketImpl::sIdentity = PR_INVALID_IO_LAYER;
/* static */ PRIOMethods BoGoPacketImpl::sMethods;
/* static */ const PRIOMethods* BoGoPacketImpl::sDefaultMethods;

PRFileDesc* BoGoPacket::Import(PRFileDesc* tcp) {
  PRFileDesc* layer = BoGoPacketImpl::MakeLayer();
  PRStatus status = PR_PushIOLayer(tcp, PR_TOP_IO_LAYER, layer);
  PR_ASSERT(PR_SUCCESS == status);
  return tcp;
}

BoGoPacket* BoGoPacket::FromDesc(PRFileDesc* fd) {
  return BoGoPacketImpl::FromDesc(fd);
}
