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

  static BoGoPacketImpl* FromDesc(PRFileDesc* desc) {
    if (desc->identity != BoGoPacketImpl::Identity()) {
      return nullptr;
    }
    return reinterpret_cast<BoGoPacketImpl*>(desc->secret);
  }

private:
  friend class BoGoPacket;

  BoGoPacketImpl(PRFileDesc* tcp) {
    desc_.methods = &kMethods;
    desc_.secret = reinterpret_cast<PRFilePrivate*>(this);
    desc_.lower = nullptr;
    desc_.higher = nullptr;
    desc_.dtor = nullptr;
    desc_.identity = Identity();
    tcp_ = tcp;
    received_timeout_ = false;
  }

  ~BoGoPacketImpl() {
    PR_ASSERT(desc_.identity == Identity());
    PR_ASSERT(desc_.secret == reinterpret_cast<PRFilePrivate*>(this));
    // Need to wait until peer is done sending; otherwise it will get
    // RST and may lose the alert that the test spec is expecting.
    // (SO_LINGER isn't enough; need to shutdown and read to end.)
    PR_Shutdown(tcp_, PR_SHUTDOWN_SEND);
    char buf[64];
    while (PR_Read(tcp_, buf, sizeof(buf)) > 0)
      /* discard */;
    PR_Close(tcp_);
  }

  static PRDescIdentity Identity() {
    static PRDescIdentity identity = PR_INVALID_IO_LAYER;
    if (identity == PR_INVALID_IO_LAYER) {
      identity = PR_GetUniqueIdentity("bogo_packet");
      PR_ASSERT(identity != PR_INVALID_IO_LAYER);
    }
    return identity;
  }

  static PRStatus CloseStatic(PRFileDesc* fd) {
    delete FromDesc(fd);
    return PR_SUCCESS;
  }

  static PRInt32 ReadStatic(PRFileDesc* fd, void* buf, PRInt32 amount) {
    return FromDesc(fd)->Read(buf, amount);
  }

  static PRInt32 WriteStatic(PRFileDesc* fd, const void* buf, PRInt32 amount) {
    return FromDesc(fd)->Write(buf, amount);
  }

  static PRInt32 RecvStatic(PRFileDesc* fd, void* buf, PRInt32 amount,
			    PRIntn flags, PRIntervalTime timeout) {
    // Check flags and ignore timeout.
    PR_ASSERT(flags == 0);
    if (flags != 0) {
      PR_SetError(PR_INVALID_ARGUMENT_ERROR, 0);
      return -1;
    }

    return ReadStatic(fd, buf, amount);
  }

  static PRInt32 SendStatic(PRFileDesc* fd, const void* buf, PRInt32 amount,
			    PRIntn flags, PRIntervalTime timeout) {
    // Check flags and ignore timeout.
    PR_ASSERT(flags == 0);
    if (flags != 0) {
      PR_SetError(PR_INVALID_ARGUMENT_ERROR, 0);
      return -1;
    }

    return WriteStatic(fd, buf, amount);
  }

  bool ReadAll(void* buf, PRInt32 amount) {
    while (amount > 0) {
      const PRInt32 result = PR_Read(tcp_, buf, amount);
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

  bool WriteAll(const void* buf, PRInt32 amount) {
    while (amount > 0) {
      const PRInt32 result = PR_Write(tcp_, buf, amount);
      PR_ASSERT(result != 0);
      if (result < 0) {
	return false;
      }
      amount -= result;
      buf = static_cast<const char*>(buf) + result;
    }
    return true;
  }

  bool Discard(PRInt32 amount) {
    if (amount == 0) {
      return true;
    }
    char* const buf = new char[amount];
    const bool ok = ReadAll(buf, amount);
    delete[] buf;
    return ok;
  }

  bool ReadBE(size_t octets, uint64_t* result) {
    PR_ASSERT(octets <= 8);
    uint8_t buf[octets];
    if (!ReadAll(&buf, octets)) {
      return false;
    }
    *result = 0;
    for (size_t i = 0; i < octets; ++i) {
      *result <<= 8;
      *result += buf[i];
    }
    return true;
  }

  bool WriteBE(size_t octets, uint64_t value) {
    PR_ASSERT(octets <= 8);
    uint8_t buf[octets];

    for (size_t i = octets; i > 0; --i) {
      buf[i - 1] = static_cast<uint8_t>(value);
      value >>= 8;
    }
    return WriteAll(&buf, octets);
  }

  PRInt32 Read(void* buf, PRInt32 amount) {
    if (ReceivedTimeout()) {
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
    if (!ReadAll(&opcode, 1)) {
      return -1;
    }

    if (opcode == kOpcodePacket) {
      uint64_t ulen;
      if (!ReadBE(4, &ulen)) {
        return -1;
      }
      const PRInt32 len = static_cast<PRInt32>(ulen);
      // The LargeCiphertext-DTLS test deliberately generates a packet
      // that's larger than a conforming implementation should expect.
      // This follows the normal datagram-socket behavior and
      // truncates it, allowing for test coverage of the parts of NSS
      // that handle that case.
      const PRInt32 to_read = amount < len ? amount : len;
      const bool ok = ReadAll(buf, to_read) && Discard(len - to_read);
      return ok ? to_read : -1;
    }

    if (opcode == kOpcodeTimeout) {
      uint64_t nsec;
      if (!ReadBE(8, &nsec)) {
        return -1;
      }
      if (!WriteAll(&kOpcodeTimeoutAck, 1)) {
        return -1;
      }
      received_timeout_ = true;
      PR_SetError(PR_WOULD_BLOCK_ERROR, 0);
      return -1;
    }

    // Bad opcode.
    PR_ASSERT(false);
    PR_SetError(PR_IO_ERROR, 0);
    return -1;
  }

  PRInt32 Write(const void* buf, PRInt32 amount) {
    const bool success =
      WriteAll(&kOpcodePacket, 1) &&
      WriteBE(4, static_cast<uint64_t>(amount)) &&
      WriteAll(buf, amount);
    return success ? amount : -1;
  }

  static PRStatus GetSockNameStatic(PRFileDesc* fd, PRNetAddr* addr) {
    return PR_GetSockName(FromDesc(fd)->tcp_, addr);
  }

  static PRStatus GetPeerNameStatic(PRFileDesc* fd, PRNetAddr* addr) {
    return PR_GetPeerName(FromDesc(fd)->tcp_, addr);
  }

  static PRStatus GetSocketOptionStatic(PRFileDesc* fd,
					PRSocketOptionData* data) {
    if (data->option == PR_SockOpt_Nonblocking) {
      data->value.non_blocking = PR_TRUE;
      return PR_SUCCESS;
    }
    PR_ASSERT(false);
    PR_SetError(PR_NOT_IMPLEMENTED_ERROR, 0);
    return PR_FAILURE;
  }

  static const PRIOMethods kMethods;

  static const char kOpcodePacket;
  static const char kOpcodeTimeout;
  static const char kOpcodeTimeoutAck;

  PRFileDesc desc_;
  PRFileDesc* tcp_;
  bool received_timeout_;
};

/* static */ const char BoGoPacketImpl::kOpcodePacket = 'P';
/* static */ const char BoGoPacketImpl::kOpcodeTimeout = 'T';
/* static */ const char BoGoPacketImpl::kOpcodeTimeoutAck = 't';

/* static */ const PRIOMethods BoGoPacketImpl::kMethods = {
  PR_DESC_SOCKET_UDP, // file_type
  CloseStatic,
  ReadStatic,
  WriteStatic,
  nullptr, // available
  nullptr, // available64
  nullptr, // fsync
  nullptr, // seek
  nullptr, // seek64
  nullptr, // fileinfo
  nullptr, // fileinfo64
  nullptr, // writev
  nullptr, // connect
  nullptr, // accept
  nullptr, // bind
  nullptr, // listen
  nullptr, // shutdown
  RecvStatic,
  SendStatic,
  nullptr, // recvfrom
  nullptr, // sendto
  nullptr, // poll
  nullptr, // acceptread
  nullptr, // transmitfile
  GetSockNameStatic,
  GetPeerNameStatic,
  nullptr, // reserved_fn_6
  nullptr, // reserved_fn_5
  GetSocketOptionStatic,
  nullptr, // setsocketoption
  nullptr, // sendfile
  nullptr, // connectcontinue
  nullptr, // reserved_fn_3
  nullptr, // reserved_fn_2
  nullptr, // reserved_fn_1
  nullptr, // reserved_fn_0
};

PRFileDesc* BoGoPacket::Import(PRFileDesc* tcp) {
  return &(new BoGoPacketImpl(tcp))->desc_;
}

BoGoPacket* BoGoPacket::FromDesc(PRFileDesc* desc) {
  return BoGoPacketImpl::FromDesc(desc);
}
