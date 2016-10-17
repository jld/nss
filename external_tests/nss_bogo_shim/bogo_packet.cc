/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#if 0
#include <iostream>
#endif

#include "nspr.h"
#include "prio.h"

#include "bogo_packet.h"

class BoGoPacketized {
public:
  static PRFileDesc* Import(PRFileDesc* tcp) {
    return &(new BoGoPacketized(tcp))->desc_;
  }

private:
  BoGoPacketized(PRFileDesc* tcp) {
    desc_.methods = &kMethods;
    desc_.secret = reinterpret_cast<PRFilePrivate*>(this);
    desc_.lower = nullptr;
    desc_.higher = nullptr;
    desc_.dtor = nullptr;
    desc_.identity = Identity();
    tcp_ = tcp;
    now_ = 0;
    next_packet_ = 0;
  }

  ~BoGoPacketized() {
    PR_ASSERT(desc_.identity == Identity());
    PR_ASSERT(desc_.secret == reinterpret_cast<PRFilePrivate*>(this));
    PR_Close(tcp_);
  }

  static BoGoPacketized* FromDesc(PRFileDesc* desc) {
    PR_ASSERT(desc->identity == Identity());
    return reinterpret_cast<BoGoPacketized*>(desc->secret);
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
    return PR_Recv(fd, buf, amount, 0, PR_INTERVAL_NO_TIMEOUT);
  }

  static PRInt32 WriteStatic(PRFileDesc* fd, const void* buf, PRInt32 amount) {
    return PR_Send(fd, buf, amount, 0, PR_INTERVAL_NO_TIMEOUT);
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

  bool Discard(PRInt32 amount) {
    if (amount == 0) {
      return true;
    }
    char* const buf = new char[amount];
    const bool ok = ReadAll(buf, amount);
    delete[] buf;
    return ok;
  }

  bool ReadBE32(uint32_t& result) {
    uint8_t buf[4];
    if (!ReadAll(&buf, 4)) {
      return false;
    }
    result =
      (static_cast<uint32_t>(buf[0]) << 24) |
      (static_cast<uint32_t>(buf[1]) << 16) |
      (static_cast<uint32_t>(buf[2]) << 8) |
      static_cast<uint32_t>(buf[3]);
    return true;
  }

  bool WriteBE32(uint32_t value) {
    const uint8_t buf[4] = {
      static_cast<uint8_t>(value >> 24),
      static_cast<uint8_t>(value >> 16),
      static_cast<uint8_t>(value >> 8),
      static_cast<uint8_t>(value)
    };
    return WriteAll(&buf, 4);
  }

  bool ReadBE64(uint64_t& result) {
    uint8_t buf[8];
    if (!ReadAll(&buf, 8)) {
      return false;
    }
    result =
      (static_cast<uint64_t>(buf[0]) << 56) |
      (static_cast<uint64_t>(buf[1]) << 48) |
      (static_cast<uint64_t>(buf[2]) << 40) |
      (static_cast<uint64_t>(buf[3]) << 32) |
      (static_cast<uint64_t>(buf[4]) << 24) |
      (static_cast<uint64_t>(buf[5]) << 16) |
      (static_cast<uint64_t>(buf[6]) << 8) |
      static_cast<uint64_t>(buf[7]);
    return true;
  }

  static PRInt32 RecvStatic(PRFileDesc* fd, void* buf, PRInt32 amount,
			    PRIntn flags, PRIntervalTime timeout) {
    PR_ASSERT(flags == 0);
    if (flags != 0) {
      PR_SetError(PR_INVALID_ARGUMENT_ERROR, 0);
      return -1;
    }

    return FromDesc(fd)->Recv(buf, amount, timeout);
  }

  PRInt32 Recv(void* buf, PRInt32 amount, PRIntervalTime timeout) {
    const uint64_t deadline = timeout == PR_INTERVAL_NO_TIMEOUT
      ? 0xffffffffffffffff
      : now_ + static_cast<uint64_t>(timeout) * 10000000;
#if 0
    std::cerr << "RECV: timeout = " << timeout << " ms, "
	      << "now = " << now_ << " ns, "
	      << "deadline = " << deadline << " ns." << std::endl;
#endif

    for (;;) {
      char opcode;
      if (!ReadAll(&opcode, 1)) {
	return -1;
      }
      if (opcode == kOpcodePacket) {
	uint32_t ulen;
	if (!ReadBE32(ulen)) {
	  return -1;
	}
	const PRInt32 len = static_cast<PRInt32>(ulen);
	const PRInt32 to_read = amount < len ? amount : len;
	const bool ok = ReadAll(buf, to_read) && Discard(len - to_read);
#if 0
	if (ok) {
	  std::cerr << "PACKET: " << to_read << " octets." << std::endl;
	}
#endif
	return ok ? to_read : -1;
      }
      if (opcode == kOpcodeTimeout) {
	uint64_t nsec;
	if (!ReadBE64(nsec)) {
	  return -1;
	}
	if (!WriteAll(&kOpcodeTimeoutAck, 1)) {
	  return -1;
	}
#if 0
	std::cerr << "DELAY: " << nsec << " ns." << std::endl;
#endif
	next_packet_ += nsec;
	if (next_packet_ > deadline) {
#if 0
	  std::cerr << "TIMEOUT: " << (deadline - now_) << " ns used; "
		    << (next_packet_ - deadline) << " ns left." << std::endl;
#endif
	  now_ = deadline;
	  PR_SetError(PR_IO_TIMEOUT_ERROR, 0);
	  return -1;
	}
	now_ = next_packet_;
      } else {
	PR_ASSERT(0);
	PR_SetError(PR_IO_ERROR, 0);
	return -1;
      }
    }
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

  static PRInt32 SendStatic(PRFileDesc* fd, const void* buf, PRInt32 amount,
			    PRIntn flags, PRIntervalTime timeout) {
    PR_ASSERT(flags == 0);
    if (flags != 0) {
      PR_SetError(PR_INVALID_ARGUMENT_ERROR, 0);
      return -1;
    }

    return FromDesc(fd)->Send(buf, amount, timeout);
  }

  PRInt32 Send(const void* buf, PRInt32 amount, PRIntervalTime timeout) {
    const bool success = 
      WriteAll(&kOpcodePacket, 1) &&
      WriteBE32(static_cast<uint32_t>(amount)) &&
      WriteAll(buf, amount);
#if 0
    std::cerr << "SENT: " << amount << " octets." << std::endl;
#endif
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
      data->value.non_blocking = PR_FALSE;
      return PR_SUCCESS;
    }
    PR_ASSERT(0);
    PR_SetError(PR_NOT_IMPLEMENTED_ERROR, 0);
    return PR_FAILURE;
  }

  static const PRIOMethods kMethods;

  static const char kOpcodePacket;
  static const char kOpcodeTimeout;
  static const char kOpcodeTimeoutAck;

  PRFileDesc desc_;
  PRFileDesc* tcp_;
  uint64_t now_;
  uint64_t next_packet_;
};

PRFileDesc* BoGoPacket_ImportFD(PRFileDesc* tcp) {
  return BoGoPacketized::Import(tcp);
}

/* static */ const char BoGoPacketized::kOpcodePacket = 'P';
/* static */ const char BoGoPacketized::kOpcodeTimeout = 'T';
/* static */ const char BoGoPacketized::kOpcodeTimeoutAck = 't';

/* static */ const PRIOMethods BoGoPacketized::kMethods = {
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
