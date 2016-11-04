/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */
#include "config.h"

#include <cstdlib>
#include <iostream>
#include <memory>
#include "nspr.h"
#include "nss.h"
#include "prio.h"
#include "prnetdb.h"
#include "ssl.h"
#include "sslerr.h"
#include "sslproto.h"
#include "ssl3prot.h"

#include "bogo_packet.h"
#include "nsskeys.h"

static const char* kVersionDisableFlags[] = {
  "no-ssl3",
  "no-tls1",
  "no-tls11",
  "no-tls12",
  "no-tls13"
};

bool exitCodeUnimplemented = false;

std::string FormatError(PRErrorCode code) {
  return std::string(":") + PORT_ErrorToName(code) + ":" + ":" +
         PORT_ErrorToString(code);
}

class TestAgent {
 public:
  TestAgent(const Config& cfg)
      : cfg_(cfg),
        pr_fd_(nullptr),
        ssl_fd_(nullptr),
        cert_(nullptr),
        key_(nullptr) {}

  ~TestAgent() {
    if (pr_fd_) {
      PR_Close(pr_fd_);
    }

    if (ssl_fd_) {
      PR_Close(ssl_fd_);
    }

    if (key_) {
      SECKEY_DestroyPrivateKey(key_);
    }

    if (cert_) {
      CERT_DestroyCertificate(cert_);
    }
  }

  static std::unique_ptr<TestAgent> Create(const Config& cfg) {
    std::unique_ptr<TestAgent> agent(new TestAgent(cfg));

    if (!agent->Init()) return nullptr;

    return agent;
  }

  bool SleepUntilReadable() {
    PRFileDesc* pr_fd = ssl_fd_ ? ssl_fd_->lower : pr_fd_;
    if (BoGoPacket* packetized = BoGoPacket::FromDesc(pr_fd)) {
      PRIntervalTime to_sleep = packetized->TimeUntilReadable();
#if 0
      std::cerr << "SLEEPING: " << to_sleep << " NSPR ticks.\n";
#endif
      PR_Sleep(to_sleep);
#if 0
      std::cerr << "WOKE UP.\n";
#endif
      return true;
    }
    return false;
  }

  bool Init() {
    if (!ConnectTcp()) {
      return false;
    }

    if (!SetupKeys()) {
      std::cerr << "Couldn't set up keys/certs\n";
      return false;
    }

    if (!SetupOptions()) {
      std::cerr << "Couldn't configure socket\n";
      return false;
    }

    SECStatus rv = SSL_ResetHandshake(ssl_fd_, cfg_.get<bool>("server"));
    if (rv != SECSuccess) return false;

    return true;
  }

  bool ConnectTcp() {
    PRStatus prv;
    PRNetAddr addr;

    prv = PR_StringToNetAddr("127.0.0.1", &addr);
    if (prv != PR_SUCCESS) {
      return false;
    }
    addr.inet.port = PR_htons(cfg_.get<int>("port"));

    pr_fd_ = PR_OpenTCPSocket(addr.raw.family);
    if (!pr_fd_) return false;

    prv = PR_Connect(pr_fd_, &addr, PR_INTERVAL_NO_TIMEOUT);
    if (prv != PR_SUCCESS) {
      return false;
    }

    if (cfg_.get<bool>("dtls")) {
      pr_fd_ = BoGoPacket::Import(pr_fd_);
      ssl_fd_ = DTLS_ImportFD(NULL, pr_fd_);
    } else {
      ssl_fd_ = SSL_ImportFD(NULL, pr_fd_);
    }
    if (!ssl_fd_) return false;
    pr_fd_ = nullptr;

    return true;
  }

  bool SetupKeys() {
    SECStatus rv;

    if (cfg_.get<std::string>("key-file") != "") {
      key_ = ReadPrivateKey(cfg_.get<std::string>("key-file"));
      if (!key_) {
        // Temporary to handle our inability to handle ECDSA.
        exitCodeUnimplemented = true;
        return false;
      }
    }
    if (cfg_.get<std::string>("cert-file") != "") {
      cert_ = ReadCertificate(cfg_.get<std::string>("cert-file"));
      if (!cert_) return false;
    }
    if (cfg_.get<bool>("server")) {
      // Server
      rv = SSL_ConfigServerCert(ssl_fd_, cert_, key_, nullptr, 0);
      if (rv != SECSuccess) {
        std::cerr << "Couldn't configure server cert\n";
        return false;
      }
    } else {
      // Client.

      // Needed because server certs are not entirely valid.
      rv = SSL_AuthCertificateHook(ssl_fd_, AuthCertificateHook, this);
      if (rv != SECSuccess) return false;

      if (key_ && cert_) {
        rv = SSL_GetClientAuthDataHook(ssl_fd_, GetClientAuthDataHook, this);
        if (rv != SECSuccess) return false;
      }
    }

    return true;
  }

  static bool ConvertFromWireVersion(SSLProtocolVariant variant,
                                     int wire_version,
                                     uint16_t* lib_version) {
    // These default values are used when {min,max}-version isn't given.
    if (wire_version == 0 || wire_version == 0xffff) {
      *lib_version = static_cast<uint16_t>(wire_version);
      return true;
    }

#ifdef TLS_1_3_DRAFT_VERSION
    if (wire_version == (0x7f00 | TLS_1_3_DRAFT_VERSION)) {
      // N.B. SSL_LIBRARY_VERSION_DTLS_1_3_WIRE == SSL_LIBRARY_VERSION_TLS_1_3
      wire_version = SSL_LIBRARY_VERSION_TLS_1_3;
    }
#endif

    if (variant == ssl_variant_datagram) {
      switch (wire_version) {
      case SSL_LIBRARY_VERSION_DTLS_1_0_WIRE:
        *lib_version = SSL_LIBRARY_VERSION_DTLS_1_0;
        break;
      case SSL_LIBRARY_VERSION_DTLS_1_2_WIRE:
        *lib_version = SSL_LIBRARY_VERSION_DTLS_1_2;
        break;
      case SSL_LIBRARY_VERSION_DTLS_1_3_WIRE:
        *lib_version = SSL_LIBRARY_VERSION_DTLS_1_3;
        break;
      default:
        std::cerr << "Unrecognized DTLS version " << wire_version << ".\n";
        return false;
      }
    } else {
      if (wire_version < SSL_LIBRARY_VERSION_3_0 ||
          wire_version > SSL_LIBRARY_VERSION_TLS_1_3) {
        std::cerr << "Unrecognized TLS version " << wire_version << ".\n";
        return false;
      }
      *lib_version = static_cast<uint16_t>(wire_version);
    }
    return true;
  }

  bool GetVersionRange(SSLVersionRange* range_out, SSLProtocolVariant variant) {
    SSLVersionRange supported;
    if (SSL_VersionRangeGetSupported(variant, &supported) != SECSuccess) {
      return false;
    }

    uint16_t min_allowed;
    uint16_t max_allowed;
    if (!ConvertFromWireVersion(variant, cfg_.get<int>("min-version"),
                                &min_allowed)) {
      return false;
    }
    if (!ConvertFromWireVersion(variant, cfg_.get<int>("max-version"),
                                &max_allowed)) {
      return false;
    }

    min_allowed = std::max(min_allowed, supported.min);
    max_allowed = std::min(max_allowed, supported.max);

    bool found_min = false;
    bool found_max = false;
    // Ignore -no-ssl3, because SSLv3 is never supported.
    for (size_t i = 1; i < PR_ARRAY_SIZE(kVersionDisableFlags); ++i) {
      auto version =
        static_cast<uint16_t>(SSL_LIBRARY_VERSION_TLS_1_0 + (i - 1));
      if (variant == ssl_variant_datagram) {
        // In DTLS mode, the -no-tlsN flags refer to DTLS versions,
        // but NSS wants the corresponding TLS versions.
        if (version == SSL_LIBRARY_VERSION_TLS_1_1) {
          // DTLS 1.1 doesn't exist.
          continue;
        }
        if (version == SSL_LIBRARY_VERSION_TLS_1_0) {
          version = SSL_LIBRARY_VERSION_DTLS_1_0;
        }
      }

      if (version < min_allowed) {
        continue;
      }
      if (version > max_allowed) {
        break;
      }

      const bool allowed = !cfg_.get<bool>(kVersionDisableFlags[i]);

      if (!found_min && allowed) {
        found_min = true;
        range_out->min = version;
      }
      if (found_min && !found_max) {
        if (allowed) {
          range_out->max = version;
        } else {
          found_max = true;
        }
      }
      if (found_max && allowed) {
        std::cerr << "Discontiguous version range.\n";
        return false;
      }
    }

    if (!found_min) {
      std::cerr << "All versions disabled.\n";
    }
    return found_min;
  }

  bool SetupOptions() {
    SECStatus rv = SSL_OptionSet(ssl_fd_, SSL_ENABLE_SESSION_TICKETS, PR_TRUE);
    if (rv != SECSuccess) {
      std::cerr << "Couldn't enable session tickets.\n";
      return false;
    }

    SSLVersionRange vrange;
    if (!GetVersionRange(&vrange, cfg_.get<bool>("dtls")
                         ? ssl_variant_datagram
                         : ssl_variant_stream)) {
      std::cerr << "Couldn't compute version range from options.\n";
      return false;
    }

    rv = SSL_VersionRangeSet(ssl_fd_, &vrange);
    if (rv != SECSuccess) {
      std::cerr << "Couldn't set version range to [" << vrange.min << ","
                << vrange.max << "].\n";
      return false;
    }

    rv = SSL_OptionSet(ssl_fd_, SSL_NO_CACHE, false);
    if (rv != SECSuccess) {
      std::cerr << "Couldn't disable cache.\n";
      return false;
    }

    if (!cfg_.get<bool>("server")) {
      // Needed to make resumption work.
      rv = SSL_SetURL(ssl_fd_, "server");
      if (rv != SECSuccess) {
        std::cerr << "Couldn't set SNI string.\n";
        return false;
      }
    }

    rv = SSL_OptionSet(ssl_fd_, SSL_ENABLE_EXTENDED_MASTER_SECRET, PR_TRUE);
    if (rv != SECSuccess) {
      std::cerr << "Couldn't enable extended master secret.\n";
      return false;
    }

    if (!EnableNonExportCiphers()) {
      std::cerr << "Couldn't fix ciphersuite config.\n";
      return false;
    }

    return true;
  }

  bool EnableNonExportCiphers() {
    for (size_t i = 0; i < SSL_NumImplementedCiphers; ++i) {
      SSLCipherSuiteInfo csinfo;

      SECStatus rv = SSL_GetCipherSuiteInfo(SSL_ImplementedCiphers[i], &csinfo,
                                            sizeof(csinfo));
      if (rv != SECSuccess) {
        return false;
      }

      rv = SSL_CipherPrefSet(ssl_fd_, SSL_ImplementedCiphers[i], PR_TRUE);
      if (rv != SECSuccess) {
        return false;
      }
    }
    return true;
  }

  // Dummy auth certificate hook.
  static SECStatus AuthCertificateHook(void* arg, PRFileDesc* fd,
                                       PRBool checksig, PRBool isServer) {
    return SECSuccess;
  }

  static SECStatus GetClientAuthDataHook(void* self, PRFileDesc* fd,
                                         CERTDistNames* caNames,
                                         CERTCertificate** cert,
                                         SECKEYPrivateKey** privKey) {
    TestAgent* a = static_cast<TestAgent*>(self);
    *cert = CERT_DupCertificate(a->cert_);
    *privKey = SECKEY_CopyPrivateKey(a->key_);
    return SECSuccess;
  }

  SECStatus Handshake() {
    SECStatus rv;
    do {
      rv = SSL_ForceHandshake(ssl_fd_);
    } while ((rv == SECWouldBlock
              // Sigh:
              || (rv == SECFailure && PR_GetError() == PR_WOULD_BLOCK_ERROR))
             && SleepUntilReadable());
    return rv;
  }

  // Implement a trivial echo client/server. Read bytes from the other side,
  // flip all the bits, and send them back.
  SECStatus ReadWrite() {
    for (;;) {
      uint8_t block[512];
      int32_t rv;
      do {
        rv = PR_Read(ssl_fd_, block, sizeof(block));
      } while (rv < 0 && PR_GetError() == PR_WOULD_BLOCK_ERROR
               && SleepUntilReadable());
      if (rv < 0) {
        std::cerr << "Failure reading\n";
        return SECFailure;
      }
      if (rv == 0) return SECSuccess;

      int32_t len = rv;
      for (int32_t i = 0; i < len; ++i) {
        block[i] ^= 0xff;
      }

      do {
        rv = PR_Write(ssl_fd_, block, len);
      } while (rv < 0 && PR_GetError() == PR_WOULD_BLOCK_ERROR
               && SleepUntilReadable());
      if (rv != len) {
        std::cerr << "Write failure\n";
        return SECFailure;
      }
    }
    return SECSuccess;
  }

  SECStatus DoExchange() {
    SECStatus rv = Handshake();
    if (rv != SECSuccess) {
      PRErrorCode err = PR_GetError();
      std::cerr << "Handshake failed with error=" << err << FormatError(err)
                << std::endl;
      return SECFailure;
    }

    rv = ReadWrite();
    if (rv != SECSuccess) {
      PRErrorCode err = PR_GetError();
      std::cerr << "ReadWrite failed with error=" << FormatError(err)
                << std::endl;
      return SECFailure;
    }

    return SECSuccess;
  }

 private:
  const Config& cfg_;
  PRFileDesc* pr_fd_;
  PRFileDesc* ssl_fd_;
  CERTCertificate* cert_;
  SECKEYPrivateKey* key_;
};

std::unique_ptr<const Config> ReadConfig(int argc, char** argv) {
  std::unique_ptr<Config> cfg(new Config());

  cfg->AddEntry<int>("port", 0);
  cfg->AddEntry<bool>("server", false);
  cfg->AddEntry<int>("resume-count", 0);
  cfg->AddEntry<std::string>("key-file", "");
  cfg->AddEntry<std::string>("cert-file", "");
  cfg->AddEntry<int>("min-version", 0);
  cfg->AddEntry<int>("max-version", 0xffff);
  for (auto flag : kVersionDisableFlags) {
    cfg->AddEntry<bool>(flag, false);
  }
  cfg->AddEntry<bool>("dtls", false);

  auto rv = cfg->ParseArgs(argc, argv);
  switch (rv) {
    case Config::kOK:
      break;
    case Config::kUnknownFlag:
      exitCodeUnimplemented = true;
    default:
      return nullptr;
  }

  // Needed to change to std::unique_ptr<const Config>
  return std::move(cfg);
}


bool RunCycle(std::unique_ptr<const Config>& cfg) {
  std::unique_ptr<TestAgent> agent(TestAgent::Create(*cfg));
  return agent && agent->DoExchange() == SECSuccess;
}

int GetExitCode(bool success) {
  if (exitCodeUnimplemented) {
    return 89;
  }

  if (success) {
    return 0;
  }

  return 1;
}

int main(int argc, char** argv) {
  std::unique_ptr<const Config> cfg = ReadConfig(argc, argv);
  if (!cfg) {
    return GetExitCode(false);
  }

  if (cfg->get<bool>("server")) {
    if (SSL_ConfigServerSessionIDCache(1024, 0, 0, ".") != SECSuccess) {
      std::cerr << "Couldn't configure session cache\n";
      return 1;
    }
  }

  if (NSS_NoDB_Init(nullptr) != SECSuccess) {
    return 1;
  }

  // Run a single test cycle.
  bool success = RunCycle(cfg);

  int resume_count = cfg->get<int>("resume-count");
  while (success && resume_count-- > 0) {
    std::cout << "Resuming" << std::endl;
    success = RunCycle(cfg);
  }

  SSL_ClearSessionCache();

  if (cfg->get<bool>("server")) {
    SSL_ShutdownServerSessionIDCache();
  }

  if (NSS_Shutdown() != SECSuccess) {
    success = false;
  }

  return GetExitCode(success);
}
