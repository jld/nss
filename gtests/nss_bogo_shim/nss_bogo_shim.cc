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
#include "secerr.h"
#include "ssl.h"
#include "ssl3prot.h"
#include "sslerr.h"
#include "sslproto.h"

#include "bogo_packet.h"
#include "nsskeys.h"

static const char* kVersionDisableFlags[] = {"no-ssl3", "no-tls1", "no-tls11",
                                             "no-tls12", "no-tls13"};

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
      if (!key_) return false;
    }
    if (cfg_.get<std::string>("cert-file") != "") {
      cert_ = ReadCertificate(cfg_.get<std::string>("cert-file"));
      if (!cert_) return false;
    }

    // Needed because certs are not entirely valid.
    rv = SSL_AuthCertificateHook(ssl_fd_, AuthCertificateHook, this);
    if (rv != SECSuccess) return false;

    if (cfg_.get<bool>("server")) {
      // Server
      rv = SSL_ConfigServerCert(ssl_fd_, cert_, key_, nullptr, 0);
      if (rv != SECSuccess) {
        std::cerr << "Couldn't configure server cert\n";
        return false;
      }

    } else if (key_ && cert_) {
      // Client.
      rv = SSL_GetClientAuthDataHook(ssl_fd_, GetClientAuthDataHook, this);
      if (rv != SECSuccess) return false;
    }

    return true;
  }

  static bool ConvertFromWireVersion(SSLProtocolVariant variant,
                                     int wire_version, uint16_t* lib_version) {
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
    // Override the library maximum -- DTLS 1.3 isn't specified yet,
    // and enabling TLS 1.3 features in DTLS mode causes disagreements
    // with BoGo.  (Bug 1314819)
    if (variant == ssl_variant_datagram) {
      supported.max = SSL_LIBRARY_VERSION_DTLS_1_2;
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
    if (rv != SECSuccess) return false;

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

    SSLVersionRange verify_vrange;
    rv = SSL_VersionRangeGet(ssl_fd_, &verify_vrange);
    if (rv != SECSuccess) return false;
    if (vrange.min != verify_vrange.min || vrange.max != verify_vrange.max)
      return false;

    rv = SSL_OptionSet(ssl_fd_, SSL_NO_CACHE, false);
    if (rv != SECSuccess) return false;

    auto alpn = cfg_.get<std::string>("advertise-alpn");
    if (!alpn.empty()) {
      assert(!cfg_.get<bool>("server"));

      rv = SSL_OptionSet(ssl_fd_, SSL_ENABLE_ALPN, PR_TRUE);
      if (rv != SECSuccess) return false;

      rv = SSL_SetNextProtoNego(
          ssl_fd_, reinterpret_cast<const unsigned char*>(alpn.c_str()),
          alpn.size());
      if (rv != SECSuccess) return false;
    }

    if (cfg_.get<bool>("fallback-scsv")) {
      rv = SSL_OptionSet(ssl_fd_, SSL_ENABLE_FALLBACK_SCSV, PR_TRUE);
      if (rv != SECSuccess) return false;
    }

    if (cfg_.get<bool>("false-start")) {
      rv = SSL_OptionSet(ssl_fd_, SSL_ENABLE_FALSE_START, PR_TRUE);
      if (rv != SECSuccess) return false;
    }

    if (cfg_.get<bool>("enable-ocsp-stapling")) {
      rv = SSL_OptionSet(ssl_fd_, SSL_ENABLE_OCSP_STAPLING, PR_TRUE);
      if (rv != SECSuccess) return false;
    }

    bool requireClientCert = cfg_.get<bool>("require-any-client-certificate");
    if (requireClientCert || cfg_.get<bool>("verify-peer")) {
      assert(cfg_.get<bool>("server"));

      rv = SSL_OptionSet(ssl_fd_, SSL_REQUEST_CERTIFICATE, PR_TRUE);
      if (rv != SECSuccess) return false;

      rv = SSL_OptionSet(
          ssl_fd_, SSL_REQUIRE_CERTIFICATE,
          requireClientCert ? SSL_REQUIRE_ALWAYS : SSL_REQUIRE_NO_ERROR);
      if (rv != SECSuccess) return false;
    }

    if (!cfg_.get<bool>("server")) {
      // Needed to make resumption work.
      rv = SSL_SetURL(ssl_fd_, "server");
      if (rv != SECSuccess) return false;
    }

    rv = SSL_OptionSet(ssl_fd_, SSL_ENABLE_EXTENDED_MASTER_SECRET, PR_TRUE);
    if (rv != SECSuccess) return false;

    if (!EnableNonExportCiphers()) return false;

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

  bool ShouldTryAgain() {
    // Timeouts aren't supported yet, because:
    //
    // 1. See the large comment about blocking/nonblocking read on the
    // real socket in BogoPacketImpl::Read; neither one works for all
    // tests and this needs to be investigated and fixed.
    //
    // 2. We need to "sleep" in a way that affects the DTLS retransmit
    // timers but not actually sleep -- not only is wasting several
    // minutes per test run annoying, but also the BoGo harness will
    // time out in some cases.
    if (PR_GetError() == PR_WOULD_BLOCK_ERROR) {
      BoGoPacket* packetized = BoGoPacket::FromDesc(ssl_fd_);
      PR_ASSERT(packetized);
      if (packetized && packetized->ReceivedTimeout()) {
        // Got timeout packet.
        exitCodeUnimplemented = true;
        return false;
      }
      // The WOULD_BLOCK must be from inside NSS; retry.
      // (SendSplitAlert-* and LargeCiphertext-DTLS cause this.)
      return true;
    }
    // Some other error.
    return false;
  }

  SECStatus Handshake() {
    SECStatus rv;
    do {
      rv = SSL_ForceHandshake(ssl_fd_);
    } while (rv == SECFailure && ShouldTryAgain());
    return rv;
  }

  // Implement a trivial echo client/server. Read bytes from the other side,
  // flip all the bits, and send them back.
  SECStatus ReadWrite() {
    for (;;) {
      // For DTLS, this buffer needs to be large enough for a
      // maximum-length application data message.
      uint8_t block[16384];
      int32_t rv;
      do {
        rv = PR_Read(ssl_fd_, block, sizeof(block));
      } while (rv < 0 && ShouldTryAgain());
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
      } while (rv < 0 && ShouldTryAgain());
      if (rv != len) {
        std::cerr << "Write failure\n";
        PORT_SetError(SEC_ERROR_OUTPUT_LEN);
        return SECFailure;
      }
    }
    return SECSuccess;
  }

  // Write bytes to the other side then read them back and check
  // that they were correctly XORed as in ReadWrite.
  SECStatus WriteRead() {
    static const uint8_t ch = 'E';

    // We do 600-byte blocks to provide mis-alignment of the
    // reader and writer.
    uint8_t block[600];
    memset(block, ch, sizeof(block));
    int32_t rv = PR_Write(ssl_fd_, block, sizeof(block));
    if (rv != sizeof(block)) {
      std::cerr << "Write failure\n";
      PORT_SetError(SEC_ERROR_OUTPUT_LEN);
      return SECFailure;
    }

    size_t left = sizeof(block);
    while (left) {
      int32_t rv = PR_Read(ssl_fd_, block, left);
      if (rv < 0) {
        std::cerr << "Failure reading\n";
        return SECFailure;
      }
      if (rv == 0) {
        PORT_SetError(SEC_ERROR_INPUT_LEN);
        return SECFailure;
      }

      int32_t len = rv;
      for (int32_t i = 0; i < len; ++i) {
        if (block[i] != (ch ^ 0xff)) {
          PORT_SetError(SEC_ERROR_BAD_DATA);
          return SECFailure;
        }
      }
      left -= len;
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

    if (cfg_.get<bool>("write-then-read")) {
      rv = WriteRead();
      if (rv != SECSuccess) {
        PRErrorCode err = PR_GetError();
        std::cerr << "WriteRead failed with error=" << FormatError(err)
                  << std::endl;
        return SECFailure;
      }
    } else {
      rv = ReadWrite();
      if (rv != SECSuccess) {
        PRErrorCode err = PR_GetError();
        std::cerr << "ReadWrite failed with error=" << FormatError(err)
                  << std::endl;
        return SECFailure;
      }
    }

    auto alpn = cfg_.get<std::string>("expect-alpn");
    if (!alpn.empty()) {
      SSLNextProtoState state;
      char chosen[256];
      unsigned int chosen_len;
      rv = SSL_GetNextProto(ssl_fd_, &state,
                            reinterpret_cast<unsigned char*>(chosen),
                            &chosen_len, sizeof(chosen));
      if (rv != SECSuccess) {
        PRErrorCode err = PR_GetError();
        std::cerr << "SSL_GetNextProto failed with error=" << FormatError(err)
                  << std::endl;
        return SECFailure;
      }

      assert(chosen_len <= sizeof(chosen));
      if (std::string(chosen, chosen_len) != alpn) {
        std::cerr << "Unexpected ALPN selection" << std::endl;
        return SECFailure;
      }
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
  cfg->AddEntry<bool>("fallback-scsv", false);
  cfg->AddEntry<bool>("false-start", false);
  cfg->AddEntry<bool>("enable-ocsp-stapling", false);
  cfg->AddEntry<bool>("write-then-read", false);
  cfg->AddEntry<bool>("require-any-client-certificate", false);
  cfg->AddEntry<bool>("verify-peer", false);
  cfg->AddEntry<std::string>("advertise-alpn", "");
  cfg->AddEntry<std::string>("expect-alpn", "");
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
