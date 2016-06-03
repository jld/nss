// -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*-
// vim: set ts=2 et sw=2 tw=80:
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

#include <string.h>
#ifdef XP_UNIX
#include <sys/resource.h>
#endif

#include <memory> // for unique_ptr

#include "prthread.h"

#include "gtest_utils.h"
#include "keyhi.h"
#include "scoped_ptrs.h"
#include "ssl.h"
#include "sslerr.h"
#include "sslimpl.h"
#include "test_io.h"

namespace nss_test {

// FIXME, bug 1243238: move this into a common location.
class SuppressCoreDump {
public:
  SuppressCoreDump();
  ~SuppressCoreDump();
private:
#ifdef XP_UNIX
  struct ::rlimit _saved_limit;
#endif
};

#ifdef XP_UNIX
SuppressCoreDump::SuppressCoreDump() {
  _saved_limit.rlim_cur = _saved_limit.rlim_max = RLIM_INFINITY;
  getrlimit(RLIMIT_CORE, &_saved_limit);
  struct ::rlimit new_limit = _saved_limit;
  new_limit.rlim_cur = 0;
  setrlimit(RLIMIT_CORE, &new_limit);
}
SuppressCoreDump::~SuppressCoreDump() {
  setrlimit(RLIMIT_CORE, &_saved_limit);
}
#else
SuppressCoreDump::SuppressCoreDump() { }
SuppressCoreDump::~SuppressCoreDump() { }
#endif // XP_UNIX

#ifdef DEBUG
#define DEBUG_ASSERT_DEATH(stmt, regex) ASSERT_DEATH_IF_SUPPORTED({ \
      SuppressCoreDump _coreDumpGuard;                              \
      stmt;                                                         \
    }, regex)
#else
// Assert that the bad thing doesn't crash by doing it anyway:
#define DEBUG_ASSERT_DEATH(stmt, regex) stmt
#endif // DEBUG

class InternalSocketTest : public ::testing::Test {
public:
  InternalSocketTest() : fd_(nullptr), ss_(nullptr) { }
  ~InternalSocketTest() {
    if (fd_) {
      PR_Close(fd_);
    }
  }

  void SetUp() {
    fd_ = DummyPrSocket::CreateFD("fake", STREAM);
    ASSERT_NE(nullptr, fd_);
    ASSERT_EQ(fd_, SSL_ImportFD(nullptr, fd_));
    ss_ = ssl_FindSocket(fd_);
    ASSERT_NE(nullptr, ss_);
  }

protected:
  PRFileDesc *fd_;
  sslSocket *ss_;
};

class InternalKeyPairTest : public ::testing::Test {
public:
  InternalKeyPairTest() : keys_(nullptr) { }
  ~InternalKeyPairTest() {
    if (keys_) {
      ssl3_FreeKeyPair(keys_);
    }
  }

  void SetUp() {
    static const ECName curve = ec_secp256r1;
    ScopedSECItem ecParams;
    ScopedSECKEYPrivateKey privKey;
    ScopedSECKEYPublicKey pubKey;

    ecParams.reset(SECITEM_AllocItem(nullptr, // no arena
                                     nullptr, // not reallocating
                                     0));     // length
    ASSERT_TRUE(ecParams);
    ASSERT_EQ(SECSuccess,
              ssl3_ECName2Params(nullptr, // no arena
                                 curve, ecParams.get()));
    EXPECT_NE(nullptr, ecParams->data);
    EXPECT_NE(0, ecParams->len);

    {
      SECKEYPublicKey *tmpPubKey;
      privKey.reset(SECKEY_CreateECPrivateKey(ecParams.get(), &tmpPubKey,
                                              nullptr)); // no UI context
      pubKey.reset(tmpPubKey);
    }
    ASSERT_TRUE(privKey);
    ASSERT_TRUE(pubKey);

    keys_ = ssl3_NewKeyPair(privKey.release(), pubKey.release());
    ASSERT_TRUE(keys_);
  }

protected:
  ssl3KeyPair *keys_;
};

template<class F>
static void
ThreadFunctionalMain(void *vp) {
  (*static_cast<const F*>(vp))();
}

template<class F>
static void
RunOnThreads(size_t n, const F& func)
{
  void* vp = const_cast<void*>(static_cast<const void*>(&func));
  std::unique_ptr<PRThread*[]> threads(new PRThread*[n]);

  for (size_t i = 0; i < n; ++i) {
    threads[i] = PR_CreateThread(PR_SYSTEM_THREAD,
                                 ThreadFunctionalMain<F>,
                                 vp,
                                 PR_PRIORITY_NORMAL,
                                 PR_GLOBAL_THREAD,
                                 PR_JOINABLE_THREAD,
                                 0); // use default stack size
    ASSERT_NE(nullptr, threads[i]);
  }
  for (size_t i = 0; i < n; ++i) {
    EXPECT_EQ(PR_SUCCESS, PR_JoinThread(threads[i]));
  }
}

TEST(SSL3Random, SmokeTest) {
  SSL3Random r0, r1;

  // ssl3_GetNewRandom uses the "rand" field, but other code memcpy()s
  // the first SSL3_RANDOM_LENGTH bytes, so make sure that does what's
  // expected:
  ASSERT_LE(SSL3_RANDOM_LENGTH, sizeof(SSL3Random));
  ASSERT_EQ(static_cast<void*>(&r0), static_cast<void*>(r0.rand));

  // Check that two successive random numbers aren't equal.  This is
  // wrong with probability 2**-256 per test run, which is negligible.
  ASSERT_EQ(SECSuccess, ssl3_GetNewRandom(&r0));
  ASSERT_EQ(SECSuccess, ssl3_GetNewRandom(&r1));
  EXPECT_NE(0, memcmp(&r0, &r1, SSL3_RANDOM_LENGTH));
}

typedef InternalSocketTest InternalSocketDeathTest;

TEST_F(InternalSocketDeathTest, DoubleUnlockReader) {
  // Run this twice -- on non-debug builds, an excess unlock is ignored.
  for (int i = 0; i < 2; ++i) {
    SSL_LOCK_READER(ss_);
    SSL_UNLOCK_READER(ss_);
    DEBUG_ASSERT_DEATH(SSL_UNLOCK_READER(ss_), "Assertion failure:");
  }
}

TEST_F(InternalSocketDeathTest, DoubleUnlock1stHandshake) {
  // Run this twice -- on non-debug builds, an excess unlock is ignored.
  for (int i = 0; i < 2; ++i) {
    EXPECT_FALSE(ssl_Have1stHandshakeLock(ss_));
    ssl_Get1stHandshakeLock(ss_);
    EXPECT_TRUE(ssl_Have1stHandshakeLock(ss_));
    ssl_Release1stHandshakeLock(ss_);
    EXPECT_FALSE(ssl_Have1stHandshakeLock(ss_));
    DEBUG_ASSERT_DEATH(ssl_Release1stHandshakeLock(ss_), "Assertion failure:");
  }
}

TEST_F(InternalKeyPairTest, RefCountSimple) {
  EXPECT_EQ(1, keys_->refCount);
  EXPECT_EQ(keys_, ssl3_GetKeyPairRef(keys_));
  EXPECT_EQ(2, keys_->refCount);
  ssl3_FreeKeyPair(keys_);
  EXPECT_EQ(1, keys_->refCount);
}

TEST_F(InternalKeyPairTest, RefCountThreaded) {
  static const size_t numThreads = 5;
  static const size_t iterations = 1000000;
  ssl3KeyPair *const keys = keys_;

  RunOnThreads(numThreads, [=]{
    for (size_t i = 0; i < iterations; ++i) {
      ssl3_GetKeyPairRef(keys);
    }
  });

  ASSERT_EQ(1 + numThreads * iterations, size_t(keys_->refCount));

  RunOnThreads(numThreads, [=]{
    for (size_t i = 0; i < iterations; ++i) {
      ssl3_FreeKeyPair(keys);
    }
  });

  EXPECT_EQ(1, keys_->refCount);
}

} // namespace nss_test
