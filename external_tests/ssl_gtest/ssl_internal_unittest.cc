/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "ssl.h"
#include "sslerr.h"
#include "keyhi.h"

extern "C" {
// Work around sslimpl.h being non-C++-safe.
#define explicit explicit_
#include "sslimpl.h"
#undef explicit
}

#include "gtest_utils.h"
#include "scoped_ptrs.h"
#include "test_io.h"

#include "prthread.h"

#include <memory> // for unique_ptr
#include <string.h>

#ifdef GTEST_HAS_DEATH_TEST
#ifdef DEBUG
#define DEBUG_ASSERT_DEATH(stmt, regex) ASSERT_DEATH(stmt, regex)
#else
// Assert that the bad thing doesn't crash by doing it anyway:
#define DEBUG_ASSERT_DEATH(stmt, regex) stmt
#endif // DEBUG
#endif // GTEST_HAS_DEATH_TEST

namespace nss_test {

class InternalSocketTest : public ::testing::Test {
protected:
  PRFileDesc *fd_;
  sslSocket *ss_;
public:
  InternalSocketTest() : fd_(nullptr), ss_(nullptr) { }
  ~InternalSocketTest() {
    TearDown();
  }

  void SetUp() {
    fd_ = DummyPrSocket::CreateFD("fake", STREAM);
    EXPECT_TRUE(fd_);
    EXPECT_EQ(fd_, SSL_ImportFD(nullptr, fd_));
    ss_ = ssl_FindSocket(fd_);
    EXPECT_TRUE(ss_);
  }

  void TearDown() {
    if (fd_) {
      PR_Close(fd_);
      fd_ = nullptr;
      ss_ = nullptr;
    }
  }
};

class InternalKeyPairTest : public ::testing::Test {
protected:
  ssl3KeyPair *keys_;
public:
  InternalKeyPairTest() : keys_() { }
  ~InternalKeyPairTest() {
    TearDown();
  }

  void SetUp() {
    static const ECName curve = ec_secp256r1;
    ScopedSECItem ecParams;
    ScopedSECKEYPrivateKey privKey;
    ScopedSECKEYPublicKey pubKey;

    ecParams.reset(SECITEM_AllocItem(/* arena */ nullptr,
                                     /* existing item */ nullptr,
                                     /* len */ 0));
    EXPECT_TRUE(ecParams);
    EXPECT_EQ(SECSuccess,
              ssl3_ECName2Params(/* arena */ nullptr, curve, ecParams.get()));
    EXPECT_NE(nullptr, ecParams->data);
    EXPECT_NE(0, ecParams->len);

    {
      SECKEYPublicKey *tmpPubKey;
      privKey.reset(SECKEY_CreateECPrivateKey(ecParams.get(), &tmpPubKey,
                                              /* UI context */ nullptr));
      pubKey.reset(tmpPubKey);
    }
    EXPECT_TRUE(privKey);
    EXPECT_TRUE(pubKey);

    keys_ = ssl3_NewKeyPair(privKey.release(), pubKey.release());
    EXPECT_TRUE(keys_);
  }

  void TearDown() {
    if (keys_) {
      ssl3_FreeKeyPair(keys_);
      keys_ = nullptr;
    }
  }
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
                                 0 /* us default stack size */);
    EXPECT_NE(nullptr, threads[i]);
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

#ifdef GTEST_HAS_DEATH_TEST
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
#endif

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
