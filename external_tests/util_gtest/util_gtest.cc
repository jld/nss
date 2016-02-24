#include "nspr.h"
#include "prenv.h"

#include <cstdlib>

#define GTEST_HAS_RTTI 0
#include "gtest/gtest.h"

std::string g_working_dir_path;

int main(int argc, char **argv) {
  // Start the tests
  ::testing::InitGoogleTest(&argc, argv);
  g_working_dir_path = ".";

  char* workdir = PR_GetEnvSecure("NSS_GTEST_WORKDIR");
  if (workdir)
    g_working_dir_path = workdir;

  for (int i = 0; i < argc; i++) {
    if (!strcmp(argv[i], "-d")) {
      g_working_dir_path = argv[i + 1];
      ++i;
    }
  }

  int rv = RUN_ALL_TESTS();

  return rv;
}
