#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#define TEST_EXPORT __declspec(dllexport)
#else
#define TEST_EXPORT __attribute__((visibility("default")))
#endif

TEST_EXPORT int plugin_crypto_test_all_zero(const uint8_t *buffer,
                                            size_t length) {
  if (buffer == NULL && length != 0) return 0;
  for (size_t i = 0; i < length; i++) {
    if (buffer[i] != 0) return 0;
  }
  return 1;
}
