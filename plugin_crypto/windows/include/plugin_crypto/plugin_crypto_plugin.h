#ifndef FLUTTER_PLUGIN_PLUGIN_CRYPTO_PLUGIN_H_
#define FLUTTER_PLUGIN_PLUGIN_CRYPTO_PLUGIN_H_

#include <flutter_windows.h>

#include <functional>
#include <memory>

#include "plugin_crypto_plugin_c_api.h"

#define PLUGIN_CRYPTO_PLUGIN(obj) \
  (reinterpret_cast<PluginCryptoPlugin*>(obj))

namespace plugin_crypto {

class PluginCryptoPlugin {
 public:
  // Registers this plugin with the given registrar.
  static void RegisterWithRegistrar(
      flutter::PluginRegistrarWindows* registrar);

  PluginCryptoPlugin();
  virtual ~PluginCryptoPlugin();

  // Prevent copying.
  PluginCryptoPlugin(PluginCryptoPlugin const&) = delete;
  PluginCryptoPlugin& operator=(PluginCryptoPlugin const&) = delete;

 private:
  // Called when a method is called on this plugin's channel from Dart.
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue>& method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
};

}  // namespace plugin_crypto

#endif  // FLUTTER_PLUGIN_PLUGIN_CRYPTO_PLUGIN_H_
