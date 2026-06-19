#include "include/plugin_crypto/plugin_crypto_plugin.h"

#include <windows.h>

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>

#include <memory>
#include <sstream>
#include <string>

namespace plugin_crypto {

// static
void PluginCryptoPlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarWindows* registrar) {
  auto channel =
      std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
          registrar->messenger(), "plugin_crypto",
          &flutter::StandardMethodCodec::GetInstance());

  auto plugin = std::make_unique<PluginCryptoPlugin>();

  channel->SetMethodCallHandler(
      [plugin_pointer = plugin.get()](const auto& call, auto result) {
        plugin_pointer->HandleMethodCall(call, std::move(result));
      });

  registrar->AddPlugin(std::move(plugin));
}

PluginCryptoPlugin::PluginCryptoPlugin() {}

PluginCryptoPlugin::~PluginCryptoPlugin() {}

void PluginCryptoPlugin::HandleMethodCall(
    const flutter::MethodCall<flutter::EncodableValue>& method_call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  const std::string& method = method_call.method_name();

  if (method == "getPlatformVersion") {
    std::ostringstream version_stream;
    version_stream << "Windows ";
    // Get Windows version info
    OSVERSIONINFOEXW osvi = {};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
#pragma warning(suppress : 4996)
    GetVersionExW(reinterpret_cast<LPOSVERSIONINFOW>(&osvi));
    version_stream << osvi.dwMajorVersion << "." << osvi.dwMinorVersion
                   << " (build " << osvi.dwBuildNumber << ")";
    result->Success(flutter::EncodableValue(version_stream.str()));
  } else {
    result->NotImplemented();
  }
}

}  // namespace plugin_crypto
