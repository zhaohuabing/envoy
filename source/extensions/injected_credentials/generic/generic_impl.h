#pragma once

#include "source/common/secret/secret_provider_impl.h"
#include "source/extensions/injected_credentials/common/credential.h"

namespace Envoy {
namespace Extensions {
namespace InjectedCredentials {
namespace Generic {

/**
 * Implementation of credential injector's interface.
 */
class GenericCredentialInjector : public Common::CredentialInjector {
public:
  GenericCredentialInjector(
      const std::string& header,
      std::shared_ptr<Secret::ThreadLocalGenericSecretProvider> secret_provider)
      : header_(header), secret_provider_(secret_provider){};

  // Common::CredentialInjector
  RequestPtr requestCredential(Callbacks& callbacks) override {
    // Generic credential injector does not need to make a request to get the credential.
    // It can get the credential from the secret directly. So it can call onSuccess() immediately.
    callbacks.onSuccess();
    return nullptr;
  };

  absl::Status inject(Http::RequestHeaderMap& headers, bool overwrite) override;

private:
  const std::string header_;
  const std::shared_ptr<Secret::ThreadLocalGenericSecretProvider> secret_provider_;
};

} // namespace Generic
} // namespace InjectedCredentials
} // namespace Extensions
} // namespace Envoy
