#pragma once

#include "source/extensions/credentials/common/credential.h"

namespace Envoy {
namespace Extensions {
namespace Credentials {
namespace BasicAuth {

/**
 * Implementation of credential injector's interface.
 */
class BasicAuthImpl : public Common::CredentialInjector {
public:
  BasicAuthImpl(std::string username, std::string password);

  // Common::CredentialInjector
  virtual void inject(RequestHeaderMap& headers) override;

private:
  std::string username_;
  std::string password_;
};

} // namespace BasicAuth
} // namespace Credentials
} // namespace Extensions
} // namespace Envoy
