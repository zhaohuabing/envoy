#pragma once

#include "source/extensions/credentials/common/credential.h"

namespace Envoy {
namespace Extensions {
namespace Credentials {
namespace BasicAuth {

/**
 * Implementation of credential injector's interface.
 */
class BasicAuthCredentialInjector : public Common::CredentialInjector {
public:
  BasicAuthCredentialInjector(std::string username, std::string password);

  // Common::CredentialInjector
  bool inject(RequestHeaderMap& headers, bool overrite) override;

private:
  std::string username_;
  std::string password_;
};

} // namespace BasicAuth
} // namespace Credentials
} // namespace Extensions
} // namespace Envoy
