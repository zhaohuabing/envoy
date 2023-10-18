#include "source/extensions/credentials/basic_auth/basic_auth_impl.h"

namespace Envoy {
namespace Extensions {
namespace Credentials {
namespace BasicAuth {

BasicAuthCredentialInjector::BasicAuthCredentialInjector(std::string username, std::string password)
    : username_(username), password_(password) {}

bool BasicAuthCredentialInjector::inject(RequestHeaderMap& headers, bool overrite) {
  if (!overrite && !headers.get(Http::LowerCaseString("Authorization")).empty()) {
    return false;
  }

  headers.setCopy(Http::LowerCaseString("Authorization"), "Basic " + username_ + ":" + password_);
  return true;
}

} // namespace BasicAuth
} // namespace Credentials
} // namespace Extensions
} // namespace Envoy
