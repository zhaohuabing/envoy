#include "source/extensions/credentials/basic_auth/basic_auth_impl.h"

namespace Envoy {
namespace Extensions {
namespace Credentials {
namespace BasicAuth {

BasicAuthImpl::BasicAuthImpl(std::string username, std::string password)
    : username_(username), password_(password) {}

void BasicAuthImpl::inject(RequestHeaderMap& headers) {
  headers.setCopy(Http::LowerCaseString("Authorization"), "Basic " + username_ + ":" + password_);
}

} // namespace BasicAuth
} // namespace Credentials
} // namespace Extensions
} // namespace Envoy
