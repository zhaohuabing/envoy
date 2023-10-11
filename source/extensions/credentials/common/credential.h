#pragma once

#include "envoy/http/header_map.h"

namespace Envoy {
namespace Extensions {
namespace Credentials {
namespace Common {

/**
 * Credential injector injects credential to HTTP headers.
 */
class CredentialInjector {
public:
  virtual ~CredentialInjector() = default;

  /**
   * Inject credential to HTTP headers.
   * @param headers supplies the reference to HTTP headers. The credential will be injected into the headers.
   */
  virtual void inject(RequestHeaderMap& headers) PURE;
};

using CredentialInjectorPtr = std::unique_ptr<CredentialInjector>;

} // namespace Common
} // namespace Credential
} // namespace Extensions
} // namespace Envoy
