#include "source/extensions/compression/gzip/compressor/config.h"

namespace Envoy {
namespace Extensions {
namespace Credentials {
namespace BasicAuth {

common::CredentialInjectorPtr
BasicAuthCredentialInjectorFactory::createCredentialInjectorFromProtoTyped(
      const envoy::extensions::credentials::basic_auth::v3::BasicAuth& config,
      Server::Configuration::FactoryContext&) {
  //todo: retrive username and password from config
  return std::make_unique<BasicAuthCredentialInjector>(config.username(), "password");
}

/**
 * Static registration for the basic auth credential injector. @see NamedCredentialInjectorConfigFactory.
 */
REGISTER_FACTORY(BasicAuthCredentialInjectorFactory,
                 Common::NamedCredentialInjectorConfigFactory);

} // namespace Compressor
} // namespace Gzip
} // namespace Compression
} // namespace Extensions
} // namespace Envoy
