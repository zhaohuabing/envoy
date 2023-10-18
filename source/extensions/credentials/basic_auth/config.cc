#include "source/extensions/compression/gzip/compressor/config.h"

namespace Envoy {
namespace Extensions {
namespace Credentials {
namespace BasicAuth {

common::CredentialInjectorSharedPtr
BasicAuthCredentialInjectorFactory::createCredentialInjectorFromProtoTyped(
    const BasicAuth& config, Server::Configuration::FactoryContext&) {
  // todo: retrive username and password from config
  return std::make_shared<BasicAuthCredentialInjector>(config.username(), "password");
}

/**
 * Static registration for the basic auth credential injector. @see
 * NamedCredentialInjectorConfigFactory.
 */
REGISTER_FACTORY(BasicAuthCredentialInjectorFactory, Common::NamedCredentialInjectorConfigFactory);

} // namespace Compressor
} // namespace Gzip
} // namespace Compression
} // namespace Extensions
} // namespace Envoy
