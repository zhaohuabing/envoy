#include "source/extensions/filters/http/credential_injector/config.h"

#include "source/common/config/datasource.h"
#include "source/extensions/filters/http/credential_injector/credential_injector_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace CredentialInjector {

using envoy::extensions::filters::http::credential_injector::v3::CredentialInjector;

Http::FilterFactoryCb CredentialInjectorFilterFactory::createFilterFactoryFromProtoTyped(
    const CredentialInjector& proto_config, const std::string& stats_prefix,
    Server::Configuration::FactoryContext& context) {
  const std::string type{
      TypeUtil::typeUrlToDescriptorFullName(proto_config.credential().typed_config().type_url())};
  Credentials::Common::NamedCredentialInjectorConfigFactory* const config_factory =
      Registry::FactoryRegistry<
          Credentials::Common::NamedCredentialInjectorConfigFactory>::getFactoryByType(type);
  if (config_factory == nullptr) {
    throw EnvoyException(
        fmt::format("Didn't find a registered implementation for type: '{}'", type));
  }

  ProtobufTypes::MessagePtr message = Config::Utility::translateAnyToFactoryConfig(
      proto_config.credential().typed_config(), context.messageValidationVisitor(),
      *config_factory);
  Credentials::Common::CredentialInjectorPtr compressor_factory =
      config_factory->createCredentialInjectorFromProto(*message, context);

  FilterConfigSharedPtr config =
      std::make_shared<FilterConfig>(users, stats_prefix, context.scope());
  return [config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamDecoderFilter(std::make_shared<CredentialInjectorFilter>(config));
  };
}

REGISTER_FACTORY(CredentialInjectorFilterFactory,
                 Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace CredentialInjector
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
