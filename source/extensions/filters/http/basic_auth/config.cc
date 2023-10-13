#include "source/extensions/filters/http/basic_auth/config.h"

#include "source/extensions/filters/http/basic_auth/basic_auth.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace BasicAuth {

Http::FilterFactoryCb CacheFilterFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::basic_auth::v3::BasicAuth& ,
    const std::string& , Server::Configuration::FactoryContext& ) {
  }

  return [](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamDecoderFilter(std::make_shared<BasicAuthFilter>());
  };
}

REGISTER_FACTORY(CacheFilterFactory, Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace BasicAuth
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
