#include "source/extensions/filters/http/oauth2/config.h"

#include <chrono>
#include <memory>
#include <string>

#include "envoy/common/exception.h"
#include "envoy/extensions/filters/http/oauth2/v3/oauth.pb.validate.h"
#include "envoy/registry/registry.h"
#include "envoy/secret/secret_manager.h"
#include "envoy/secret/secret_provider.h"
#include "envoy/ssl/private_key/private_key.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/common/assert.h"
#include "source/common/protobuf/utility.h"
#include "source/extensions/filters/http/oauth2/filter.h"
#include "source/extensions/filters/http/oauth2/oauth.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Oauth2 {

Http::FilterFactoryCb FilterFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::oauth2::v3::OAuth2& proto,
    const std::string& stats_prefix, Server::Configuration::FactoryContext& context) {
  if (!proto.has_config()) {
    throw EnvoyException("config must be present for global config");
  }

  const auto& proto_config = proto.config();
  auto& cluster_manager = context.clusterManager();

  auto global_config = std::make_shared<OAuth2Config>(proto_config, cluster_manager);
  auto filter_config = std::make_shared<FilterConfig>(context.scope(), stats_prefix);

  return
      [&context, filter_config, global_config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
      callbacks.addStreamDecoderFilter(
            std::make_shared<OAuth2Filter>(filter_config, global_config, context.timeSource(),context));
      };
}

Router::RouteSpecificFilterConfigConstSharedPtr FilterFactory::createRouteSpecificFilterConfigTyped(
      const envoy::extensions::filters::http::oauth2::v3::OAuth2& proto,
      Server::Configuration::ServerFactoryContext& context, ProtobufMessage::ValidationVisitor&){
  if (!proto.has_config()) {
    throw EnvoyException("config must be present for per route config");
  }

  const auto& proto_config = proto.config();
  auto& cluster_manager = context.clusterManager();
  return std::make_shared<OAuth2Config>(proto_config, cluster_manager);
}

/*
 * Static registration for the OAuth2 filter. @see RegisterFactory.
 */
REGISTER_FACTORY(FilterFactory, Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace Oauth2
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy

