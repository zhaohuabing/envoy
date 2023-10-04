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

namespace {
Secret::GenericSecretConfigProviderSharedPtr
secretsProvider(const envoy::extensions::transport_sockets::tls::v3::SdsSecretConfig& config,
                Secret::SecretManager& secret_manager,
                Server::Configuration::TransportSocketFactoryContext& transport_socket_factory,
                Init::Manager& init_manager) {
  if (config.has_sds_config()) {
    return secret_manager.findOrCreateGenericSecretProvider(config.sds_config(), config.name(),
                                                            transport_socket_factory, init_manager);
  } else {
    return secret_manager.findStaticGenericSecretProvider(config.name());
  }
}
} // namespace

Http::FilterFactoryCb FilterFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::oauth2::v3::OAuth2& proto,
    const std::string& stats_prefix, Server::Configuration::FactoryContext& context) {
  if (!proto.has_config()) {
    throw EnvoyException("config must be present for global config");
  }

  const auto& proto_config = proto.config();
  const auto& credentials = proto_config.credentials();

  const auto& token_secret = credentials.token_secret();
  const auto& hmac_secret = credentials.hmac_secret();

  auto& cluster_manager = context.clusterManager();
  auto& secret_manager = cluster_manager.clusterManagerFactory().secretManager();
  auto& transport_socket_factory = context.getTransportSocketFactoryContext();
  auto secret_provider_token_secret = secretsProvider(
      token_secret, secret_manager, transport_socket_factory, context.initManager());
  if (secret_provider_token_secret == nullptr) {
    throw EnvoyException("invalid token secret configuration");
  }
  auto secret_provider_hmac_secret =
      secretsProvider(hmac_secret, secret_manager, transport_socket_factory, context.initManager());
  if (secret_provider_hmac_secret == nullptr) {
    throw EnvoyException("invalid HMAC secret configuration");
  }

  auto secret_reader = std::make_shared<SDSSecretReader>(
      secret_provider_token_secret, secret_provider_hmac_secret, context.api());

  auto oauth2_config = std::make_shared<OAuth2Config>(proto_config, cluster_manager);
  auto filter_config = std::make_shared<FilterConfig>(oauth2_config, secret_reader,
                                               context.scope(), stats_prefix);

  return
      [&context, filter_config, &cluster_manager](Http::FilterChainFactoryCallbacks& callbacks) -> void {
        std::unique_ptr<OAuth2Client> oauth_client =
            std::make_unique<OAuth2ClientImpl>(cluster_manager, filter_config->oauthTokenEndpoint()); //TODO: create oauth_client per route
        callbacks.addStreamDecoderFilter(
            std::make_shared<OAuth2Filter>(filter_config, std::move(oauth_client), context.timeSource()));
      };
}

Router::RouteSpecificFilterConfigConstSharedPtr FilterFactory::createRouteSpecificFilterConfigTyped(
      const envoy::extensions::filters::http::oauth2::v3::OAuth2& proto,
      Server::Configuration::ServerFactoryContext& context, ProtobufMessage::ValidationVisitor&){
  if (!proto.has_config()) {
    throw EnvoyException("config must be present for per route config");
  }
  return std::make_shared<OAuth2Config>(proto);
}

/*
 * Static registration for the OAuth2 filter. @see RegisterFactory.
 */
REGISTER_FACTORY(FilterFactory, Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace Oauth2
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
