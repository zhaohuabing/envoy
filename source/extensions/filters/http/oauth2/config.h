#pragma once

#include <string>

#include "envoy/extensions/filters/http/oauth2/v3/oauth.pb.h"
#include "envoy/extensions/filters/http/oauth2/v3/oauth.pb.validate.h"

#include "source/extensions/filters/http/common/factory_base.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Oauth2 {

class FilterFactory
    : public Common::FactoryBase<envoy::extensions::filters::http::oauth2::v3::OAuth2> {
public:
  FilterFactory() : FactoryBase("envoy.filters.http.oauth2") {}

private:
  Http::FilterFactoryCb createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::oauth2::v3::OAuth2& proto,
    const std::string& stats_prefix,
    Server::Configuration::FactoryContext& context) override;

  Router::RouteSpecificFilterConfigConstSharedPtr createRouteSpecificFilterConfigTyped(
    const envoy::extensions::filters::http::oauth2::v3::OAuth2& proto,
    Server::Configuration::ServerFactoryContext&,
    ProtobufMessage::ValidationVisitor&) override;
};

} // namespace Oauth2
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
