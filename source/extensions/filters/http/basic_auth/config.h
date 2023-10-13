#pragma once

#include "envoy/extensions/filters/http/basic_auth/v3/basic_auth.pb.h"
#include "envoy/extensions/filters/http/basic_auth/v3/basic_auth.pb.validate.h"

#include "source/extensions/filters/http/common/factory_base.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace BasicAuth {

class BasicAuthFilterFactory
    : public Common::FactoryBase<envoy::extensions::filters::http::basic_auth::v3::BasicAuth> {
public:
  CacheFilterFactory() : FactoryBase("envoy.filters.http.basic_auth") {}

private:
  Http::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const envoy::extensions::filters::http::basic_auth::v3::BasicAuth& config,
      const std::string& stats_prefix, Server::Configuration::FactoryContext& context) override;
};

} // namespace Cache
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
