#pragma once

#include "envoy/stats/stats_macros.h"

#include "source/common/common/logger.h"
#include "source/extensions/filters/http/common/pass_through_filter.h"

#include "absl/container/flat_hash_map.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace CredentialInjector {

/**
 * All Basic Auth filter stats. @see stats_macros.h
 */
#define ALL_credential_injector_STATS(COUNTER)                                                              \
  COUNTER(allowed)                                                                                 \
  COUNTER(denied)

/**
 * Struct definition for Basic Auth stats. @see stats_macros.h
 */
struct CredentialInjectorStats {
  ALL_credential_injector_STATS(GENERATE_COUNTER_STRUCT)
};

/**
 * Struct definition for username password pairs.
 */
struct User {
  // the user name
  std::string name;
  // the hashed password,  see https://httpd.apache.org/docs/2.4/misc/password_encryptions.html
  std::string hash;
};

using UserMap = absl::flat_hash_map<std::string, User>; // username, User

/**
 * Configuration for the Basic Auth filter.
 */
class FilterConfig {
public:
  FilterConfig(UserMap users, const std::string& stats_prefix, Stats::Scope& scope);
  CredentialInjectorStats& stats() { return stats_; }
  bool validateUser(const std::string& username, const std::string& password);

private:
  static CredentialInjectorStats generateStats(const std::string& prefix, Stats::Scope& scope) {
    return CredentialInjectorStats{ALL_credential_injector_STATS(POOL_COUNTER_PREFIX(scope, prefix))};
  }

  UserMap users_;
  CredentialInjectorStats stats_;
};
using FilterConfigSharedPtr = std::shared_ptr<FilterConfig>;

// The Envoy filter to process HTTP basic auth.
class CredentialInjectorFilter : public Http::PassThroughFilter,
                        public Logger::Loggable<Logger::Id::credential_injector> {
public:
  CredentialInjectorFilter(FilterConfigSharedPtr config);

  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers, bool) override;
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) override;

private:
  // The callback function.
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_;
  FilterConfigSharedPtr config_;
};

} // namespace CredentialInjector
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
