#pragma once

#include "source/common/common/logger.h"

#include "source/extensions/filters/http/common/pass_through_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace BasicAuth {

// The Envoy filter to process HTTP basic auth.
class BasicAuthFilter : public Http::PassThroughFilter,
               public Logger::Loggable<Logger::Id::basic_auth> {
public:
  BasicAuthFilter(){};

  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers, bool) override;
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) override;

private:
    // The callback function.
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_;
};

} // namespace BasicAuth
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
