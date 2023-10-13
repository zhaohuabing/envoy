#include "source/extensions/filters/http/basic_authn/filter.h"

#include "source/common/http/headers.h"

using ::google::jwt_verify::Status;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace BasicAuth {

Http::FilterHeadersStatus BasicAuthFilter::decodeHeaders(Http::RequestHeaderMap& headers, bool) {
  ENVOY_LOG(debug, "Called Filter : {}", __func__);
  return Http::FilterHeadersStatus::Continue;
}

void BasicAuthFilter::setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) {
  ENVOY_LOG(debug, "Called Filter : {}", __func__);
  decoder_callbacks_ = &callbacks;
}

} // namespace BasicAuth
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
