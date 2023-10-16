
#include "envoy/extensions/filters/http/basic_auth/v3/basic_auth.pb.h"

#include "source/extensions/filters/http/basic_auth/basic_auth_filter.h"

#include "test/mocks/http/mocks.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace BasicAuth {


class FilterTest : public testing::Test {
public:
  FilterTest() = default;

  void setup(const std::vector<User>& users) {
    config_ =
        std::make_shared<FilterConfig>(users, "stats", *stats_.rootScope());
    filter_ = std::make_shared<BasicAuthFilter>(config_);
    filter_->setDecoderFilterCallbacks(decoder_filter_callbacks_);
  }

  NiceMock<Stats::IsolatedStoreImpl> stats_;
  NiceMock<Http::MockStreamDecoderFilterCallbacks> decoder_filter_callbacks_;
  FilterConfigSharedPtr config_;
  std::shared_ptr<BasicAuthFilter> filter_;
};


TEST_F(FilterTest, BasicAuth) {
  std::vector<User> users;
  users.push_back({"user1", "tESsBmE/yNY3lb6a0L6vVQEZNqw="});
  users.push_back({"user2", "EJ9LPFDXsN9ynSmbxvjp75Bmlx8="});
  setup(users);

  Http::TestRequestHeaderMapImpl request_headers_user1{{"Authorization", "Basic dXNlcjE6dGVzdDE="}};
  EXPECT_EQ(Http::FilterHeadersStatus::Continue,
            filter_->decodeHeaders(request_headers_user1, true));

  Http::TestRequestHeaderMapImpl request_headers_user2{{"Authorization", "Basic dXNlcjI6dGVzdDI="}};
  EXPECT_EQ(Http::FilterHeadersStatus::Continue,
            filter_->decodeHeaders(request_headers_user2, true));            
}

} // namespace BasicAuth
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
