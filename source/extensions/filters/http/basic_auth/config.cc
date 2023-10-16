#include "source/extensions/filters/http/basic_auth/config.h"

#include "source/common/config/datasource.h"
#include "source/extensions/filters/http/basic_auth/basic_auth_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace BasicAuth {

using envoy::extensions::filters::http::basic_auth::v3::BasicAuth;

std::vector<User> readHtpasswd(std::string htpasswd) {
  std::vector<User> users;
  std::istringstream htpsswd_ss(htpasswd);
  std::string line;

  // Define a regular expression pattern to match the username, and password hash
  // Only support SHA1 for now
  std::regex htpasswdRegex(R"((\w+):\{SHA\}(.+))");

  while (std::getline(htpsswd_ss, line)) {
    std::smatch match;
    std::string name, hash;
    if (std::regex_search(line, match, htpasswdRegex)) {
      name = match[1];
      hash = match[2];
      users.push_back({name, hash});
    } else {
      throw EnvoyException("unsupported htpasswd format: please use {SHA}");
    }
  }

  return users;
}

Http::FilterFactoryCb BasicAuthFilterFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::http::basic_auth::v3::BasicAuth& proto_config,
    const std::string& stats_prefix, Server::Configuration::FactoryContext& context) {
  auto htpasswd = Config::DataSource::read(proto_config.users(), false, context.api());
  auto users = readHtpasswd(htpasswd);
  FilterConfigSharedPtr config =
      std::make_shared<FilterConfig>(users, stats_prefix, context.scope());
  return [users, config](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamDecoderFilter(std::make_shared<BasicAuthFilter>(config));
  };
}

REGISTER_FACTORY(BasicAuthFilterFactory, Server::Configuration::NamedHttpFilterConfigFactory);

} // namespace BasicAuth
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
