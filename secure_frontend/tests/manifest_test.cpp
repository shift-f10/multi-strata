#include "secure_frontend/acquire_url.hpp"
#include "support/test_support.hpp"

#include <iostream>
#include <string>
#include <string_view>
#include <variant>

namespace {

int failures = 0;

void expect(const bool condition, const std::string& message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAILED: " << message << '\n';
  }
}

bool problem_is(const std::variant<secure_frontend::HttpsUrl, secure_frontend::UrlProblem>& result,
                const secure_frontend::UrlProblem expected) {
  const auto* problem = std::get_if<secure_frontend::UrlProblem>(&result);
  return problem != nullptr && *problem == expected;
}

void source_url_grammar_matrix() {
  using P = secure_frontend::UrlProblem;
  const auto ok = secure_frontend::parse_source_url(
      "https://huggingface.co/ISTA-DASLab/Qwen3.8-Flash-Next-GSQ-RCO-GGUF/resolve/ed59f92082b1e93c0e96d60a8b11aab089b52f09/"
      "IQ2_XS/Qwen3.8-Flash-Next-GSQ-RCO-IQ2_XS-00001-of-00002.gguf");
  expect(std::holds_alternative<secure_frontend::HttpsUrl>(ok), "Hugging Face resolve URL accepted");
  if (const auto* url = std::get_if<secure_frontend::HttpsUrl>(&ok)) {
    expect(url->host == "huggingface.co", "host split");
    expect(secure_frontend::render_url(*url).starts_with("https://huggingface.co/ISTA-DASLab/"), "round trip");
  }
  expect(std::holds_alternative<secure_frontend::HttpsUrl>(secure_frontend::parse_source_url("https://h.example:443/a%20b")),
         "explicit :443 and %XX accepted");
  expect(problem_is(secure_frontend::parse_source_url("http://huggingface.co/a"), P::not_https), "http rejected");
  expect(problem_is(secure_frontend::parse_source_url("HTTPS://huggingface.co/a"), P::not_https), "scheme is exact");
  expect(problem_is(secure_frontend::parse_source_url("https://huggingface.co:8443/a"), P::port_not_allowed), "port 8443");
  expect(problem_is(secure_frontend::parse_source_url("https://huggingface.co:/a"), P::port_not_allowed), "empty port");
  expect(problem_is(secure_frontend::parse_source_url("https://user@huggingface.co/a"), P::userinfo), "userinfo");
  expect(problem_is(secure_frontend::parse_source_url("https://huggingface.co/a?x=1"), P::query_not_allowed), "query");
  expect(problem_is(secure_frontend::parse_source_url("https://huggingface.co/a#f"), P::fragment), "fragment");
  for (const auto* bad : {"https://h.example/a[1]", "https://h.example/a{b}", "https://h.example/a b",
                          "https://h.example/a\"b", "https://h.example/a\\b", "https://h.example/%zz",
                          "https://h.example/a%2"}) {
    expect(problem_is(secure_frontend::parse_source_url(bad), P::bad_character), std::string{"bad character: "} + bad);
  }
  expect(problem_is(secure_frontend::parse_source_url("https://h.example"), P::missing_path), "no path");
  expect(problem_is(secure_frontend::parse_source_url("https://h.example/"), P::missing_path), "root path only");
  expect(problem_is(secure_frontend::parse_source_url("https://H.example/a"), P::bad_host), "manifest hosts are lowercase");
  expect(problem_is(secure_frontend::parse_source_url("https://127.0.0.1/a"), P::bad_host), "IPv4 literal");
  expect(problem_is(secure_frontend::parse_source_url("https://[::1]/a"), P::bad_host), "IPv6 literal");
  expect(problem_is(secure_frontend::parse_source_url("https://localhost/a"), P::bad_host), "single label");
  expect(problem_is(secure_frontend::parse_source_url("https://h.example/" + std::string(2100, 'a')), P::too_long),
         "longer than 2048 bytes");
}

void dns_names_and_wildcards() {
  expect(secure_frontend::is_valid_dns_name("huggingface.co"), "two labels");
  expect(secure_frontend::is_valid_dns_name("us.aws.cdn.hf.co"), "five labels");
  for (const auto* bad : {"", "co", "-a.co", "a-.co", "a..co", "a.co.", "A.co", "a_b.co", "1.2.3.4", "a.123"}) {
    expect(!secure_frontend::is_valid_dns_name(bad), std::string{"invalid dns name: "} + bad);
  }
  expect(secure_frontend::is_valid_redirect_pattern("*.aws.cdn.hf.co"), "wildcard over 4 labels");
  expect(secure_frontend::is_valid_redirect_pattern("cas-bridge.xethub.hf.co"), "plain host");
  expect(!secure_frontend::is_valid_redirect_pattern("*.co"), "wildcard base needs two labels");
  expect(!secure_frontend::is_valid_redirect_pattern("*"), "bare star");
  expect(!secure_frontend::is_valid_redirect_pattern("a.*.co"), "star only leftmost");
  expect(secure_frontend::host_matches("*.aws.cdn.hf.co", "us.aws.cdn.hf.co"), "one extra label matches");
  expect(!secure_frontend::host_matches("*.aws.cdn.hf.co", "aws.cdn.hf.co"), "zero extra labels do not match");
  expect(!secure_frontend::host_matches("*.aws.cdn.hf.co", "a.b.aws.cdn.hf.co"), "two extra labels do not match");
  expect(!secure_frontend::host_matches("*.aws.cdn.hf.co", "evilaws.cdn.hf.co"), "label boundary");
  expect(secure_frontend::host_matches("huggingface.co", "huggingface.co"), "exact");
  expect(!secure_frontend::host_matches("huggingface.co", "x.huggingface.co"), "exact means exact");
}

void proxy_grammar() {
  const auto http = secure_frontend::parse_proxy("http://proxy.corp:3128");
  expect(std::holds_alternative<secure_frontend::ProxySetting>(http), "http proxy with single-label-free name");
  const auto single = secure_frontend::parse_proxy("http://proxy:8080");
  expect(std::holds_alternative<secure_frontend::ProxySetting>(single), "single-label proxy name");
  expect(std::holds_alternative<secure_frontend::ProxySetting>(secure_frontend::parse_proxy("https://10.0.0.5:443")),
         "IPv4 literal proxy (may be private)");
  expect(std::holds_alternative<secure_frontend::ProxySetting>(secure_frontend::parse_proxy("http://[fd00::1]:3128")),
         "IPv6 literal proxy");
  if (const auto* p = std::get_if<secure_frontend::ProxySetting>(&http)) {
    expect(secure_frontend::render_proxy(*p) == "http://proxy.corp:3128", "render");
  }
  for (const auto* bad : {"proxy:3128", "socks5://p.example:1080", "http://u:p@p.example:3128", "http://p.example",
                          "http://p.example:0", "http://p.example:65536", "http://p.example:3128/path",
                          "http://p.example:03128"}) {
    expect(std::holds_alternative<secure_frontend::UrlProblem>(secure_frontend::parse_proxy(bad)),
           std::string{"proxy rejected: "} + bad);
  }
}

}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"source_url_grammar_matrix", source_url_grammar_matrix},
      {"dns_names_and_wildcards", dns_names_and_wildcards},
      {"proxy_grammar", proxy_grammar},
  }, failures);
}
