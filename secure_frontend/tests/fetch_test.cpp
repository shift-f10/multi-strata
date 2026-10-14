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

bool location_problem(const std::string_view value, const secure_frontend::UrlProblem expected) {
  const auto result = secure_frontend::parse_location(value, "huggingface.co");
  const auto* problem = std::get_if<secure_frontend::UrlProblem>(&result);
  return problem != nullptr && *problem == expected;
}

// Spec §9 "URL globbing makes curl fetch many URLs": [ ] { } never pass a Location.
void dl03_location_with_glob_characters_rejected() {
  using P = secure_frontend::UrlProblem;
  for (const auto* bad : {"https://us.aws.cdn.hf.co/a[1-9]", "https://us.aws.cdn.hf.co/{a,b}",
                          "https://us.aws.cdn.hf.co/a?x=[1]", "https://us.aws.cdn.hf.co/a?x={y}",
                          "https://us.aws.cdn.hf.co/a b", "https://us.aws.cdn.hf.co/a?x=\"y\"",
                          "https://us.aws.cdn.hf.co/a\\b"}) {
    expect(location_problem(bad, P::bad_character), std::string{"Location rejected: "} + bad);
  }
}

void location_resolution_and_host_normalization() {
  using P = secure_frontend::UrlProblem;
  const auto relative = secure_frontend::parse_location("/api/x", "huggingface.co");
  const auto* url = std::get_if<secure_frontend::HttpsUrl>(&relative);
  expect(url != nullptr && url->host == "huggingface.co" && url->target == "/api/x", "absolute path uses current host");
  const auto upper = secure_frontend::parse_location("https://US.AWS.CDN.HF.CO/x", "huggingface.co");
  const auto* lowered = std::get_if<secure_frontend::HttpsUrl>(&upper);
  expect(lowered != nullptr && lowered->host == "us.aws.cdn.hf.co", "Location host is lowercased");
  expect(location_problem("https://us.aws.cdn.hf.co./x", P::bad_host), "trailing dot rejected");
  expect(location_problem("http://us.aws.cdn.hf.co/x", P::not_https), "http Location");
  expect(location_problem("//us.aws.cdn.hf.co/x", P::not_https), "network-path reference");
  expect(location_problem("x/y", P::not_https), "relative path");
  expect(location_problem("https://us.aws.cdn.hf.co:444/x", P::port_not_allowed), "port 444");
  expect(location_problem("https://a@us.aws.cdn.hf.co/x", P::userinfo), "userinfo");
  expect(location_problem("https://us.aws.cdn.hf.co/x#f", P::fragment), "fragment");
  expect(location_problem("https://us.aws.cdn.hf.co/" + std::string(8200, 'a'), P::too_long), "over 8 KiB");
  const auto bare = secure_frontend::parse_location("https://us.aws.cdn.hf.co", "huggingface.co");
  const auto* bare_url = std::get_if<secure_frontend::HttpsUrl>(&bare);
  expect(bare_url != nullptr && bare_url->target == "/", "no path means /");
}

void location_query_characters() {
  const auto signed_url = secure_frontend::parse_location(
      "https://us.aws.cdn.hf.co/xet-bridge-us/abc?X-Xet-Signed-Range=bytes%3D0-1&Expires=1&Policy=a,b;c:d@e!f$g'h(i)j*k+l",
      "huggingface.co");
  expect(std::holds_alternative<secure_frontend::HttpsUrl>(signed_url), "signed CDN query characters accepted");
  expect(location_problem("https://us.aws.cdn.hf.co/a?b?c", secure_frontend::UrlProblem::bad_character),
         "second ? rejected");
  expect(location_problem("https://us.aws.cdn.hf.co/a=b", secure_frontend::UrlProblem::bad_character),
         "query-only characters are not path characters");
}

}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"dl03_location_with_glob_characters_rejected", dl03_location_with_glob_characters_rejected},
      {"location_resolution_and_host_normalization", location_resolution_and_host_normalization},
      {"location_query_characters", location_query_characters},
  }, failures);
}
