#include "secure_frontend/acquire_url.hpp"
#include "secure_frontend/address_policy.hpp"
#include "support/test_support.hpp"

#include <iostream>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

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

using secure_frontend::make_ipv4;
using secure_frontend::make_ipv6;

void address_policy_denies_special_ranges() {
  const std::vector<secure_frontend::ResolvedAddress> denied{
      make_ipv4(0, 1, 2, 3),        make_ipv4(10, 0, 0, 1),     make_ipv4(100, 64, 0, 1),   make_ipv4(100, 127, 255, 255),
      make_ipv4(127, 0, 0, 1),      make_ipv4(169, 254, 1, 1),  make_ipv4(172, 16, 0, 1),   make_ipv4(172, 31, 255, 255),
      make_ipv4(192, 0, 0, 8),      make_ipv4(192, 0, 2, 1),    make_ipv4(192, 168, 1, 1),  make_ipv4(198, 18, 0, 1),
      make_ipv4(198, 19, 255, 255), make_ipv4(198, 51, 100, 7), make_ipv4(203, 0, 113, 9),  make_ipv4(224, 0, 0, 1),
      make_ipv4(239, 1, 1, 1),      make_ipv4(240, 0, 0, 1),    make_ipv4(255, 255, 255, 255),
      make_ipv6({0, 0, 0, 0, 0, 0, 0, 0}),           make_ipv6({0, 0, 0, 0, 0, 0, 0, 1}),
      make_ipv6({0, 0, 0, 0, 0, 0, 0x0808, 0x0808}), make_ipv6({0, 0, 0, 0, 0, 0xffff, 0x0808, 0x0808}),
      make_ipv6({0x64, 0xff9b, 0, 0, 0, 0, 0x0808, 0x0808}), make_ipv6({0x64, 0xff9b, 1, 0, 0, 0, 0, 1}),
      make_ipv6({0x100, 0, 0, 0, 0, 0, 0, 1}),       make_ipv6({0x2001, 0, 1, 0, 0, 0, 0, 1}),
      make_ipv6({0x2001, 0xdb8, 0, 0, 0, 0, 0, 1}),  make_ipv6({0x2002, 0x0808, 0x0808, 0, 0, 0, 0, 1}),
      make_ipv6({0xfc00, 0, 0, 0, 0, 0, 0, 1}),      make_ipv6({0xfdff, 0, 0, 0, 0, 0, 0, 1}),
      make_ipv6({0xfe80, 0, 0, 0, 0, 0, 0, 1}),      make_ipv6({0xfebf, 0, 0, 0, 0, 0, 0, 1}),
      make_ipv6({0xff02, 0, 0, 0, 0, 0, 0, 1})};
  for (std::size_t i = 0; i < denied.size(); ++i) {
    expect(secure_frontend::is_denied_address(denied[i]), "denied #" + std::to_string(i) + " " +
                                                              secure_frontend::format_address(denied[i]));
  }
  const std::vector<secure_frontend::ResolvedAddress> allowed{
      make_ipv4(1, 1, 1, 1),        make_ipv4(9, 255, 255, 255), make_ipv4(11, 0, 0, 0),     make_ipv4(100, 63, 255, 255),
      make_ipv4(100, 128, 0, 0),    make_ipv4(172, 15, 255, 255), make_ipv4(172, 32, 0, 0),   make_ipv4(192, 0, 1, 1),
      make_ipv4(198, 17, 255, 255), make_ipv4(198, 20, 0, 0),     make_ipv4(223, 255, 255, 255),
      make_ipv6({0x2001, 0x4860, 0, 0, 0, 0, 0, 0x8888}), make_ipv6({0x2a00, 0x1450, 0, 0, 0, 0, 0, 1}),
      make_ipv6({0xfbff, 0, 0, 0, 0, 0, 0, 1}),           make_ipv6({0xfec0, 0, 0, 0, 0, 0, 0, 1}),
      make_ipv6({0x64, 0xff9b, 2, 0, 0, 0, 0, 1}),        make_ipv6({0x100, 0, 0, 1, 0, 0, 0, 1})};
  for (std::size_t i = 0; i < allowed.size(); ++i) {
    expect(!secure_frontend::is_denied_address(allowed[i]), "allowed #" + std::to_string(i) + " " +
                                                                secure_frontend::format_address(allowed[i]));
  }
}

// fec0::/10 (deprecated site-local) is allowed: spec §3.5's IPv6 list does not deny it (only fc00::/7 and fe80::/10).
void address_policy_any_denied_answer_rejects_hop() {
  const std::vector answers{make_ipv4(93, 184, 216, 34), make_ipv4(192, 168, 1, 1)};
  const auto verdict = secure_frontend::choose_pinned_address(answers, false);
  expect(verdict.kind == secure_frontend::AddressVerdictKind::denied, "a mixed public/private answer is denied");
  expect(secure_frontend::choose_pinned_address({}, false).kind == secure_frontend::AddressVerdictKind::no_usable_address,
         "no answers");
}

void ipv6_only_answer_fails_closed() {
  const std::vector answers{make_ipv6({0x2a00, 0x1450, 0, 0, 0, 0, 0, 1})};
  expect(secure_frontend::choose_pinned_address(answers, false).kind == secure_frontend::AddressVerdictKind::no_usable_address,
         "IPv6-only hops fail closed until the [addr] --resolve form is verified");
  const std::vector mixed{make_ipv6({0x2a00, 0x1450, 0, 0, 0, 0, 0, 1}), make_ipv4(1, 1, 1, 1)};
  const auto verdict = secure_frontend::choose_pinned_address(mixed, false);
  expect(verdict.kind == secure_frontend::AddressVerdictKind::pinned && !verdict.pinned.ipv6, "first IPv4 is pinned");
}

void allow_private_addresses_pins_first_ipv4() {
  const std::vector answers{make_ipv4(10, 0, 0, 7), make_ipv4(1, 1, 1, 1)};
  const auto verdict = secure_frontend::choose_pinned_address(answers, true);
  expect(verdict.kind == secure_frontend::AddressVerdictKind::pinned &&
             secure_frontend::format_address(verdict.pinned) == "10.0.0.7",
         "pull.allow_private_addresses pins the first address");
}

void resolve_argument_brackets_ipv6() {
  expect(secure_frontend::resolve_argument("huggingface.co", make_ipv4(1, 2, 3, 4)) == "huggingface.co:443:1.2.3.4", "IPv4");
  expect(secure_frontend::resolve_argument("h.example", make_ipv6({0x2a00, 0x1450, 0, 0, 0, 0, 0, 0x1f})) ==
             "h.example:443:[2a00:1450:0:0:0:0:0:1f]",
         "IPv6 in brackets, uncompressed");
}

}  // namespace

int main(int argc, char** argv) {
  return secure_frontend_test::run_cases(argc, argv, {
      {"dl03_location_with_glob_characters_rejected", dl03_location_with_glob_characters_rejected},
      {"location_resolution_and_host_normalization", location_resolution_and_host_normalization},
      {"location_query_characters", location_query_characters},
      {"address_policy_denies_special_ranges", address_policy_denies_special_ranges},
      {"address_policy_any_denied_answer_rejects_hop", address_policy_any_denied_answer_rejects_hop},
      {"ipv6_only_answer_fails_closed", ipv6_only_answer_fails_closed},
      {"allow_private_addresses_pins_first_ipv4", allow_private_addresses_pins_first_ipv4},
      {"resolve_argument_brackets_ipv6", resolve_argument_brackets_ipv6},
  }, failures);
}
