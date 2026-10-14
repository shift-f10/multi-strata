#include "secure_frontend/http_wire.hpp"

#include <array>
#include <cstdio>

namespace secure_frontend {
namespace {

constexpr std::array<std::pair<std::string_view, std::string_view>, 5> kSecurityHeaders{{
    {"Cache-Control", "no-store"},
    {"X-Content-Type-Options", "nosniff"},
    {"Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"},
    {"Referrer-Policy", "no-referrer"},
    {"Cross-Origin-Resource-Policy", "same-origin"},
}};

bool ascii_iequal(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    const auto lower = [](char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c + 32) : c; };
    if (lower(a[i]) != lower(b[i])) return false;
  }
  return true;
}

bool is_reserved_header(std::string_view name) {
  for (const auto& [fixed, value] : kSecurityHeaders) {
    (void)value;
    if (ascii_iequal(name, fixed)) return true;
  }
  return ascii_iequal(name, "Date") || ascii_iequal(name, "Connection") || ascii_iequal(name, "Content-Length") ||
         ascii_iequal(name, "Transfer-Encoding") || ascii_iequal(name, "Server") || ascii_iequal(name, "X-Powered-By");
}

}  // namespace

std::string_view reason_phrase(const int status) noexcept {
  switch (status) {
    case 100: return "Continue";
    case 200: return "OK";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 411: return "Length Required";
    case 413: return "Content Too Large";
    case 414: return "URI Too Long";
    case 415: return "Unsupported Media Type";
    case 417: return "Expectation Failed";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 503: return "Service Unavailable";
    case 505: return "HTTP Version Not Supported";
    default: return "Unknown";
  }
}

std::string imf_fixdate(const std::chrono::system_clock::time_point now) {
  // Civil-from-days (H. Hinnant), integer only: no <chrono> calendar types,
  // which g++ 11.4's libstdc++ does not fully provide.
  static constexpr const char* kDays[] = {"Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"};   // 1970-01-01 was a Thursday
  static constexpr const char* kMonths[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  const long long total = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
  long long days = total / 86400;
  long long secs = total % 86400;
  if (secs < 0) { secs += 86400; --days; }
  const long long weekday = ((days % 7) + 7) % 7;
  const long long z = days + 719468;
  const long long era = (z >= 0 ? z : z - 146096) / 146097;
  const long long doe = z - era * 146097;
  const long long yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  const long long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  const long long mp = (5 * doy + 2) / 153;
  const long long day = doy - (153 * mp + 2) / 5 + 1;
  const long long month = mp < 10 ? mp + 3 : mp - 9;
  const long long year = yoe + era * 400 + (month <= 2 ? 1 : 0);
  char buffer[40];
  std::snprintf(buffer, sizeof(buffer), "%s, %02lld %s %04lld %02lld:%02lld:%02lld GMT", kDays[weekday], day,
                kMonths[month - 1], year, secs / 3600, (secs / 60) % 60, secs % 60);
  return buffer;
}

std::string serialize_response(const HttpResponse& response, const std::chrono::system_clock::time_point now) {
  std::string output{"HTTP/1.1 "};
  output += std::to_string(response.status);
  output += ' ';
  output += reason_phrase(response.status);
  output += "\r\nDate: ";
  output += imf_fixdate(now);
  output += "\r\nConnection: close\r\n";
  if (response.status != 204) {
    output += "Content-Length: ";
    output += std::to_string(response.body.size());
    output += "\r\n";
  }
  for (const auto& [name, value] : kSecurityHeaders) {
    output += name;
    output += ": ";
    output += value;
    output += "\r\n";
  }
  for (const auto& [name, value] : response.headers) {
    // Values come from code, never from the request; the CR/LF guard stays (SP0).
    if (name.find_first_of("\r\n") != std::string::npos || value.find_first_of("\r\n") != std::string::npos ||
        is_reserved_header(name)) {
      continue;
    }
    output += name;
    output += ": ";
    output += value;
    output += "\r\n";
  }
  output += "\r\n";
  if (response.status != 204) output += response.body;
  return output;
}

}  // namespace secure_frontend
