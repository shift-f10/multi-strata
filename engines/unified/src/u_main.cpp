// strata-unified-engine: the command line, the geometry guard, the dispatch, and the serve
// loop skeleton (design §3.1, plan T0.4/T0.6). It reads a GGUF header, guards the geometry
// for its `general.architecture`, dispatches to a FamilyGraph, and serves the converged
// "unified" wire dialect. On a host-only build (STRATA_U_CUDA OFF) the FamilyGraph is the
// stub, so the binary builds and serves without a CUDA toolkit but refuses to generate.
#include "u_dispatch.hpp"
#include "u_family.hpp"
#include "u_geometry.hpp"
#include "u_gguf.hpp"
#include "u_protocol.hpp"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <set>
#include <string>
#include <variant>
#include <vector>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace {

struct Options final {
  std::string model;        // --native (required)
  bool serve{false};        // --serve
  std::vector<int> gpus;    // --gpu i,j (argv mechanism, design §3.4)
  int max_context{32768};   // --max-context 1..262144
  int chunk{512};           // --chunk 1..8192
};

bool parse_int(std::string_view text, long long lo, long long hi, long long& out) {
  if (text.empty() || text.size() > 19) return false;
  if (text.front() == '+' || (text.size() > 1 && text.front() == '0')) return false;
  long long v = 0;
  const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), v);
  if (ec != std::errc{} || end != text.data() + text.size() || v < lo || v > hi) return false;
  out = v;
  return true;
}

std::variant<Options, std::string> parse_cli(const std::vector<std::string>& args) {
  Options o;
  std::set<std::string> seen;
  for (std::size_t i = 0; i < args.size(); ++i) {
    const std::string& a = args[i];
    if (a.rfind("--", 0) != 0) return std::string{"unexpected positional argument"};
    if (!seen.insert(a).second) return std::string{"a flag is given twice"};
    auto value = [&](std::string& out) -> bool {
      if (i + 1 >= args.size()) return false;
      out = args[++i];
      return true;
    };
    auto integer = [&](long long lo, long long hi, int& out) -> bool {
      std::string v;
      long long n = 0;
      if (!value(v) || !parse_int(v, lo, hi, n)) return false;
      out = static_cast<int>(n);
      return true;
    };
    if (a == "--serve") { o.serve = true; continue; }
    if (a == "--native") {
      if (!value(o.model) || o.model.empty()) return std::string{"--native needs the model file"};
      continue;
    }
    if (a == "--gpu") {
      std::string v;
      if (!value(v) || v.empty()) return std::string{"--gpu needs a device list"};
      std::size_t at = 0;
      while (at <= v.size()) {
        const std::size_t comma = std::min(v.find(',', at), v.size());
        long long d = 0;
        if (!parse_int(std::string_view(v).substr(at, comma - at), 0, 255, d)) return std::string{"--gpu takes device numbers 0-255"};
        if (std::find(o.gpus.begin(), o.gpus.end(), static_cast<int>(d)) != o.gpus.end()) return std::string{"--gpu lists a device twice"};
        o.gpus.push_back(static_cast<int>(d));
        if (comma == v.size()) break;
        at = comma + 1;
      }
      if (o.gpus.empty() || o.gpus.size() > 16) return std::string{"--gpu takes 1-16 devices"};
      continue;
    }
    if (a == "--max-context") { if (!integer(1, 262144, o.max_context)) return std::string{"--max-context must be 1-262144"}; continue; }
    if (a == "--chunk") { if (!integer(1, 8192, o.chunk)) return std::string{"--chunk must be 1-8192"}; continue; }
    return std::string{"unknown flag"};
  }
  if (o.model.empty()) return std::string{"--native is required"};
  return o;
}

void set_env(const char* key, const std::string& value) {
#if defined(_WIN32)
  _putenv_s(key, value.c_str());
#else
  setenv(key, value.c_str(), 1);
#endif
}

std::uint32_t serving_context(const u::Geometry& geom, int max_context) {
  const long long want = std::min<long long>(geom.context_length, max_context);
  return static_cast<std::uint32_t>(std::max<long long>(1, want));
}

u::Record info_record(const u::Geometry& geom, const u::FamilyGraph& graph) {
  u::Info info;
  info.fields.push_back({"engine", "strata-unified"});
  info.fields.push_back({"arch", geom.arch});
  info.fields.push_back({"family", std::string(u::name_of(geom.family))});
  info.fields.push_back({"context", std::to_string(graph.context())});
  info.fields.push_back({"experts", std::to_string(geom.expert_count)});
  info.fields.push_back({"experts_used", std::to_string(geom.expert_used_count)});
  info.fields.push_back({"router", geom.router == u::RouterKind::sigmoid ? "sigmoid" : "softmax"});
  info.fields.push_back({"rope", geom.rope == u::RopeKind::rope ? "rope" : "nope"});
  info.fields.push_back({"available", graph.available() ? "1" : "0"});
  return u::Record{std::move(info)};
}

void emit_line(const u::Record& r) {
  const std::string line = u::emit(r);
  std::printf("%s\n", line.c_str());
  std::fflush(stdout);
}

int serve(const u::Geometry& geom, u::FamilyGraph& graph) {
  emit_line(info_record(geom, graph));
  emit_line(u::Record{u::Ready{graph.context(), /*stop_honored=*/true}});

  std::string line;
  while (std::getline(std::cin, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) continue;

    const auto parsed = u::parse_line(line);
    if (const auto* perr = std::get_if<u::ParseError>(&parsed)) {
      emit_line(u::Record{u::Err{perr->message}});
      continue;
    }
    const auto& record = std::get<u::Record>(parsed);

    if (std::holds_alternative<u::Quit>(record)) return 0;
    if (std::holds_alternative<u::Stop>(record)) continue;  // nothing is generating in the skeleton
    if (const auto* gen = std::get_if<u::Gen>(&record)) {
      std::string error;
      const bool ok = graph.generate(*gen, [](const std::string& out) {
        std::printf("%s\n", out.c_str());
        std::fflush(stdout);
      }, error);
      if (!ok) emit_line(u::Record{u::Err{error}});
      continue;
    }
    // Any other record (an inbound/engine record arriving from the client) fails closed.
    emit_line(u::Record{u::Err{"unexpected record from the client"}});
  }
  return 0;
}

int summary(const u::Geometry& geom, const u::FamilyGraph& graph) {
  std::printf(
      "strata-unified: arch=%s family=%s blocks=%lld hidden=%lld heads=%lld head_dim=%lld ff=%lld moe_ff=%lld "
      "experts=%lld used=%lld shared=%lld vocab=%lld context=%u router=%s rope=%s available=%d\n",
      geom.arch.c_str(), std::string(u::name_of(geom.family)).c_str(), static_cast<long long>(geom.block_count),
      static_cast<long long>(geom.embedding_length), static_cast<long long>(geom.head_count),
      static_cast<long long>(geom.head_dim), static_cast<long long>(geom.feed_forward_length),
      static_cast<long long>(geom.expert_feed_forward_length), static_cast<long long>(geom.expert_count),
      static_cast<long long>(geom.expert_used_count), static_cast<long long>(geom.expert_shared_count),
      static_cast<long long>(geom.vocab_size), graph.context(),
      geom.router == u::RouterKind::sigmoid ? "sigmoid" : "softmax", geom.rope == u::RopeKind::rope ? "rope" : "nope",
      graph.available() ? 1 : 0);
  return 0;
}

int run(const std::vector<std::string>& args) {
  const auto parsed = parse_cli(args);
  if (const auto* err = std::get_if<std::string>(&parsed)) {
    std::fprintf(stderr, "strata-unified-engine: %s\n", err->c_str());
    return 2;
  }
  const auto& o = std::get<Options>(parsed);

  if (!o.gpus.empty()) {
    std::string list;
    for (const int g : o.gpus) list += (list.empty() ? "" : ",") + std::to_string(g);
    set_env("CUDA_DEVICE_ORDER", "PCI_BUS_ID");
    set_env("CUDA_VISIBLE_DEVICES", list);
  }

  const auto header = u::read_gguf_header(o.model);
  if (const auto* err = std::get_if<u::GgufError>(&header)) {
    std::fprintf(stderr, "strata-unified-engine: %s\n", err->message.c_str());
    return 1;
  }
  const auto geometry = u::read_geometry(std::get<u::GgufFile>(header));
  if (const auto* err = std::get_if<u::GeometryError>(&geometry)) {
    std::fprintf(stderr, "strata-unified-engine: %s\n", err->message.c_str());
    return 1;
  }
  const auto& geom = std::get<u::Geometry>(geometry);

  const std::uint32_t context = serving_context(geom, o.max_context);
  std::string error;
  auto graph = u::make_family_graph(geom, context, error);
  if (!graph) {
    std::fprintf(stderr, "strata-unified-engine: %s\n", error.c_str());
    return 1;
  }
  std::fprintf(stderr, "strata-unified-engine: %s ready (context %u, chunk %d); generation %s\n",
               std::string(u::name_of(geom.family)).c_str(), context, o.chunk,
               graph->available() ? "available" : "not available on this host build");

  if (o.serve) return serve(geom, *graph);
  return summary(geom, *graph);
}

}  // namespace

#if defined(_WIN32)
int wmain(int argc, wchar_t** argv) {
  std::vector<std::string> args;
  for (int i = 1; i < argc; ++i) {
    const int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[i], -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) {
      std::fprintf(stderr, "strata-unified-engine: an argument is not valid UTF-16\n");
      return 2;
    }
    std::string s(static_cast<std::size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[i], -1, s.data(), n, nullptr, nullptr);
    s.resize(static_cast<std::size_t>(n - 1));
    args.push_back(std::move(s));
  }
  return run(args);
}
#else
int main(int argc, char** argv) {
  std::vector<std::string> args(argv + 1, argv + argc);
  return run(args);
}
#endif
