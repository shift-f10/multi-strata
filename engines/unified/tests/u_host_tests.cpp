// Hermetic tests for strata-unified-engine's host code (no GPU): the GGUF reader, the
// per-family geometry guard, the converged protocol dialect, and the family dispatch.
#include "u_dispatch.hpp"
#include "u_geometry.hpp"
#include "u_gguf.hpp"
#include "u_protocol.hpp"
#include "u_test.hpp"
#include "u_gguf_writer.hpp"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <optional>
#include <string>
#include <variant>
#include <vector>

using u_test::expect;
using u_test::GgufBuilder;

namespace {

std::variant<u::GgufFile, u::GgufError> parse(const std::vector<std::uint8_t>& image) {
  return u::parse_gguf(image.data(), image.size(), image.size());
}

bool close(double a, double b) { return std::fabs(a - b) < 1e-6; }

// ---- fixtures ----------------------------------------------------------------------------

void put_raon1_meta(GgufBuilder& b) {
  b.str("general.architecture", "raon1");
  b.u32("raon1.block_count", 25);
  b.u32("raon1.embedding_length", 2560);
  b.u32("raon1.attention.head_count", 40);
  b.u32("raon1.attention.key_length", 128);
  b.u32("raon1.feed_forward_length", 12032);
  b.u32("raon1.expert_feed_forward_length", 1088);
  b.u32("raon1.expert_count", 128);
  b.u32("raon1.expert_used_count", 6);
  b.u32("raon1.expert_shared_count", 1);
  b.u32("raon1.context_length", 262144);
  b.u32("raon1.vocab_size", 259840);
}

void put_glm5next_meta(GgufBuilder& b) {
  b.str("general.architecture", "glm5next");
  b.u32("glm5next.block_count", 48);
  b.u32("glm5next.embedding_length", 4096);
  b.u32("glm5next.attention.head_count", 32);
  b.u32("glm5next.attention.key_length", 128);
  b.u32("glm5next.feed_forward_length", 13696);
  b.u32("glm5next.expert_feed_forward_length", 1536);
  b.u32("glm5next.expert_count", 160);
  b.u32("glm5next.expert_used_count", 8);
  b.u32("glm5next.expert_shared_count", 1);
  b.u32("glm5next.context_length", 131072);
  b.u32("glm5next.vocab_size", 151552);
  b.f32("glm5next.rope.freq_base", 1000000.0f);
}

// A committed GGUF-header fixture: the raon1 metadata plus a small, well-formed tensor
// directory (two tensors; no weight bytes are read by the host).
GgufBuilder raon1_fixture() {
  GgufBuilder b;
  put_raon1_meta(b);
  b.tensor("output_norm.weight", {2560}, /*f32=*/0, 2560 * 4);
  b.tensor("token_embd.weight", {64, 2}, /*q8_0=*/8, 2 * 2 * 34);
  return b;
}

// ---- GGUF reader -------------------------------------------------------------------------

void gguf_parses_a_committed_header() {
  const auto image = raon1_fixture().bytes();
  const auto r = parse(image);
  const auto* f = std::get_if<u::GgufFile>(&r);
  expect(f != nullptr, "the committed raon1 header parses");
  if (f == nullptr) return;
  expect(f->version == 3, "version 3");
  const auto* arch = f->find("general.architecture");
  expect(arch != nullptr && arch->type == u::GgufType::string && arch->text == "raon1", "general.architecture is raon1");
  const auto* blocks = f->find("raon1.block_count");
  expect(blocks != nullptr && blocks->integer == 25, "raon1.block_count is 25");
  const auto* vocab = f->find("raon1.vocab_size");
  expect(vocab != nullptr && vocab->integer == 259840, "raon1.vocab_size is 259840");
  expect(f->tensors.size() == 2, "two tensors in the directory");
  const auto* emb = f->tensor("token_embd.weight");
  expect(emb != nullptr && emb->type == u::TensorType::q8_0 && emb->bytes == 136, "the Q8_0 tensor's type and bytes");
  expect(f->data_offset % 32 == 0, "the data section is aligned");
  // A bad magic and a wrong version are both refused.
  auto bad = image;
  bad[0] = 'X';
  expect(std::holds_alternative<u::GgufError>(parse(bad)), "a bad magic is refused");
  bad = image;
  bad[4] = 2;
  expect(std::holds_alternative<u::GgufError>(parse(bad)), "version 2 is refused");
}

void gguf_reads_a_header_from_disk() {
  const auto image = raon1_fixture().bytes();
  const char* path = "u_host_tests_fixture.gguf";
  {
    std::ofstream os(path, std::ios::binary);
    expect(static_cast<bool>(os), "the fixture file opens for writing");
    os.write(reinterpret_cast<const char*>(image.data()), static_cast<std::streamsize>(image.size()));
  }
  const auto r = u::read_gguf_header(path);
  const auto* f = std::get_if<u::GgufFile>(&r);
  expect(f != nullptr, "read_gguf_header reads the file back");
  if (f != nullptr) {
    const auto* arch = f->find("general.architecture");
    expect(arch != nullptr && arch->text == "raon1", "the disk header is raon1");
  }
  std::remove(path);
  expect(std::holds_alternative<u::GgufError>(u::read_gguf_header("does-not-exist.gguf")), "a missing file is refused");
}

// ---- geometry guard ----------------------------------------------------------------------

void geometry_guard_accepts_valid_key_sets() {
  {
    GgufBuilder b;
    put_raon1_meta(b);
    const auto file = parse(b.bytes());
    const auto* f = std::get_if<u::GgufFile>(&file);
    expect(f != nullptr, "raon1 metadata parses");
    if (f != nullptr) {
      const auto g = u::read_geometry(*f);
      const auto* geom = std::get_if<u::Geometry>(&g);
      expect(geom != nullptr, "raon1 geometry is accepted");
      if (geom != nullptr) {
        expect(geom->family == u::FamilyId::raon1, "family is raon1");
        expect(geom->block_count == 25 && geom->embedding_length == 2560 && geom->head_count == 40, "raon1 core dims");
        expect(geom->head_dim == 128 && geom->feed_forward_length == 12032 && geom->expert_feed_forward_length == 1088,
               "raon1 feed-forward dims");
        expect(geom->expert_count == 128 && geom->expert_used_count == 6 && geom->expert_shared_count == 1,
               "raon1 expert counts");
        expect(geom->vocab_size == 259840 && geom->context_length == 262144, "raon1 vocab and context");
        expect(geom->router == u::RouterKind::sigmoid, "raon1 uses the sigmoid router");
        expect(geom->rope == u::RopeKind::nope && close(geom->rope_freq_base, 0.0), "raon1 is NoPE");
      }
    }
  }
  {
    GgufBuilder b;
    put_glm5next_meta(b);
    const auto file = parse(b.bytes());
    const auto* f = std::get_if<u::GgufFile>(&file);
    expect(f != nullptr, "glm5next metadata parses");
    if (f != nullptr) {
      const auto g = u::read_geometry(*f);
      const auto* geom = std::get_if<u::Geometry>(&g);
      expect(geom != nullptr, "glm5next geometry is accepted");
      if (geom != nullptr) {
        expect(geom->family == u::FamilyId::glm5next, "family is glm5next");
        expect(geom->router == u::RouterKind::sigmoid, "glm5next uses the sigmoid router");
        expect(geom->rope == u::RopeKind::rope && close(geom->rope_freq_base, 1000000.0), "glm5next is RoPE with its base");
      }
    }
  }
}

bool geometry_refused(const GgufBuilder& b) {
  const auto file = parse(b.bytes());
  const auto* f = std::get_if<u::GgufFile>(&file);
  if (f == nullptr) return true;  // a header that will not even parse is certainly refused
  return std::holds_alternative<u::GeometryError>(u::read_geometry(*f));
}

void geometry_guard_rejects_bad_key_sets() {
  // An out-of-range pinned dimension (raon1.block_count must be exactly 25).
  {
    GgufBuilder b;
    b.str("general.architecture", "raon1");
    b.u32("raon1.block_count", 999);
    b.u32("raon1.embedding_length", 2560);
    b.u32("raon1.attention.head_count", 40);
    b.u32("raon1.attention.key_length", 128);
    b.u32("raon1.feed_forward_length", 12032);
    b.u32("raon1.expert_feed_forward_length", 1088);
    b.u32("raon1.expert_count", 128);
    b.u32("raon1.expert_used_count", 6);
    b.u32("raon1.expert_shared_count", 1);
    b.u32("raon1.context_length", 262144);
    b.u32("raon1.vocab_size", 259840);
    expect(geometry_refused(b), "raon1 with block_count 999 is refused");
  }
  // A missing key (no raon1.vocab_size).
  {
    GgufBuilder b;
    b.str("general.architecture", "raon1");
    b.u32("raon1.block_count", 25);
    b.u32("raon1.embedding_length", 2560);
    b.u32("raon1.attention.head_count", 40);
    b.u32("raon1.attention.key_length", 128);
    b.u32("raon1.feed_forward_length", 12032);
    b.u32("raon1.expert_feed_forward_length", 1088);
    b.u32("raon1.expert_count", 128);
    b.u32("raon1.expert_used_count", 6);
    b.u32("raon1.expert_shared_count", 1);
    b.u32("raon1.context_length", 262144);
    expect(geometry_refused(b), "raon1 missing vocab_size is refused");
  }
  // A RoPE family without a rope.freq_base.
  {
    GgufBuilder b2;
    b2.str("general.architecture", "glm5next");
    b2.u32("glm5next.block_count", 48);
    b2.u32("glm5next.embedding_length", 4096);
    b2.u32("glm5next.attention.head_count", 32);
    b2.u32("glm5next.attention.key_length", 128);
    b2.u32("glm5next.feed_forward_length", 13696);
    b2.u32("glm5next.expert_feed_forward_length", 1536);
    b2.u32("glm5next.expert_count", 160);
    b2.u32("glm5next.expert_used_count", 8);
    b2.u32("glm5next.expert_shared_count", 1);
    b2.u32("glm5next.context_length", 131072);
    b2.u32("glm5next.vocab_size", 151552);
    expect(geometry_refused(b2), "glm5next without rope.freq_base is refused");
  }
  // An unknown architecture.
  {
    GgufBuilder b;
    b.str("general.architecture", "llama");
    b.u32("llama.block_count", 32);
    expect(geometry_refused(b), "an unknown architecture is refused");
  }
  // expert_used_count greater than expert_count.
  {
    GgufBuilder b2;
    b2.str("general.architecture", "glm5next");
    b2.u32("glm5next.block_count", 48);
    b2.u32("glm5next.embedding_length", 4096);
    b2.u32("glm5next.attention.head_count", 32);
    b2.u32("glm5next.attention.key_length", 128);
    b2.u32("glm5next.feed_forward_length", 13696);
    b2.u32("glm5next.expert_feed_forward_length", 1536);
    b2.u32("glm5next.expert_count", 160);
    b2.u32("glm5next.expert_used_count", 200);  // > expert_count
    b2.u32("glm5next.expert_shared_count", 1);
    b2.u32("glm5next.context_length", 131072);
    b2.u32("glm5next.vocab_size", 151552);
    b2.f32("glm5next.rope.freq_base", 1000000.0f);
    expect(geometry_refused(b2), "expert_used_count > expert_count is refused");
  }
}

// ---- protocol ----------------------------------------------------------------------------

const u::Record* ok_record(const std::variant<u::Record, u::ParseError>& r) {
  return std::get_if<u::Record>(&r);
}

template <typename T>
const T* round_trip(const u::Record& in) {
  static thread_local std::variant<u::Record, u::ParseError> held;
  held = u::parse_line(u::emit(in));
  const u::Record* r = ok_record(held);
  return r == nullptr ? nullptr : std::get_if<T>(r);
}

void protocol_round_trips_valid_lines() {
  {
    u::Info info;
    info.fields = {{"engine", "strata-unified"}, {"arch", "raon1"}, {"context", "262144"}};
    const auto* out = round_trip<u::Info>(u::Record{info});
    expect(out != nullptr && out->fields.size() == 3 && out->fields[0].key == "engine" &&
               out->fields[0].value == "strata-unified" && out->fields[2].value == "262144",
           "INFO round-trips");
  }
  {
    const auto* out = round_trip<u::Ready>(u::Record{u::Ready{262144, true}});
    expect(out != nullptr && out->ctx == 262144 && out->stop_honored, "READY with stop round-trips");
    const auto* out2 = round_trip<u::Ready>(u::Record{u::Ready{4096, false}});
    expect(out2 != nullptr && out2->ctx == 4096 && !out2->stop_honored, "READY without stop round-trips");
  }
  {
    u::Gen gen;
    gen.max_new = 128;
    gen.params = {{"temperature", "0.7"}, {"top_k", "40"}, {"seed", "12345"}};
    gen.ids = {2, 105, 2364, 107};
    const auto* out = round_trip<u::Gen>(u::Record{gen});
    expect(out != nullptr && out->max_new == 128 && out->params.size() == 3 && out->params[0].key == "temperature" &&
               out->params[0].value == "0.7" && out->ids == std::vector<std::uint32_t>{2, 105, 2364, 107},
           "GEN round-trips");
    u::Gen gen2;
    gen2.max_new = 16;
    gen2.ids = {1};
    const auto* out2 = round_trip<u::Gen>(u::Record{gen2});
    expect(out2 != nullptr && out2->max_new == 16 && out2->params.empty() &&
               out2->ids == std::vector<std::uint32_t>{1},
           "GEN with no params round-trips");
  }
  expect(round_trip<u::Stop>(u::Record{u::Stop{}}) != nullptr, "STOP round-trips");
  expect(round_trip<u::Quit>(u::Record{u::Quit{}}) != nullptr, "QUIT round-trips");
  {
    const auto* out = round_trip<u::Token>(u::Record{u::Token{45518}});
    expect(out != nullptr && out->id == 45518, "T round-trips");
  }
  {
    const auto* out = round_trip<u::PromptProgress>(u::Record{u::PromptProgress{12, 29, 250.0, 116.0}});
    expect(out != nullptr && out->done == 12 && out->total == 29 && close(out->ms, 250.0) && close(out->tok_s, 116.0),
           "PP round-trips");
  }
  {
    u::Stat stat;
    stat.fields = {{"vram_mib", "15000"}, {"reused", "4"}};
    const auto* out = round_trip<u::Stat>(u::Record{stat});
    expect(out != nullptr && out->fields.size() == 2 && out->fields[1].key == "reused", "STAT round-trips");
  }
  {
    const auto* out = round_trip<u::Done>(u::Record{u::Done{64, 29, 250.0, 1875.5, u::Finish::stop, 7, 12, 4}});
    expect(out != nullptr && out->produced == 64 && out->prompt == 29 && close(out->prompt_ms, 250.0) &&
               close(out->decode_ms, 1875.5) && out->finish == u::Finish::stop && out->spec_hits == 7 &&
               out->spec_steps == 12 && out->reused == 4,
           "DONE round-trips");
    // Every finish value survives.
    for (const auto fin : {u::Finish::stop, u::Finish::length, u::Finish::cancel, u::Finish::nonfinite}) {
      const auto* d = round_trip<u::Done>(u::Record{u::Done{1, 1, 0.0, 0.0, fin, 0, 0, 0}});
      expect(d != nullptr && d->finish == fin, "DONE finish value survives");
    }
  }
  {
    const auto* empty = round_trip<u::Err>(u::Record{u::Err{std::string{}}});
    expect(empty != nullptr && empty->text.empty(), "ERR with no text round-trips");
    const auto* text = round_trip<u::Err>(u::Record{u::Err{"the engine failed and more"}});
    expect(text != nullptr && text->text == "the engine failed and more", "ERR with spaced text round-trips");
  }
}

void protocol_rejects_malformed_and_unknown_lines() {
  std::vector<std::string> bad = {
      "",                                  // empty
      " ",                                 // a lone space
      "FOO 1",                             // unknown prefix
      "NOTE hello",                        // there is no NOTE record
      "RESUME 5",                          // there is no RESUME record
      "REUSED 3",                          // there is no REUSED record
      "READY",                             // missing ctx
      "READY -1",                          // negative ctx
      "READY 01",                          // leading zero
      "READY 1 go",                        // bad optional word
      "READY 1 stop extra",                // trailing junk
      "GEN 1",                             // no id list
      "GEN 0 1,2",                         // max_new 0
      "GEN 5 temperature 1,2",             // a param that is not key=value
      "GEN 5 1,2,",                        // a trailing comma in the ids
      "GEN 5 ,1",                          // a leading comma in the ids
      "T",                                 // missing id
      "T x",                               // id is not a number
      "T 1 2",                             // extra field
      "T 4294967296",                      // overflows u32
      "STOP x",                            // STOP takes no field
      "QUIT x",                            // QUIT takes no field
      "PP 1 2 3",                          // too few fields
      "PP 1 2 x 4",                        // a timing that is not a decimal
      "PP 1 2 1.0 2.0 3",                  // too many fields
      "PP 1 2 -1.0 2.0",                   // a negative timing
      "DONE 1 2 3 4 bogus 0 0 0",          // an unknown finish
      "DONE 1 2 3 4 stop 0 0",             // too few fields
      "INFO a",                            // a field that is not key=value
      "INFO =b",                           // an empty key
      "STAT a",                            // a field that is not key=value
      " READY 1",                          // a leading space
      "READY 1 ",                          // a trailing space
      "GEN  5 1",                          // a doubled space
      "T\t1",                              // a non-printable byte (tab)
  };
  for (const auto& line : bad) {
    const auto r = u::parse_line(line);
    expect(std::holds_alternative<u::ParseError>(r), "fail closed: '" + line + "'");
  }
  // An over-long line (8193 bytes) is refused.
  const std::string over(u::kMaxLineBytes + 1, 'a');
  expect(std::holds_alternative<u::ParseError>(u::parse_line(over)), "fail closed: an over-long line");
  // A line of exactly 8192 bytes passes the length gate (it still fails as an unknown record,
  // but not for length) -- confirm the boundary is inclusive by using a valid record.
  const std::string info_line = "INFO " + std::string(u::kMaxLineBytes - 7, 'a') + "=1";
  expect(info_line.size() == u::kMaxLineBytes, "the boundary line is exactly 8192 bytes");
  expect(std::holds_alternative<u::Record>(u::parse_line(info_line)), "a 8192-byte INFO is accepted");
}

// ---- dispatch ----------------------------------------------------------------------------

void dispatch_maps_known_archs_and_rejects_unknown() {
  const std::pair<const char*, u::FamilyId> known[] = {
      {"glm5next", u::FamilyId::glm5next}, {"ds4", u::FamilyId::ds4},         {"raon1", u::FamilyId::raon1},
      {"qwen35moe", u::FamilyId::qwen35moe}, {"qwen4exp", u::FamilyId::qwen4exp}, {"gemma4", u::FamilyId::gemma4},
  };
  for (const auto& [arch, family] : known) {
    const auto got = u::family_for_arch(arch);
    expect(got.has_value() && *got == family, std::string("dispatch maps ") + arch);
    expect(u::arch_of(family) == arch, std::string("arch_of round-trips ") + arch);
  }
  for (const char* unknown : {"", "llama", "GLM5NEXT", "raon", "gemma", "qwen"}) {
    expect(!u::family_for_arch(unknown).has_value(), std::string("dispatch rejects '") + unknown + "'");
  }
}

}  // namespace

int main(int argc, char** argv) {
  return u_test::run_cases(argc, argv,
                           {
                               {"gguf_parses_a_committed_header", gguf_parses_a_committed_header},
                               {"gguf_reads_a_header_from_disk", gguf_reads_a_header_from_disk},
                               {"geometry_guard_accepts_valid_key_sets", geometry_guard_accepts_valid_key_sets},
                               {"geometry_guard_rejects_bad_key_sets", geometry_guard_rejects_bad_key_sets},
                               {"protocol_round_trips_valid_lines", protocol_round_trips_valid_lines},
                               {"protocol_rejects_malformed_and_unknown_lines", protocol_rejects_malformed_and_unknown_lines},
                               {"dispatch_maps_known_archs_and_rejects_unknown", dispatch_maps_known_archs_and_rejects_unknown},
                           });
}
