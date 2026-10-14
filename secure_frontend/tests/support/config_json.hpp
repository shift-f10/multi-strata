#pragma once
#include "secure_frontend/json.hpp"
#include "support/test_support.hpp"

#include <filesystem>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace secure_frontend_test {

inline std::string json_literal(const std::string& text) {
  std::string out;
  secure_frontend::append_json_string(&out, text);
  return out;
}

// Renders {"a":{"b":1}} from {{"a.b","1"}} (values are JSON literals). The key
// path named by `duplicate` is written twice, for duplicate-key tests.
inline std::string render_config_json(const std::map<std::string, std::string>& literals,
                                      const std::string& duplicate = {}) {
  struct Node {
    std::vector<std::string> names;
    std::vector<Node> children;
    std::string literal;
  };
  Node root;
  for (const auto& [path, literal] : literals) {
    Node* node = &root;
    std::size_t start = 0;
    while (true) {
      const auto dot = path.find('.', start);
      const std::string name = path.substr(start, dot == std::string::npos ? std::string::npos : dot - start);
      std::size_t index = 0;
      while (index < node->names.size() && node->names[index] != name) ++index;
      if (index == node->names.size()) {
        node->names.push_back(name);
        node->children.emplace_back();
      }
      node = &node->children[index];
      if (dot == std::string::npos) break;
      start = dot + 1;
    }
    node->literal = literal;
  }
  std::function<void(const Node&, const std::string&, std::string&)> emit =
      [&](const Node& node, const std::string& prefix, std::string& out) {
        out += '{';
        for (std::size_t i = 0; i < node.names.size(); ++i) {
          const std::string path = prefix.empty() ? node.names[i] : prefix + "." + node.names[i];
          for (int copy = 0; copy < (path == duplicate ? 2 : 1); ++copy) {
            if (out.back() != '{') out += ',';
            out += json_literal(node.names[i]) + ':';
            if (node.children[i].names.empty()) out += node.children[i].literal;
            else emit(node.children[i], path, out);
          }
        }
        out += '}';
      };
  std::string out;
  emit(root, "", out);
  return out;
}

// A valid minimal configuration over real, owner-only directories: models,
// tokenizer pack, secret root and an engine file (mode 0700).
struct ConfigFixture final {
  std::filesystem::path dir = make_scratch_directory();
  std::map<std::string, std::string> literals;

  ConfigFixture() {
    for (const char* name : {"models", "tok", "secret", "bin"}) make_private_directory(dir / name);
    write_file(dir / "bin" / "engine", "not a real engine\n", 0700);
    literals = {{"schema_version", "1"},
                {"roots.models", json_literal((dir / "models").string())},
                {"roots.tokenizer_pack", json_literal((dir / "tok").string())},
                {"roots.secret", json_literal((dir / "secret").string())},
                {"engine.executable", json_literal((dir / "bin" / "engine").string())},
                {"engine.model_id", json_literal("qwen-local")}};
  }
  [[nodiscard]] std::string document(const std::string& duplicate = {}) const {
    return render_config_json(literals, duplicate);
  }
};

}  // namespace secure_frontend_test
