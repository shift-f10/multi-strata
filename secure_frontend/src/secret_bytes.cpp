#include "secure_frontend/secret_bytes.hpp"

#include <cstring>

#if defined(_WIN32)
#include "secure_frontend/win32_prelude.hpp"
#else
#include <string.h>
#endif

namespace secure_frontend {

void secure_wipe(void* const data, const std::size_t size) noexcept {
  if (data == nullptr || size == 0U) return;
#if defined(_WIN32)
  SecureZeroMemory(data, size);
#elif defined(__GLIBC__)
  explicit_bzero(data, size);
#else
  volatile unsigned char* bytes = static_cast<volatile unsigned char*>(data);
  for (std::size_t index = 0; index < size; ++index) bytes[index] = 0U;
#endif
}

SecretBytes::SecretBytes(SecretBytes&& other) noexcept : size_(other.size_) {
  std::memcpy(bytes_.data(), other.bytes_.data(), other.size_);
  other.clear();
}

SecretBytes& SecretBytes::operator=(SecretBytes&& other) noexcept {
  if (this != &other) {
    clear();
    std::memcpy(bytes_.data(), other.bytes_.data(), other.size_);
    size_ = other.size_;
    other.clear();
  }
  return *this;
}

SecretBytes::~SecretBytes() { clear(); }

bool SecretBytes::assign(const std::string_view bytes) noexcept {
  clear();
  return append(bytes);
}

bool SecretBytes::append(const std::string_view bytes) noexcept {
  if (bytes.size() > kCapacity - size_) return false;
  if (!bytes.empty()) std::memcpy(bytes_.data() + size_, bytes.data(), bytes.size());
  size_ += bytes.size();
  return true;
}

void SecretBytes::clear() noexcept {
  secure_wipe(bytes_.data(), bytes_.size());
  size_ = 0U;
}

std::string_view SecretBytes::view() const noexcept {
  return std::string_view{reinterpret_cast<const char*>(bytes_.data()), size_};
}

}  // namespace secure_frontend
