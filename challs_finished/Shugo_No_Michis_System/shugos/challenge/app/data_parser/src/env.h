#pragma once
#include <string>
#include <unordered_map>

struct Env {
  std::unordered_map<std::string,std::string> kv;

  void load_file(const std::string& path);
  static std::string trim(const std::string& s);
  std::string get(const std::string& key, const std::string& def = "") const;
  int get_int(const std::string& key, int def) const;
};
