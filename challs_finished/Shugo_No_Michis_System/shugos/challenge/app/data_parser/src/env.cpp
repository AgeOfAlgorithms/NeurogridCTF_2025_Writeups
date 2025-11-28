#include "env.h"
#include <fstream>
#include <sstream>
#include <cstdlib>

static bool starts_with(const std::string& s, const std::string& p){ return s.rfind(p,0)==0; }

std::string Env::trim(const std::string& s){
  size_t b=0,e=s.size();
  while(b<e && isspace((unsigned char)s[b])) ++b;
  while(e>b && isspace((unsigned char)s[e-1])) --e;
  return s.substr(b,e-b);
}

void Env::load_file(const std::string& path){
  std::ifstream in(path);
  if(!in.good()) return;
  std::string line;
  while(std::getline(in,line)){
    line = trim(line);
    if(line.empty() || line[0]=='#') continue;
    auto pos = line.find('=');
    if(pos==std::string::npos) continue;
    auto k = trim(line.substr(0,pos));
    auto v = trim(line.substr(pos+1));
    kv[k]=v;
  }
}

std::string Env::get(const std::string& key, const std::string& def) const{
  // environment variable overrides .env
  if(const char* ev = std::getenv(key.c_str())) return std::string(ev);
  auto it = kv.find(key);
  return it==kv.end()? def : it->second;
}

int Env::get_int(const std::string& key, int def) const{
  try { return std::stoi(get(key, std::to_string(def))); } catch(...) { return def; }
}
