#include <libpq-fe.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <ctime>

#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <fstream>
#include <sstream>
#include <chrono>
#include <atomic>
#include <filesystem>
#include <iomanip>
#include <iostream>

#include "env.h"

// logs
#define LOG(level, msg) do { \
    auto now = std::chrono::system_clock::now(); \
    auto t = std::chrono::system_clock::to_time_t(now); \
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000; \
    std::cout << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%M:%S.") \
              << std::setfill('0') << std::setw(3) << ms.count() \
              << " [" << level << "] " << msg << std::endl; \
} while(0)
#define LOG_INFO(msg)  LOG("INFO ", msg)
#define LOG_ERROR(msg) LOG("ERROR", msg)
#define LOG_DEBUG(msg) LOG("DEBUG", msg)

namespace fs = std::filesystem;


struct TicketRow {
  char name_buf[200];
  std::string bus_code;
  std::string user_email;
  std::string travel_date;
  int         seats       = 1;
  int         start_node  = 0;
  int         end_node    = 0;
  long long   total_cents = 0;
};

static std::mutex  g_json_mx;
static std::string g_latest_json;

// ── util ────────────────────────────────────────────────────────────────────
static std::string jesc(const std::string& s) {
  std::string out; out.reserve(s.size() + 8);
  for (unsigned char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n";  break;
      case '\r': out += "\\r";  break;
      case '\t': out += "\\t";  break;
      default:
        if (c < 0x20) {
          char buf[7]; std::snprintf(buf, sizeof(buf), "\\u%04x", c); out += buf;
        } else {
          out += static_cast<char>(c);
        }
    }
  }
  return out;
}

static std::string to_json(const std::vector<TicketRow>& rows, const std::string& source) {
  std::ostringstream oss;
  oss << "{ \"source\":\"" << jesc(source) << "\", \"tickets\":[";
  bool first = true;
  for (const auto& r : rows) {
    if (!first) oss << ","; first = false;
    oss << "{"
        << "\"name\":\""        << jesc(r.name_buf)    << "\","
        << "\"bus_code\":\""     << jesc(r.bus_code)    << "\","
        << "\"user_email\":\""   << jesc(r.user_email)  << "\","
        << "\"travel_date\":\""  << jesc(r.travel_date) << "\","
        << "\"seats\":"          << r.seats             << ","
        << "\"start_node\":"     << r.start_node        << ","
        << "\"end_node\":"       << r.end_node          << ","
        << "\"total_cents\":"    << r.total_cents
        << "}";
  }
  oss << "] }";
  return oss.str();
}

static void write_file_atomic(const fs::path& path, const std::string& contents) {
  try {
    fs::create_directories(path.parent_path());
    fs::path tmp = path; tmp += ".tmp";
    { std::ofstream out(tmp, std::ios::binary); out.write(contents.data(), (std::streamsize)contents.size()); }
    fs::rename(tmp, path);
  } catch (const std::exception& e) {
    LOG_ERROR("write " << path << ": " << e.what());
    throw;
  }
}

// ── db ─────────────────────────────────────────────────────────────────────
static std::vector<TicketRow> fetch_postgres(const Env& env) {
  std::vector<TicketRow> out;

  std::string host = env.get("PGHOST", "127.0.0.1");
  int         port = env.get_int("PGPORT", 5432);
  std::string user = env.get("PGUSER", "postgres");
  std::string pass = env.get("PGPASSWORD", "");
  std::string db   = env.get("PGDATABASE", "smbs_development");
  int         cto  = env.get_int("PGCONNECT_TIMEOUT", 2);

  LOG_DEBUG("db connect " << host << ":" << port << "/" << db);

  std::ostringstream ci;
  ci << "host=" << host
     << " port=" << port
     << " user=" << user
     << " password=******"
     << " dbname=" << db
     << " connect_timeout=" << cto;

  PGconn* conn = PQconnectdb(ci.str().c_str());
  if (PQstatus(conn) != CONNECTION_OK) {
    LOG_ERROR("pg connect: " << PQerrorMessage(conn));
    PQfinish(conn);
    return out;
  }

  const char* sql =
    "SELECT "
    "COALESCE(t.name,'') AS name, "
    "COALESCE(t.bus_code,'') AS bus_code, "
    "COALESCE(u.email,'') AS user_email, "
    "to_char(t.travel_date,'YYYY-MM-DD') AS travel_date, "
    "COALESCE(t.seats,1) AS seats, "
    "COALESCE(t.start_node,0) AS start_node, "
    "COALESCE(t.end_node,0) AS end_node, "
    "COALESCE(t.total_cents,0) AS total_cents "
    "FROM public.tickets t "
    "LEFT JOIN public.users u ON u.id = t.user_id "
    "ORDER BY t.updated_at DESC "
    "LIMIT 500";

  PGresult* res = PQexec(conn, sql);
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    LOG_ERROR("pg query: " << PQresultErrorMessage(res));
    PQclear(res); PQfinish(conn); return out;
  }

  int rows = PQntuples(res);
  for (int i = 0; i < rows; ++i) {
    TicketRow tr{};
    const char* name = PQgetvalue(res, i, 0);
    std::strcpy(tr.name_buf, name); 
    tr.bus_code    = PQgetvalue(res, i, 1);
    tr.user_email  = PQgetvalue(res, i, 2);
    tr.travel_date = PQgetvalue(res, i, 3);
    tr.seats       = std::atoi(PQgetvalue(res, i, 4));
    tr.start_node  = std::atoi(PQgetvalue(res, i, 5));
    tr.end_node    = std::atoi(PQgetvalue(res, i, 6));
    tr.total_cents = std::atoll(PQgetvalue(res, i, 7));
    out.push_back(tr);
  }

  PQclear(res); PQfinish(conn);
  return out;
}

static std::vector<TicketRow> mock_rows() {
  std::vector<TicketRow> v;
  for (int i = 0; i < 5; i++) {
    TicketRow tr{};
    std::string nm = "MOCK-" + std::to_string(i + 1);
    std::strcpy(tr.name_buf, nm.c_str());
    tr.bus_code    = std::to_string(i);
    tr.user_email  = "—";
    tr.travel_date = "2025-01-01";
    tr.seats       = 1;
    tr.start_node  = std::rand() % 12;
    tr.end_node    = 30 + (std::rand() % 60);
    tr.total_cents = (std::llabs(tr.end_node - tr.start_node) * 50LL * 100LL);
    v.push_back(tr);
  }
  return v;
}

// ── refresh / bootstrap ─────────────────────────────────────────────────────
static void refresh_loop(const Env env) {
  const int       period   = env.get_int("PULL_INTERVAL_SECONDS", 10);
  const fs::path  data_dir = env.get("DATA_DIR", "./data");
  const fs::path  latest   = data_dir / "latest.json";
  LOG_INFO("refresh every " << period << "s");

  while (true) {
    auto rows = fetch_postgres(env);
    bool using_mock = rows.empty();
    if (using_mock) rows = mock_rows();
    std::string json = to_json(rows, using_mock ? "mock" : "parser");

    { std::lock_guard<std::mutex> lk(g_json_mx); g_latest_json = json; }
    write_file_atomic(latest, json);

    std::this_thread::sleep_for(std::chrono::seconds(period));
  }
}

static void load_bootstrap_latest(const Env& env) {
  const fs::path latest = fs::path(env.get("DATA_DIR", "./data")) / "latest.json";
  if (fs::exists(latest)) {
    try {
      std::ifstream in(latest, std::ios::binary); std::ostringstream ss; ss << in.rdbuf();
      std::lock_guard<std::mutex> lk(g_json_mx); g_latest_json = ss.str();
    } catch (const std::exception& e) {
      LOG_ERROR("bootstrap: " << e.what());
    }
  } else {
    auto rows = mock_rows();
    std::lock_guard<std::mutex> lk(g_json_mx); g_latest_json = to_json(rows, "mock");
  }
}

// ── tcp server ──────────────────────────────────────────────────────────────
static void serve(const Env& env) {
  std::string host = env.get("LISTEN_HOST", "127.0.0.1");
  int         port = env.get_int("LISTEN_PORT", 9099);

  int srv = ::socket(AF_INET, SOCK_STREAM, 0); if (srv < 0) { std::perror("socket"); return; }
  int opt = 1; ::setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port); addr.sin_addr.s_addr = inet_addr(host.c_str());
  if (::bind(srv, (sockaddr*)&addr, sizeof(addr)) < 0) { std::perror("bind"); ::close(srv); return; }
  if (::listen(srv, 16) < 0) { std::perror("listen"); ::close(srv); return; }

  while (true) {
    sockaddr_in cli{}; socklen_t cl = sizeof(cli);
    int c = ::accept(srv, (sockaddr*)&cli, &cl); if (c < 0) { continue; }
    char buf[256]; ::recv(c, buf, sizeof(buf), 0); // ignore request content

    std::string json; { std::lock_guard<std::mutex> lk(g_json_mx); json = g_latest_json; }
    if (json.empty()) { json = to_json(mock_rows(), "mock"); }

    std::string payload = json + "\n";
    ::send(c, payload.data(), payload.size(), 0);
    ::close(c);
  }
}

int main() {
  std::srand((unsigned)std::time(nullptr));
  Env env; if (fs::exists(".env")) env.load_file(".env");
  load_bootstrap_latest(env);
  std::thread t(refresh_loop, env); t.detach();
  serve(env);
  return 0;
}