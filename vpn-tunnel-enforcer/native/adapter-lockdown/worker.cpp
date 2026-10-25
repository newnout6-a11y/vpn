// AT-03-006/007/012: fixed native adapter-binding/DNS batch. No NIC disable,
// shell, registry, firewall or transition-interface operations live here.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2ipdef.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <objbase.h>
#include <netcfgx.h>
#include <devguid.h>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
constexpr size_t MAX_INPUT = 262144;
struct Failure { DWORD code; };
void require(bool ok, DWORD code = ERROR_INVALID_DATA) { if (!ok) throw Failure{code}; }
void hr(HRESULT value) { if (value != S_OK) throw Failure{static_cast<DWORD>(value)}; }
using Clock = std::chrono::steady_clock;
void timing(const char* phase, Clock::time_point start) {
  std::cout << "NATIVE_TIMING phase=" << phase << " durationMs="
            << std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count() << '\n';
}
std::vector<std::string> split(const std::string& text, char separator) {
  std::vector<std::string> out; size_t from = 0;
  do { size_t end = text.find(separator, from); out.push_back(text.substr(from, end - from));
       if (end == std::string::npos) break;
       from = end + 1; } while (true);
  return out;
}
int hex(char c) { if (c >= '0' && c <= '9') return c - '0'; if (c >= 'a' && c <= 'f') return c - 'a' + 10; if (c >= 'A' && c <= 'F') return c - 'A' + 10; return -1; }
GUID parseGuid(const std::string& text) {
  require(text.size() == 38 && text.front() == '{' && text.back() == '}');
  for (size_t n : {size_t(9), size_t(14), size_t(19), size_t(24)}) require(text[n] == '-');
  std::vector<unsigned char> bytes;
  for (size_t n = 1; n < 37;) {
    if (text[n] == '-') { ++n; continue; }
    require(n + 1 < 37 && hex(text[n]) >= 0 && hex(text[n + 1]) >= 0);
    bytes.push_back(static_cast<unsigned char>((hex(text[n]) << 4) | hex(text[n + 1]))); n += 2;
  }
  require(bytes.size() == 16 && std::any_of(bytes.begin(), bytes.end(), [](unsigned char v) { return v != 0; }));
  GUID g{}; g.Data1 = (DWORD(bytes[0]) << 24) | (DWORD(bytes[1]) << 16) | (DWORD(bytes[2]) << 8) | bytes[3];
  g.Data2 = WORD((bytes[4] << 8) | bytes[5]); g.Data3 = WORD((bytes[6] << 8) | bytes[7]);
  std::copy(bytes.begin() + 8, bytes.end(), g.Data4); return g;
}
bool ipv4(const std::string& text) {
  const auto parts = split(text, '.'); if (parts.size() != 4) return false;
  for (const auto& p : parts) {
    if (p.empty() || p.size() > 3 || (p.size() > 1 && p.front() == '0')) return false;
    unsigned value = 0; for (char c : p) { if (c < '0' || c > '9') return false; value = value * 10 + unsigned(c - '0'); }
    if (value > 255) return false;
  }
  return true;
}
struct Row { size_t index; GUID guid; std::string ipv6, dns; std::vector<std::string> servers; };
std::vector<Row> parse(const std::string& input) {
  require(input.size() <= MAX_INPUT);
  for (unsigned char c : input) require((c >= 32 && c <= 126) || c == '\n' || c == '\r');
  auto lines = split(input, '\n'); if (!lines.empty() && lines.back().empty()) lines.pop_back();
  for (auto& line : lines) if (!line.empty() && line.back() == '\r') line.pop_back();
  require(lines.size() >= 2 && lines.size() <= 257 && lines.front() == "VPNTE_LOCKDOWN_V1");
  std::vector<Row> rows; std::set<std::string> identities;
  for (size_t i = 1; i < lines.size(); ++i) {
    const auto fields = split(lines[i], '|'); require(fields.size() == 5 && fields[0] == std::to_string(i - 1));
    Row row{i - 1, parseGuid(fields[1]), fields[2], fields[3], {}};
    std::string identity = fields[1]; std::transform(identity.begin(), identity.end(), identity.begin(), [](unsigned char c) { return char(c >= 'A' && c <= 'F' ? c + 32 : c); });
    require(identities.insert(identity).second);
    require(row.ipv6 == "off" || row.ipv6 == "on" || row.ipv6 == "skip" || row.ipv6 == "noop");
    require(row.dns == "set" || row.dns == "restore" || row.dns == "reset" || row.dns == "skip" || row.dns == "noop");
    if (row.dns == "set" || row.dns == "restore") {
      row.servers = split(fields[4], ','); require(!row.servers.empty() && row.servers.size() <= 16);
      std::set<std::string> unique; for (const auto& server : row.servers) require(ipv4(server) && unique.insert(server).second);
    } else require(fields[4] == "-");
    rows.push_back(std::move(row));
  }
  return rows;
}
template<class T> struct ComPtr {
  T* p = nullptr;
  ~ComPtr() { if (p) p->Release(); }
  ComPtr() = default; ComPtr(const ComPtr&) = delete; ComPtr& operator=(const ComPtr&) = delete;
  T** put() { require(p == nullptr); return &p; } T* operator->() const { return p; }
};
struct ComApartment {
  ComApartment() { const auto r = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED); require(r == S_OK || r == S_FALSE, DWORD(r)); }
  ~ComApartment() { CoUninitialize(); }
};
struct NetConfig {
  ComPtr<INetCfg> cfg; ComPtr<INetCfgLock> lock; bool initialized = false, acquired = false, staged = false;
  explicit NetConfig(bool writable) {
    try {
      hr(CoCreateInstance(CLSID_CNetCfg, nullptr, CLSCTX_INPROC_SERVER, IID_INetCfg, reinterpret_cast<void**>(cfg.put())));
      if (writable) {
        hr(cfg->QueryInterface(IID_INetCfgLock, reinterpret_cast<void**>(lock.put())));
        LPWSTR holder = nullptr; const auto result = lock->AcquireWriteLock(5000, L"VPNTE adapter lockdown", &holder);
        CoTaskMemFree(holder); hr(result); acquired = true;
      }
      hr(cfg->Initialize(nullptr)); initialized = true;
    } catch (...) { close(); throw; }
  }
  void close() {
    if (initialized) { if (staged) cfg->Cancel(); cfg->Uninitialize(); initialized = false; }
    if (acquired) { lock->ReleaseWriteLock(); acquired = false; }
  }
  ~NetConfig() { close(); }
};
void bindingPaths(INetCfg* cfg, const std::vector<Row>& rows, std::vector<INetCfgBindingPath*>& found) {
  ComPtr<INetCfgComponent> protocol; hr(cfg->FindComponent(L"ms_tcpip6", protocol.put())); require(protocol.p != nullptr);
  ComPtr<INetCfgComponentBindings> bindings; hr(protocol->QueryInterface(IID_INetCfgComponentBindings, reinterpret_cast<void**>(bindings.put())));
  ComPtr<IEnumNetCfgBindingPath> paths; hr(bindings->EnumBindingPaths(EBP_BELOW, paths.put()));
  std::vector<unsigned> counts(rows.size());
  for (unsigned guard = 0;; ++guard) {
    require(guard < 16384); ComPtr<INetCfgBindingPath> path; ULONG fetched = 0;
    const auto next = paths->Next(1, path.put(), &fetched); if (next == S_FALSE) break; hr(next); require(fetched == 1 && path.p);
    // GetDepth counts components, not edges: a direct protocol -> adapter
    // path has two components. Independently require exactly one interface.
    ULONG depth = 0; hr(path->GetDepth(&depth)); if (depth != 2) continue;
    ComPtr<IEnumNetCfgBindingInterface> edges; hr(path->EnumBindingInterfaces(edges.put()));
    ComPtr<INetCfgBindingInterface> edge; fetched = 0; hr(edges->Next(1, edge.put(), &fetched)); require(fetched == 1 && edge.p);
    ComPtr<INetCfgBindingInterface> extra; fetched = 0;
    require(edges->Next(1, extra.put(), &fetched) == S_FALSE && fetched == 0);
    ComPtr<INetCfgComponent> upper, lower; hr(edge->GetUpperComponent(upper.put())); hr(edge->GetLowerComponent(lower.put()));
    LPWSTR id = nullptr; hr(upper->GetId(&id)); const bool tcp6 = id && _wcsicmp(id, L"ms_tcpip6") == 0; CoTaskMemFree(id); if (!tcp6) continue;
    GUID cls{}, guid{}; hr(lower->GetClassGuid(&cls)); if (!IsEqualGUID(cls, GUID_DEVCLASS_NET)) continue; hr(lower->GetInstanceGuid(&guid));
    for (size_t n = 0; n < rows.size(); ++n) if (IsEqualGUID(guid, rows[n].guid)) {
      require(++counts[n] == 1); path->AddRef(); found[n] = path.p;
    }
  }
  for (size_t n = 0; n < rows.size(); ++n) if (rows[n].ipv6 == "off" || rows[n].ipv6 == "on") require(counts[n] == 1, ERROR_NOT_FOUND);
}
struct Paths {
  std::vector<INetCfgBindingPath*> values;
  explicit Paths(size_t size) : values(size, nullptr) {}
  ~Paths() { for (auto p : values) if (p) p->Release(); }
};
bool enabled(INetCfgBindingPath* path) { require(path != nullptr, ERROR_NOT_FOUND); const auto r = path->IsEnabled(); require(r == S_OK || r == S_FALSE, DWORD(r)); return r == S_OK; }
void verifyInterface(const GUID& guid) {
  NET_LUID luid{}; DWORD rc = ConvertInterfaceGuidToLuid(&guid, &luid); require(rc == NO_ERROR, rc);
  MIB_IF_ROW2 row{}; row.InterfaceLuid = luid; rc = GetIfEntry2(&row); require(rc == NO_ERROR, rc);
  require(IsEqualGUID(row.InterfaceGuid, guid) && row.InterfaceIndex != 0, ERROR_NOT_FOUND);
}
// MinGW lacks this API; prefer the Windows SDK definition when available.
#ifdef DNS_INTERFACE_SETTINGS_VERSION1
using DnsSettings = DNS_INTERFACE_SETTINGS;
#else
struct DnsSettings {
  ULONG Version; ULONG64 Flags; PWSTR Domain; PWSTR NameServer; PWSTR SearchList;
  ULONG RegistrationEnabled, RegisterAdapterName, EnableLLMNR, QueryAdapterName; PWSTR ProfileNameServer;
};
#endif
static_assert(sizeof(DnsSettings) == 64, "DNS_INTERFACE_SETTINGS v1 x64 ABI");
static_assert(offsetof(DnsSettings, Flags) == 8 && offsetof(DnsSettings, Domain) == 16 &&
              offsetof(DnsSettings, NameServer) == 24 && offsetof(DnsSettings, SearchList) == 32 &&
              offsetof(DnsSettings, RegistrationEnabled) == 40 && offsetof(DnsSettings, ProfileNameServer) == 56,
              "DNS_INTERFACE_SETTINGS v1 field offsets");
struct DnsApi {
  using Get = DWORD (WINAPI*)(GUID, DnsSettings*); using Set = DWORD (WINAPI*)(GUID, const DnsSettings*); using Free = void (WINAPI*)(DnsSettings*);
  HMODULE module = nullptr; Get get = nullptr; Set set = nullptr; Free free = nullptr;
  template<class T> T function(const char* name) {
    const FARPROC address = GetProcAddress(module, name); T result = nullptr;
    static_assert(sizeof(result) == sizeof(address), "Windows function pointer ABI");
    std::memcpy(&result, &address, sizeof(result)); return result;
  }
  DnsApi() {
    module = LoadLibraryExW(L"iphlpapi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32); require(module != nullptr, GetLastError());
    get = function<Get>("GetInterfaceDnsSettings"); set = function<Set>("SetInterfaceDnsSettings"); free = function<Free>("FreeInterfaceDnsSettings");
    if (!get || !set || !free) { FreeLibrary(module); module = nullptr; throw Failure{ERROR_PROC_NOT_FOUND}; }
  }
  ~DnsApi() { if (module) FreeLibrary(module); }
  std::vector<std::string> read(const GUID& guid) {
    DnsSettings value{}; value.Version = 1; const DWORD rc = get(guid, &value); require(rc == NO_ERROR, rc);
    struct Cleanup { Free release; DnsSettings* value; ~Cleanup() { release(value); } } cleanup{free, &value};
    require(value.Version == 1); std::vector<std::string> result; if (!value.NameServer) return result;
    std::string part;
    for (size_t n = 0;; ++n) {
      require(n <= 4096); const wchar_t c = value.NameServer[n];
      if (c == 0 || c == L',' || c == L';' || c == L' ' || c == L'\t') {
        if (!part.empty()) { require(ipv4(part)); result.push_back(part); part.clear(); require(result.size() <= 16); }
        if (c == 0) return result;
      } else { require((c >= L'0' && c <= L'9') || c == L'.'); part.push_back(char(c)); }
    }
  }
  void write(const Row& row) {
    std::wstring names;
    for (const auto& s : row.servers) { if (!names.empty()) names += L','; names.append(s.begin(), s.end()); }
    DnsSettings value{}; value.Version = 1; value.Flags = 2; value.NameServer = const_cast<PWSTR>(names.c_str());
    const DWORD rc = set(row.guid, &value); require(rc == NO_ERROR, rc);
  }
};
bool elevated() {
  HANDLE token = nullptr; if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
  TOKEN_ELEVATION value{}; DWORD size = 0; const BOOL ok = GetTokenInformation(token, TokenElevation, &value, sizeof(value), &size); CloseHandle(token);
  return ok && size == sizeof(value) && value.TokenIsElevated != 0;
}
void error(size_t index, const char* field, DWORD code) { std::cout << 'A' << index << '_' << field << "_err: native code=" << code << '\n'; }
int execute(const std::vector<Row>& rows, bool inspect) {
  const auto total = Clock::now(); bool failed = false; std::vector<bool> before(rows.size()), after(rows.size());
  try {
    if (!inspect) require(elevated(), ERROR_ELEVATION_REQUIRED);
    const auto preflight = Clock::now(); for (const auto& row : rows) verifyInterface(row.guid);
    DnsApi dns;
    // Require every DNS read to succeed before staging any binding change.
    for (const auto& row : rows) dns.read(row.guid);
    ComApartment apartment;
    {
      NetConfig config(!inspect); Paths paths(rows.size()); bindingPaths(config.cfg.p, rows, paths.values);
      for (size_t n = 0; n < rows.size(); ++n) {
        if (inspect || rows[n].ipv6 == "off" || rows[n].ipv6 == "on") before[n] = enabled(paths.values[n]);
      }
      timing("preflight", preflight);
      if (!inspect) {
        const auto binding = Clock::now();
        for (size_t n = 0; n < rows.size(); ++n) if (rows[n].ipv6 == "off" || rows[n].ipv6 == "on") {
          const bool want = rows[n].ipv6 == "on"; if (before[n] != want) { config.staged = true; hr(paths.values[n]->Enable(want)); }
        }
        if (config.staged) { hr(config.cfg->Apply()); config.staged = false; }
        timing("binding-apply", binding);
      }
    }
    // A new INetCfg instance proves committed state; staged IsEnabled is insufficient.
    const auto readback = Clock::now();
    { NetConfig fresh(false); Paths paths(rows.size()); bindingPaths(fresh.cfg.p, rows, paths.values);
      for (size_t n = 0; n < rows.size(); ++n) if (inspect || rows[n].ipv6 == "off" || rows[n].ipv6 == "on") after[n] = enabled(paths.values[n]); }
    timing("binding-readback", readback);
    for (size_t n = 0; n < rows.size(); ++n) {
      const auto& row = rows[n];
      if (inspect) std::cout << 'A' << n << "_ipv6:" << (after[n] ? "enabled" : "disabled") << '\n';
      else if (row.ipv6 == "skip" || row.ipv6 == "noop") std::cout << 'A' << n << "_ipv6:" << row.ipv6 << '\n';
      else if (after[n] != (row.ipv6 == "on")) { error(n, "ipv6", ERROR_INVALID_STATE); failed = true; }
      else { if (row.ipv6 == "off" && !before[n]) std::cout << 'A' << n << "_ipv6:already-off\n"; std::cout << 'A' << n << "_ipv6:" << row.ipv6 << '\n'; }
    }
    // Do not start DNS effects when the committed binding outcome is uncertain.
    if (failed) throw Failure{ERROR_INVALID_STATE};
    const auto dnsStart = Clock::now();
    for (const auto& row : rows) {
      try {
        verifyInterface(row.guid);
        if (inspect) {
          const auto values = dns.read(row.guid); std::cout << 'A' << row.index << "_dns:";
          if (values.empty()) std::cout << "none"; else for (size_t n = 0; n < values.size(); ++n) { if (n) std::cout << ','; std::cout << values[n]; }
          std::cout << '\n';
        } else if (row.dns == "skip" || row.dns == "noop") std::cout << 'A' << row.index << "_dns:" << row.dns << '\n';
        else { dns.write(row); require(dns.read(row.guid) == row.servers, ERROR_INVALID_STATE); std::cout << 'A' << row.index << "_dns:" << row.dns << '\n'; }
      } catch (const Failure& e) { error(row.index, "dns", e.code); failed = true; }
    }
    timing("dns-apply-readback", dnsStart);
  } catch (const Failure& e) {
    for (const auto& row : rows) { error(row.index, "ipv6", e.code); error(row.index, "dns", e.code); } failed = true;
  }
  timing("total", total); return failed ? 1 : 0;
}
// Recovery deliberately has no batch-wide adapter/DNS/binding preflight: a
// removed USB NIC or failed IPv6 restoration must not strand another NIC's DNS.
// This orchestration is shared with fault-injection tests, not a mock of Windows.
template<class Action, class Receipt>
bool restoreIndependently(const std::vector<Row>& rows, Action action, Receipt receipt) {
  bool failed = false;
  for (const auto& row : rows) for (unsigned field = 0; field < 2; ++field) {
    DWORD code = NO_ERROR;
    try { action(row, field); } catch (const Failure& e) { code = e.code; failed = true; }
    receipt(row, field, code);
  }
  return failed;
}
void restoreIpv6(const Row& row) {
  if (row.ipv6 == "skip" || row.ipv6 == "noop") return;
  verifyInterface(row.guid); ComApartment apartment;
  const std::vector<Row> one{row}; const bool want = row.ipv6 == "on";
  {
    NetConfig config(true); Paths paths(1); bindingPaths(config.cfg.p, one, paths.values);
    if (enabled(paths.values[0]) != want) {
      config.staged = true; hr(paths.values[0]->Enable(want)); hr(config.cfg->Apply()); config.staged = false;
    }
  }
  verifyInterface(row.guid);
  NetConfig fresh(false); Paths paths(1); bindingPaths(fresh.cfg.p, one, paths.values);
  require(enabled(paths.values[0]) == want, ERROR_INVALID_STATE);
}
void restoreDns(const Row& row) {
  if (row.dns == "skip" || row.dns == "noop") return;
  verifyInterface(row.guid); DnsApi dns;
  dns.write(row); require(dns.read(row.guid) == row.servers, ERROR_INVALID_STATE);
}
int restore(const std::vector<Row>& rows) {
  const auto total = Clock::now();
  require(elevated(), ERROR_ELEVATION_REQUIRED);
  std::chrono::nanoseconds elapsed[2]{};
  const bool failed = restoreIndependently(rows, [&](const Row& row, unsigned field) {
    struct Measure {
      std::chrono::nanoseconds& elapsed; Clock::time_point start = Clock::now();
      ~Measure() { elapsed += Clock::now() - start; }
    } measure{elapsed[field]};
    if (field == 0) restoreIpv6(row); else restoreDns(row);
  }, [](const Row& row, unsigned field, DWORD code) {
    const char* name = field == 0 ? "ipv6" : "dns";
    if (code != NO_ERROR) error(row.index, name, code);
    else std::cout << 'A' << row.index << '_' << name << ':' << (field == 0 ? row.ipv6 : row.dns) << '\n';
  });
  for (unsigned field = 0; field < 2; ++field) std::cout << "NATIVE_TIMING phase=restore-" << (field == 0 ? "ipv6" : "dns")
    << " durationMs=" << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed[field]).count() << '\n';
  timing("total", total); return failed ? 1 : 0;
}
unsigned restoreSelfTest() {
  const std::vector<Row> rows{{0, {}, "on", "reset", {}}, {1, {}, "on", "restore", {"192.0.2.1"}}, {2, {}, "noop", "noop", {}}};
  // Every failure subset across three adapters and both fields must preserve
  // six ordered, independent outcomes, including DNS after an IPv6 failure.
  for (unsigned mask = 0; mask < 64; ++mask) {
    std::vector<unsigned> actions, receipts;
    const bool failed = restoreIndependently(rows, [&](const Row& row, unsigned field) {
      const auto step = unsigned(row.index * 2 + field); actions.push_back(step);
      if ((mask & (1u << step)) != 0) throw Failure{ERROR_NOT_FOUND};
    }, [&](const Row& row, unsigned field, DWORD code) {
      const auto step = unsigned(row.index * 2 + field); receipts.push_back(step);
      require(code == ((mask & (1u << step)) != 0 ? ERROR_NOT_FOUND : NO_ERROR));
    });
    const std::vector<unsigned> expected{0, 1, 2, 3, 4, 5};
    require(failed == (mask != 0) && actions == expected && receipts == expected);
  }
  return 64;
}
int selfTest() {
  const std::string header = "VPNTE_LOCKDOWN_V1\n", guid = "{11111111-2222-3333-4444-555555555555}";
  const std::string valid = header + "0|" + guid + "|off|set|192.168.250.254\n";
  require(parse(valid).size() == 1); require(parse(header + "0|" + guid + "|skip|reset|-\r\n").size() == 1);
  std::vector<std::string> bad = {"", header, "other\n0|" + guid + "|off|skip|-", header + "0|" + guid + "|off|skip|-\n1|" + guid + "|on|skip|-", header + "1|" + guid + "|off|skip|-", header + "00|" + guid + "|off|skip|-", header + "0|" + guid + "|disable|skip|-", header + "0|" + guid + "|off|set|1.2.3.999", header + "0|" + guid + "|off|set|01.2.3.4", header + "0|" + guid + "|off|skip|1.2.3.4", header + "0|" + guid + "|off|reset|-|extra", valid + "\n", std::string(MAX_INPUT + 1, 'a'), header + "0|{00000000-0000-0000-0000-000000000000}|off|skip|-", header + "0|" + guid + "|off|set|1.2.3.4,1.2.3.4", header + "0|" + guid + "|off|set|1.2.3.4;calc", header + "0|" + guid + "|off|set|\xC3\xA9"};
  std::string maximum = header;
  for (unsigned i = 0; i < 256; ++i) {
    char suffix[13]; std::snprintf(suffix, sizeof(suffix), "%012x", i + 1);
    maximum += std::to_string(i) + "|{11111111-2222-3333-4444-" + suffix + "}|skip|noop|-\n";
  }
  require(parse(maximum).size() == 256);
  bad.push_back(maximum + "256|{11111111-2222-3333-4444-ffffffffffff}|skip|noop|-\n");
  for (const auto& test : bad) { bool rejected = false; try { parse(test); } catch (const Failure&) { rejected = true; } require(rejected); }
  std::cout << "SELF_TEST_PASS parser_cases=" << bad.size() + 3 << " restore_fault_cases=" << restoreSelfTest() << '\n'; return 0;
}
}
int main(int argc, char** argv) {
  try {
    require(argc == 2); const std::string mode = argv[1];
    if (mode == "--self-test") return selfTest();
    require(mode == "--batch" || mode == "--inspect" || mode == "--restore");
    std::string input; char block[4096]; while (std::cin.read(block, sizeof(block)) || std::cin.gcount()) { input.append(block, size_t(std::cin.gcount())); require(input.size() <= MAX_INPUT); }
    require(std::cin.eof()); const auto rows = parse(input);
    return mode == "--restore" ? restore(rows) : execute(rows, mode == "--inspect");
  } catch (const Failure& e) { std::cout << "NATIVE_BATCH_err: native code=" << e.code << '\n'; return 2; }
  catch (...) { std::cout << "NATIVE_BATCH_err: native code=" << ERROR_UNHANDLED_EXCEPTION << '\n'; return 2; }
}
