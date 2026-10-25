// AT-03-006/007/010/011: opt-in integration fixture; never selects an existing NIC.
// Usage: benchmark.exe <worker.exe> <wintun.dll> <existing .tmp directory>
// --self-test exercises parsing, pipe transport and timeout settlement without a NIC.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <objbase.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cwctype>
#include <cstring>
#include <iostream>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using Clock = std::chrono::steady_clock;
constexpr DWORD WorkerTimeoutMs = 30000;
constexpr size_t OutputLimit = 65536;
std::atomic<bool> cancelled{false};

struct Failure : std::exception {
    DWORD code;
    explicit Failure(DWORD value) : code(value ? value : ERROR_INVALID_DATA) {}
};
void require(bool condition, DWORD code = ERROR_INVALID_DATA) { if (!condition) throw Failure(code); }
std::uint64_t elapsed(Clock::time_point start) {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count());
}

struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    Handle() = default;
    explicit Handle(HANDLE handle) : value(handle) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    ~Handle() { close(); }
    void close() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); value = INVALID_HANDLE_VALUE; }
};

// Every exit path settles the child before the caller can close the fixture NIC.
// Even a failed TerminateProcess must not let an in-flight native call race cleanup.
struct Child {
    Handle process;
    Handle thread;
    bool settled = false;
    void settle() noexcept {
        if (settled || process.value == INVALID_HANDLE_VALUE) return;
        if (WaitForSingleObject(process.value, 0) == WAIT_TIMEOUT) TerminateProcess(process.value, ERROR_TIMEOUT);
        // Never infer exit from a failed wait. Keeping this scope alive also
        // keeps its caller's adapter handle alive if OS settlement is delayed.
        while (WaitForSingleObject(process.value, INFINITE) != WAIT_OBJECT_0) Sleep(100);
        settled = true;
    }
    ~Child() { settle(); }
};

std::wstring fullPath(const std::wstring& path) {
    require(!path.empty() && path.find(L'\0') == std::wstring::npos);
    DWORD size = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    require(size != 0, GetLastError());
    std::vector<wchar_t> buffer(size);
    const DWORD written = GetFullPathNameW(path.c_str(), size, buffer.data(), nullptr);
    require(written != 0 && written < size, GetLastError());
    return std::wstring(buffer.data(), written);
}
std::wstring existingFile(const std::wstring& path) {
    auto result = fullPath(path);
    const DWORD attributes = GetFileAttributesW(result.c_str());
    require(attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY), ERROR_FILE_NOT_FOUND);
    return result;
}
std::wstring workDirectory(const std::wstring& path) {
    const auto absolute = fullPath(path);
    Handle directory(CreateFileW(absolute.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    require(directory.value != INVALID_HANDLE_VALUE, GetLastError());
    DWORD size = GetFinalPathNameByHandleW(directory.value, nullptr, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    require(size != 0, GetLastError());
    std::vector<wchar_t> buffer(static_cast<size_t>(size) + 1);
    const DWORD written = GetFinalPathNameByHandleW(directory.value, buffer.data(), static_cast<DWORD>(buffer.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    require(written != 0 && written < buffer.size(), GetLastError());
    std::wstring result(buffer.data(), written);
    std::wstring lower = result;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
    if (lower.back() != L'\\') lower += L'\\';
    require(lower.find(L"\\.tmp\\") != std::wstring::npos, ERROR_BAD_PATHNAME);
    if (result.back() != L'\\') result += L'\\';
    return result;
}

std::wstring quoteArgument(const std::wstring& value) {
    std::wstring output = L"\"";
    size_t slashes = 0;
    for (wchar_t c : value) {
        if (c == L'\\') { ++slashes; continue; }
        if (c == L'\"') { output.append(slashes * 2 + 1, L'\\'); output += c; }
        else { output.append(slashes, L'\\'); output += c; }
        slashes = 0;
    }
    output.append(slashes * 2, L'\\');
    return output + L'\"';
}

struct ChildResult {
    std::string output;
    DWORD exitCode = ERROR_GEN_FAILURE;
    std::uint64_t milliseconds = 0;
    bool timedOut = false;
    bool interrupted = false;
    bool overflow = false;
};

ChildResult runChild(const std::wstring& executable, const std::wstring& argument,
    const std::string& input, DWORD timeout = WorkerTimeoutMs) {
    const auto start = Clock::now();
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    Handle inputRead, inputWrite, outputRead, outputWrite;
    require(CreatePipe(&inputRead.value, &inputWrite.value, &security, 0) != FALSE, GetLastError());
    require(CreatePipe(&outputRead.value, &outputWrite.value, &security, 0) != FALSE, GetLastError());
    require(SetHandleInformation(inputWrite.value, HANDLE_FLAG_INHERIT, 0) != FALSE, GetLastError());
    require(SetHandleInformation(outputRead.value, HANDLE_FLAG_INHERIT, 0) != FALSE, GetLastError());
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = inputRead.value;
    startup.StartupInfo.hStdOutput = outputWrite.value;
    startup.StartupInfo.hStdError = outputWrite.value;
    SIZE_T attributeBytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeBytes);
    std::vector<unsigned char> attributes(attributeBytes);
    startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
    require(InitializeProcThreadAttributeList(startup.lpAttributeList, 1, 0, &attributeBytes) != FALSE, GetLastError());
    struct Attributes { LPPROC_THREAD_ATTRIBUTE_LIST value; ~Attributes() { DeleteProcThreadAttributeList(value); } } attributeGuard{startup.lpAttributeList};
    HANDLE inherited[]{inputRead.value, outputWrite.value};
    require(UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr, nullptr) != FALSE, GetLastError());
    std::wstring command = quoteArgument(executable) + L" " + quoteArgument(argument);
    PROCESS_INFORMATION process{};
    require(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &startup.StartupInfo, &process) != FALSE, GetLastError());
    Child child;
    child.process.value = process.hProcess;
    child.thread.value = process.hThread;
    inputRead.close();
    outputWrite.close();
    require(input.size() < 4096, ERROR_BUFFER_OVERFLOW);
    DWORD written = 0;
    require(WriteFile(inputWrite.value, input.data(), static_cast<DWORD>(input.size()), &written, nullptr) != FALSE && written == input.size(), GetLastError());
    inputWrite.close();
    ChildResult result;
    auto drain = [&]() {
        DWORD available = 0;
        while (PeekNamedPipe(outputRead.value, nullptr, 0, nullptr, &available, nullptr) && available) {
            char buffer[4096];
            DWORD received = 0;
            if (!ReadFile(outputRead.value, buffer, std::min<DWORD>(available, sizeof(buffer)), &received, nullptr) || !received) break;
            if (result.output.size() + received > OutputLimit) { result.overflow = true; break; }
            result.output.append(buffer, received);
        }
    };
    for (;;) {
        drain();
        const DWORD state = WaitForSingleObject(child.process.value, 10);
        if (state == WAIT_OBJECT_0) { child.settled = true; break; }
        require(state == WAIT_TIMEOUT, GetLastError());
        if (elapsed(start) >= timeout || cancelled.load() || result.overflow) {
            result.timedOut = elapsed(start) >= timeout;
            result.interrupted = cancelled.load();
            child.settle(); // No reply is treated as unknown, even after process termination.
            break;
        }
    }
    drain();
    require(GetExitCodeProcess(child.process.value, &result.exitCode) != FALSE, GetLastError());
    result.milliseconds = elapsed(start);
    return result;
}

std::vector<std::string> dnsList(const std::string& value) {
    if (value == "none") return {};
    require(!value.empty());
    std::vector<std::string> addresses;
    size_t start = 0;
    for (;;) {
        const size_t end = value.find(',', start);
        const auto address = value.substr(start, end == std::string::npos ? end : end - start);
        IN_ADDR parsed{};
        char canonical[INET_ADDRSTRLEN]{};
        require(InetPtonA(AF_INET, address.c_str(), &parsed) == 1);
        require(InetNtopA(AF_INET, &parsed, canonical, sizeof(canonical)) != nullptr);
        require(address == canonical && std::find(addresses.begin(), addresses.end(), address) == addresses.end());
        addresses.push_back(address);
        require(addresses.size() <= 16);
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return addresses;
}
struct Snapshot { bool ipv6 = false; std::vector<std::string> dns; };
bool timingLine(const std::string& line, std::set<std::string>& timings) {
    if (line.rfind("NATIVE_TIMING phase=", 0) != 0) return false;
    constexpr size_t prefix = sizeof("NATIVE_TIMING phase=") - 1;
    const std::string marker = " durationMs=";
    const size_t separator = line.find(marker, prefix);
    require(separator != std::string::npos);
    const auto phase = line.substr(prefix, separator - prefix);
    require(phase == "preflight" || phase == "binding-apply" || phase == "binding-readback" ||
        phase == "dns-apply-readback" || phase == "restore-ipv6" || phase == "restore-dns" || phase == "total");
    const auto value = line.substr(separator + marker.size());
    require(!value.empty() && value.size() <= 20 && std::all_of(value.begin(), value.end(), [](char c) { return c >= '0' && c <= '9'; }));
    require(timings.insert(phase).second);
    return true;
}
Snapshot parseSnapshot(const std::string& output) {
    Snapshot snapshot;
    bool ipv6Seen = false, dnsSeen = false;
    std::set<std::string> timings;
    std::istringstream stream(output);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        if (line == "A0_ipv6:enabled" || line == "A0_ipv6:disabled") {
            require(!ipv6Seen); ipv6Seen = true; snapshot.ipv6 = line == "A0_ipv6:enabled";
        } else if (line.rfind("A0_dns:", 0) == 0) {
            require(!dnsSeen); dnsSeen = true; snapshot.dns = dnsList(line.substr(7));
        } else require(timingLine(line, timings));
    }
    require(ipv6Seen && dnsSeen);
    return snapshot;
}
bool numericError(const std::string& value, const std::string& prefix) {
    if (value.rfind(prefix, 0) != 0) return false;
    const auto code = value.substr(prefix.size());
    require(!code.empty() && code.size() <= 10 && std::all_of(code.begin(), code.end(), [](char c) { return c >= '0' && c <= '9'; }) &&
        std::any_of(code.begin(), code.end(), [](char c) { return c != '0'; }));
    return true;
}
void verifyMissingInspectReceipt(const std::string& output) {
    bool ipv6Error = false, dnsError = false;
    std::set<std::string> timings;
    std::istringstream stream(output);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        if (numericError(line, "A0_ipv6_err: native code=")) { require(!ipv6Error); ipv6Error = true; }
        else if (numericError(line, "A0_dns_err: native code=")) { require(!dnsError); dnsError = true; }
        else require(timingLine(line, timings));
    }
    require(ipv6Error && dnsError);
}
void verifyPartialRestoreReceipt(const std::string& output) {
    bool missingIpv6 = false, missingDns = false, restoredIpv6 = false, restoredDns = false;
    std::set<std::string> timings;
    std::istringstream stream(output);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        if (numericError(line, "A0_ipv6_err: native code=")) { require(!missingIpv6); missingIpv6 = true; }
        else if (numericError(line, "A0_dns_err: native code=")) { require(!missingDns); missingDns = true; }
        else if (line == "A1_ipv6:on") { require(!restoredIpv6); restoredIpv6 = true; }
        else if (line == "A1_dns:reset") { require(!restoredDns); restoredDns = true; }
        else require(timingLine(line, timings));
    }
    require(missingIpv6 && missingDns && restoredIpv6 && restoredDns);
}
std::string joinDns(const std::vector<std::string>& addresses) {
    std::string result;
    for (const auto& address : addresses) { if (!result.empty()) result += ','; result += address; }
    return result;
}
std::string guidText(const GUID& guid) {
    wchar_t text[40]{};
    require(StringFromGUID2(guid, text, 40) == 39);
    std::string result;
    for (const wchar_t* p = text; *p; ++p) result += static_cast<char>(*p);
    return result;
}
std::string request(const GUID& guid, const std::string& ipv6, const std::string& dns, const std::string& servers) {
    return "VPNTE_LOCKDOWN_V1\n0|" + guidText(guid) + '|' + ipv6 + '|' + dns + '|' + servers + "\n";
}
bool tableContainsGuid(const MIB_IF_TABLE2& table, const GUID& guid) {
    for (ULONG i = 0; i < table.NumEntries; ++i) if (IsEqualGUID(table.Table[i].InterfaceGuid, guid)) return true;
    return false;
}
void assertGuidAbsent(const GUID& guid) {
    PMIB_IF_TABLE2 table = nullptr;
    const DWORD listed = GetIfTable2(&table);
    require(listed == NO_ERROR && table, listed);
    struct Table { PMIB_IF_TABLE2 value; ~Table() { FreeMibTable(value); } } tableGuard{table};
    require(!tableContainsGuid(*table, guid), ERROR_ALREADY_EXISTS);
}
GUID absentGuid() {
    GUID result{};
    require(SUCCEEDED(CoCreateGuid(&result)), ERROR_GEN_FAILURE);
    assertGuidAbsent(result);
    // The complete current interface table is authoritative here. The exact
    // ConvertInterfaceGuidToLuid error for a missing GUID varies by Windows.
    // The caller additionally requires --inspect to reject this identity.
    return result;
}
int absenceProbe() {
    GUID guid{};
    require(SUCCEEDED(CoCreateGuid(&guid)), ERROR_GEN_FAILURE);
    assertGuidAbsent(guid);
    NET_LUID luid{};
    const DWORD code = ConvertInterfaceGuidToLuid(&guid, &luid);
    std::cout << "{\"table_absent\":1,\"convert_code\":" << code << ",\"luid_zero\":" << (luid.Value == 0) << "}\n";
    return 0;
}

std::vector<std::string> defaultRoutes(const NET_LUID* forbidden = nullptr) {
    PMIB_IPFORWARD_TABLE2 table = nullptr;
    const DWORD code = GetIpForwardTable2(AF_UNSPEC, &table);
    require(code == NO_ERROR && table, code);
    struct Table { PMIB_IPFORWARD_TABLE2 value; ~Table() { FreeMibTable(value); } } tableGuard{table};
    std::vector<std::string> routes;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const auto& row = table->Table[i];
        if (row.DestinationPrefix.PrefixLength != 0) continue;
        require(!forbidden || row.InterfaceLuid.Value != forbidden->Value, ERROR_NETWORK_ACCESS_DENIED);
        std::ostringstream key;
        key << row.InterfaceLuid.Value << ':' << row.DestinationPrefix.Prefix.si_family << ':' << row.Metric << ':' << row.Protocol << ':';
        if (row.NextHop.si_family == AF_INET) key << row.NextHop.Ipv4.sin_addr.S_un.S_addr;
        else if (row.NextHop.si_family == AF_INET6) {
            for (unsigned char value : row.NextHop.Ipv6.sin6_addr.u.Byte) key << static_cast<unsigned>(value) << ',';
            key << row.NextHop.Ipv6.sin6_scope_id;
        } else throw Failure(ERROR_INVALID_DATA);
        routes.push_back(key.str());
    }
    std::sort(routes.begin(), routes.end());
    return routes;
}

using CreateAdapter = void* (WINAPI*)(LPCWSTR, LPCWSTR, const GUID*);
using CloseAdapter = void (WINAPI*)(void*);
using GetAdapterLuid = void (WINAPI*)(void*, NET_LUID*);
template<typename T> T symbol(HMODULE module, const char* name) {
    const auto address = GetProcAddress(module, name);
    require(address != nullptr, ERROR_PROC_NOT_FOUND);
    static_assert(sizeof(T) == sizeof(address), "function pointer ABI");
    T result{};
    std::memcpy(&result, &address, sizeof(result));
    return result;
}
struct Fixture {
    HMODULE library = nullptr;
    void* adapter = nullptr;
    CreateAdapter createAdapter = nullptr;
    CloseAdapter closeAdapter = nullptr;
    GetAdapterLuid getAdapterLuid = nullptr;
    NET_LUID luid{};
    GUID guid{};
    explicit Fixture(const std::wstring& path) {
        // An explicit absolute DLL; dependencies resolve only from System32.
        library = LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        require(library != nullptr, GetLastError());
        try {
            createAdapter = symbol<CreateAdapter>(library, "WintunCreateAdapter");
            closeAdapter = symbol<CloseAdapter>(library, "WintunCloseAdapter");
            getAdapterLuid = symbol<GetAdapterLuid>(library, "WintunGetAdapterLUID");
        } catch (...) { FreeLibrary(library); library = nullptr; throw; }
    }
    ~Fixture() { close(); if (library) FreeLibrary(library); }
    void create() {
        GUID random{};
        require(SUCCEEDED(CoCreateGuid(&random)), ERROR_GEN_FAILURE);
        const auto token = guidText(random);
        std::wstring name = L"VTEBench";
        for (char c : token) if (c != '{' && c != '}' && c != '-') name += static_cast<wchar_t>(c);
        // Never OpenAdapter: only the handle returned by this CreateAdapter can be mutated.
        adapter = createAdapter(name.c_str(), L"VPNTE Benchmark", nullptr);
        require(adapter != nullptr, GetLastError());
        getAdapterLuid(adapter, &luid);
        require(luid.Value != 0);
        const DWORD code = ConvertInterfaceLuidToGuid(&luid, &guid);
        require(code == NO_ERROR, code);
    }
    void assertSafe(const std::vector<std::string>& baselineRoutes) const {
        require(adapter != nullptr && !cancelled.load(), ERROR_CANCELLED);
        NET_LUID current{};
        const DWORD code = ConvertInterfaceGuidToLuid(&guid, &current);
        require(code == NO_ERROR && current.Value == luid.Value, code);
        require(defaultRoutes(&luid) == baselineRoutes, ERROR_NETWORK_ACCESS_DENIED);
    }
    void close() { if (adapter) { closeAdapter(adapter); adapter = nullptr; } }
    bool removed() const {
        const auto start = Clock::now();
        do {
            PMIB_IF_TABLE2 table = nullptr;
            const DWORD code = GetIfTable2(&table);
            if (code != NO_ERROR || !table) return false;
            bool present = false;
            for (ULONG i = 0; i < table->NumEntries; ++i) if (table->Table[i].InterfaceLuid.Value == luid.Value) present = true;
            FreeMibTable(table);
            if (!present) return true;
            Sleep(25);
        } while (elapsed(start) < 5000);
        return false;
    }
};

struct BaselineFile {
    std::wstring path;
    ~BaselineFile() { remove(); }
    bool remove() {
        if (path.empty()) return true;
        if (!DeleteFileW(path.c_str())) return false;
        path.clear();
        return true;
    }
    void save(const std::wstring& directory, const GUID& guid, const std::string& data) {
        std::wstring token;
        for (char c : guidText(guid)) if (c != '{' && c != '}' && c != '-') token += static_cast<wchar_t>(c);
        const auto candidate = directory + L"adapter-lockdown-" + token + L".baseline";
        Handle file(CreateFileW(candidate.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY, nullptr));
        require(file.value != INVALID_HANDLE_VALUE, GetLastError());
        path = candidate; // Only a successfully created, task-owned file is ever removed.
        DWORD written = 0;
        require(WriteFile(file.value, data.data(), static_cast<DWORD>(data.size()), &written, nullptr) != FALSE && written == data.size(), GetLastError());
        require(FlushFileBuffers(file.value) != FALSE, GetLastError());
    }
};
struct Report {
    std::uint64_t createMs = 0, readMs = 0, applyMs = 0, appliedReadMs = 0, restoreMs = 0, restoredReadMs = 0, removeMs = 0, totalMs = 0;
    std::uint64_t independentRestoreMs = 0, staticRestoreMs = 0, finalResetMs = 0, regressionSetupMs = 0, missingInspectMs = 0;
    bool success = false, baselineSaved = false, applyVerified = false, restoreVerified = false, removed = false, routesUnchanged = false, unknown = false;
    bool independentRestoreVerified = false, staticRestoreVerified = false, finalResetVerified = false, missingInspectVerified = false;
    DWORD error = 0;
    unsigned stage = 0;
    void print() const {
        // No paths, adapter identifiers, addresses or native stderr leave the fixture.
        std::cout << "{\"success\":" << success << ",\"baseline_saved\":" << baselineSaved
            << ",\"apply_verified\":" << applyVerified << ",\"restore_verified\":" << restoreVerified
            << ",\"independent_restore_verified\":" << independentRestoreVerified << ",\"static_restore_verified\":" << staticRestoreVerified
            << ",\"final_reset_verified\":" << finalResetVerified
            << ",\"missing_inspection_verified\":" << missingInspectVerified
            << ",\"fixture_removed_verified\":" << removed << ",\"uplink_routes_unchanged\":" << routesUnchanged
            << ",\"outcome_unknown\":" << unknown << ",\"error_code\":" << error << ",\"stage\":" << stage
            << ",\"fixture_create_ms\":" << createMs << ",\"baseline_read_ms\":" << readMs
            << ",\"apply_ms\":" << applyMs << ",\"apply_readback_ms\":" << appliedReadMs
            << ",\"restore_ms\":" << restoreMs << ",\"restore_readback_ms\":" << restoredReadMs
            << ",\"independent_restore_ms\":" << independentRestoreMs << ",\"static_restore_ms\":" << staticRestoreMs
            << ",\"final_reset_ms\":" << finalResetMs << ",\"regression_setup_ms\":" << regressionSetupMs
            << ",\"missing_inspection_ms\":" << missingInspectMs
            << ",\"fixture_remove_ms\":" << removeMs << ",\"total_ms\":" << totalMs << "}\n";
    }
};

void checkChild(const ChildResult& result, Report& report, DWORD expectedExit = 0) {
    if (result.timedOut || result.interrupted) { report.unknown = true; throw Failure(result.timedOut ? ERROR_TIMEOUT : ERROR_CANCELLED); }
    if (result.overflow) { report.unknown = true; throw Failure(ERROR_BUFFER_OVERFLOW); }
    require(result.exitCode == expectedExit, result.exitCode);
}

BOOL WINAPI controlHandler(DWORD control) {
    if (control == CTRL_C_EVENT || control == CTRL_BREAK_EVENT || control == CTRL_CLOSE_EVENT || control == CTRL_LOGOFF_EVENT || control == CTRL_SHUTDOWN_EVENT) {
        cancelled.store(true); return TRUE;
    }
    return FALSE;
}

int benchmark(const std::wstring& worker, const std::wstring& dll, const std::wstring& work) {
    Report report;
    const auto start = Clock::now();
    std::unique_ptr<Fixture> fixture;
    BaselineFile baselineFile;
    Snapshot baseline;
    bool mutationStarted = false, restoreAttempted = false;
    std::vector<std::string> routes;
    auto restore = [&]() {
        restoreAttempted = true;
        report.stage = 6;
        fixture->assertSafe(routes); // Checked immediately before every mutating dispatch.
        const auto restored = runChild(worker, L"--restore", request(fixture->guid, baseline.ipv6 ? "on" : "off",
            baseline.dns.empty() ? "reset" : "restore", baseline.dns.empty() ? "-" : joinDns(baseline.dns)));
        report.restoreMs = restored.milliseconds;
        checkChild(restored, report);
        report.stage = 7;
        const auto read = runChild(worker, L"--inspect", request(fixture->guid, "noop", "noop", "-"));
        report.restoredReadMs = read.milliseconds;
        checkChild(read, report);
        const auto snapshot = parseSnapshot(read.output);
        report.restoreVerified = snapshot.ipv6 == baseline.ipv6 && snapshot.dns == baseline.dns;
        require(report.restoreVerified);
    };
    try {
        report.stage = 1;
        routes = defaultRoutes();
        fixture = std::make_unique<Fixture>(dll);
        const auto creating = Clock::now();
        fixture->create(); // No Wintun session, IP address, or route is created.
        report.createMs = elapsed(creating);
        fixture->assertSafe(routes);
        report.stage = 2;
        const auto read = runChild(worker, L"--inspect", request(fixture->guid, "noop", "noop", "-"));
        report.readMs = read.milliseconds;
        checkChild(read, report);
        baseline = parseSnapshot(read.output);
        // This measures a real enabled->disabled transition and a clean DNS
        // override/reset. Unexpected inherited configuration is never changed.
        require(baseline.ipv6 && baseline.dns.empty(), ERROR_NOT_SUPPORTED);
        baselineFile.save(work, fixture->guid, read.output);
        report.baselineSaved = true;
        report.stage = 3;
        fixture->assertSafe(routes);
        mutationStarted = true;
        const auto applied = runChild(worker, L"--batch", request(fixture->guid, "off", "set", "192.0.2.53"));
        report.applyMs = applied.milliseconds;
        checkChild(applied, report);
        report.stage = 4;
        const auto reread = runChild(worker, L"--inspect", request(fixture->guid, "noop", "noop", "-"));
        report.appliedReadMs = reread.milliseconds;
        checkChild(reread, report);
        const auto snapshot = parseSnapshot(reread.output);
        report.applyVerified = !snapshot.ipv6 && snapshot.dns == std::vector<std::string>{"192.0.2.53"};
        require(report.applyVerified);
        restore();

        // Regression: one vanished NIC must not prevent the live fixture's
        // independent IPv6 and DNS rollback. Only this created NIC can exist.
        auto inspectExpected = [&](bool ipv6, const std::vector<std::string>& dns) {
            const auto inspection = runChild(worker, L"--inspect", request(fixture->guid, "noop", "noop", "-"));
            checkChild(inspection, report);
            const auto actual = parseSnapshot(inspection.output);
            require(actual.ipv6 == ipv6 && actual.dns == dns);
        };
        auto setup = [&](const std::string& ipv6, const std::vector<std::string>& dns) {
            restoreAttempted = false;
            fixture->assertSafe(routes);
            const auto written = runChild(worker, L"--batch", request(fixture->guid, ipv6, "set", joinDns(dns)));
            report.regressionSetupMs += written.milliseconds;
            checkChild(written, report);
        };
        report.stage = 9;
        setup("off", {"192.0.2.53"});
        inspectExpected(false, {"192.0.2.53"});
        const GUID missing = absentGuid();
        const auto missingRead = runChild(worker, L"--inspect", request(missing, "noop", "noop", "-"));
        report.missingInspectMs = missingRead.milliseconds;
        checkChild(missingRead, report, 1);
        verifyMissingInspectReceipt(missingRead.output);
        report.missingInspectVerified = true;
        assertGuidAbsent(missing); // Repeat immediately before the mutating batch.
        fixture->assertSafe(routes);
        const auto partialInput = "VPNTE_LOCKDOWN_V1\n0|" + guidText(missing) + "|on|reset|-\n1|" + guidText(fixture->guid) + "|on|reset|-\n";
        const auto partial = runChild(worker, L"--restore", partialInput);
        report.independentRestoreMs = partial.milliseconds;
        checkChild(partial, report, 1); // The missing row must fail, the live row must succeed.
        verifyPartialRestoreReceipt(partial.output);
        inspectExpected(baseline.ipv6, baseline.dns);
        report.independentRestoreVerified = true;

        // A real two-server static baseline is installed, inspected, overwritten,
        // and restored in order before a separate final DHCP/configuration reset.
        report.stage = 10;
        const std::vector<std::string> staticDns{"192.0.2.54", "192.0.2.55"};
        setup("noop", staticDns);
        inspectExpected(baseline.ipv6, staticDns);
        setup("noop", {"192.0.2.53"});
        inspectExpected(baseline.ipv6, {"192.0.2.53"});
        report.stage = 11;
        fixture->assertSafe(routes);
        const auto staticRestored = runChild(worker, L"--restore", request(fixture->guid, "noop", "restore", joinDns(staticDns)));
        report.staticRestoreMs = staticRestored.milliseconds;
        checkChild(staticRestored, report);
        inspectExpected(baseline.ipv6, staticDns);
        report.staticRestoreVerified = true;
        report.stage = 12;
        restoreAttempted = true;
        fixture->assertSafe(routes);
        const auto finalReset = runChild(worker, L"--restore", request(fixture->guid, "on", "reset", "-"));
        report.finalResetMs = finalReset.milliseconds;
        checkChild(finalReset, report);
        inspectExpected(baseline.ipv6, baseline.dns);
        report.finalResetVerified = true;
        report.success = true;
    } catch (const Failure& error) { report.error = error.code; }
    catch (...) { report.error = ERROR_UNHANDLED_EXCEPTION; }
    // A normal partial failure still restores the saved state. An absent reply is
    // never replayed: runChild already settled that process, then we remove this
    // disposable NIC instead of racing another mutation against an unknown result.
    if (fixture && mutationStarted && report.baselineSaved && !restoreAttempted && !report.unknown && !cancelled.load()) {
        const unsigned failedStage = report.stage;
        try { restore(); }
        catch (const Failure& error) { if (!report.error) report.error = error.code; }
        catch (...) { if (!report.error) report.error = ERROR_UNHANDLED_EXCEPTION; }
        report.stage = failedStage;
    }
    if (fixture) {
        const auto removing = Clock::now();
        fixture->close(); // All worker children have exited before this point.
        report.removed = fixture->luid.Value != 0 && fixture->removed();
        report.removeMs = elapsed(removing);
    }
    try { report.routesUnchanged = defaultRoutes() == routes; } catch (...) { report.routesUnchanged = false; }
    if (!report.removed || !report.routesUnchanged) { report.success = false; if (!report.error) report.error = ERROR_NETWORK_ACCESS_DENIED; }
    if (!baselineFile.remove()) { report.success = false; if (!report.error) report.error = GetLastError(); }
    if (report.error || report.unknown) report.success = false;
    if (report.success) report.stage = 8;
    report.totalMs = elapsed(start);
    report.print();
    return report.success ? 0 : 1;
}

int selfTest(const std::wstring& executable) {
    unsigned passed = 0;
    auto test = [&](bool value) { require(value); ++passed; };
    const auto valid = parseSnapshot("A0_ipv6:enabled\r\nA0_dns:192.0.2.1,192.0.2.2\r\n");
    test(valid.ipv6 && valid.dns == std::vector<std::string>{"192.0.2.1", "192.0.2.2"});
    test(!parseSnapshot("A0_dns:none\nA0_ipv6:disabled\n").ipv6);
    test(parseSnapshot("NATIVE_TIMING phase=preflight durationMs=0\nNATIVE_TIMING phase=binding-readback durationMs=1\nA0_ipv6:enabled\nA0_dns:none\nNATIVE_TIMING phase=dns-apply-readback durationMs=2\nNATIVE_TIMING phase=total durationMs=3\n").ipv6);
    for (const auto& invalid : {"A0_ipv6:enabled\n", "A0_ipv6:enabled\nA0_ipv6:disabled\nA0_dns:none\n",
        "A1_ipv6:enabled\nA0_dns:none\n", "A0_ipv6:enabled\nA0_dns:192.0.2.01\n",
        "A0_ipv6:enabled\nA0_dns:192.0.2.1,192.0.2.1\n", "A0_ipv6:enabled\nA0_dns:192.0.2.1|on\n",
        "A0_ipv6:enabled\nA0_dns:none\nERROR:unexpected\n",
        "A0_ipv6:enabled\nA0_dns:none\nNATIVE_TIMING phase=unknown durationMs=1\n",
        "A0_ipv6:enabled\nA0_dns:none\nNATIVE_TIMING phase=total durationMs=-1\n",
        "A0_ipv6:enabled\nA0_dns:none\nNATIVE_TIMING phase=total durationMs=1 private\n",
        "A0_ipv6:enabled\nA0_dns:none\nNATIVE_TIMING phase=total durationMs=1\nNATIVE_TIMING phase=total durationMs=2\n"}) {
        bool refused = false; try { parseSnapshot(invalid); } catch (const Failure&) { refused = true; } test(refused);
    }
    test(quoteArgument(L"C:\\with space\\") == L"\"C:\\with space\\\\\"");
    const auto quick = runChild(executable, L"--self-test-child", "fixture-input\n", 5000);
    test(!quick.timedOut && quick.exitCode == 0 && parseSnapshot(quick.output).dns.empty());
    const auto timeout = runChild(executable, L"--self-test-child-wait", "fixture-input\n", 50);
    test(timeout.timedOut && timeout.exitCode != STILL_ACTIVE);
    const auto overflow = runChild(executable, L"--self-test-child-overflow", "fixture-input\n", 5000);
    test(overflow.overflow && overflow.exitCode != STILL_ACTIVE);
    Report unknown;
    bool refused = false; try { checkChild(timeout, unknown); } catch (const Failure&) { refused = true; }
    test(refused && unknown.unknown);
    verifyPartialRestoreReceipt("A0_ipv6_err: native code=1168\nA0_dns_err: native code=1168\nA1_ipv6:on\nA1_dns:reset\nNATIVE_TIMING phase=restore-ipv6 durationMs=1\nNATIVE_TIMING phase=restore-dns durationMs=2\nNATIVE_TIMING phase=total durationMs=3\n");
    test(true);
    for (const auto& invalid : {
        "A0_ipv6_err: native code=1168\nA0_dns_err: native code=1168\nA1_ipv6:on\n",
        "A0_ipv6_err: native code=1168\nA0_dns_err: native code=1168\nA1_ipv6:on\nA1_dns:restore\n",
        "A0_ipv6_err: native code=0\nA0_dns_err: native code=1168\nA1_ipv6:on\nA1_dns:reset\n",
        "A0_ipv6_err: native code=1168\nA0_dns_err: native code=1168\nA1_ipv6:on\nA1_dns:reset\nA2_dns:reset\n"}) {
        bool rejected = false; try { verifyPartialRestoreReceipt(invalid); } catch (const Failure&) { rejected = true; } test(rejected);
    }
    ChildResult expectedFailure;
    expectedFailure.exitCode = 1;
    Report verifiedPartial;
    checkChild(expectedFailure, verifiedPartial, 1);
    test(!verifiedPartial.unknown);
    verifyMissingInspectReceipt("A0_ipv6_err: native code=87\nA0_dns_err: native code=87\nNATIVE_TIMING phase=total durationMs=0\n");
    test(true);
    for (const auto& invalid : {
        "A0_ipv6:enabled\nA0_dns:none\n",
        "A0_ipv6_err: native code=87\n",
        "A0_ipv6_err: native code=87\nA0_dns_err: native code=87\nA0_dns_err: native code=87\n",
        "NATIVE_BATCH_err: native code=13\n"}) {
        bool rejected = false; try { verifyMissingInspectReceipt(invalid); } catch (const Failure&) { rejected = true; } test(rejected);
    }
    MIB_IF_TABLE2 interfaceTable{};
    GUID present{}, absent{};
    present.Data1 = 1; absent.Data1 = 2;
    test(!tableContainsGuid(interfaceTable, present));
    interfaceTable.NumEntries = 1;
    interfaceTable.Table[0].InterfaceGuid = present;
    test(tableContainsGuid(interfaceTable, present));
    test(!tableContainsGuid(interfaceTable, absent));
    std::cout << "{\"tests_passed\":" << passed << ",\"success\":1}\n";
    return 0;
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 2 && std::wstring(argv[1]) == L"--self-test-child") {
            std::string input; std::getline(std::cin, input);
            require(input == "fixture-input");
            std::cout << "A0_ipv6:enabled\nA0_dns:none\n"; return 0;
        }
        if (argc == 2 && std::wstring(argv[1]) == L"--self-test-child-wait") { Sleep(3000); return 0; }
        if (argc == 2 && std::wstring(argv[1]) == L"--self-test-child-overflow") {
            std::string input; std::getline(std::cin, input);
            require(input == "fixture-input");
            std::cout << std::string(OutputLimit * 2, 'x'); return 0;
        }
        if (argc == 2 && std::wstring(argv[1]) == L"--self-test") return selfTest(existingFile(argv[0]));
        if (argc == 2 && std::wstring(argv[1]) == L"--probe-absence") return absenceProbe();
        require(argc == 4, ERROR_BAD_ARGUMENTS);
        const auto worker = existingFile(argv[1]);
        const auto dll = existingFile(argv[2]);
        const auto work = workDirectory(argv[3]);
        require(SetConsoleCtrlHandler(controlHandler, TRUE) != FALSE, GetLastError());
        return benchmark(worker, dll, work);
    } catch (const Failure& error) {
        std::cout << "{\"success\":0,\"error_code\":" << error.code << ",\"stage\":0}\n"; return 1;
    } catch (...) {
        std::cout << "{\"success\":0,\"error_code\":" << ERROR_UNHANDLED_EXCEPTION << ",\"stage\":0}\n"; return 1;
    }
}
