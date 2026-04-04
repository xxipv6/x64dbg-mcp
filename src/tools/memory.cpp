#include "common.h"

using namespace tools;

// ---------------------------------------------------------------------------
// Tool: mem_read
// ---------------------------------------------------------------------------

static nlohmann::json HandleMemRead(const nlohmann::json& params)
{
    nlohmann::json result;
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        size_t size = params.at("size").get<size_t>();
        duint addr = ParseHexAddress(addrStr);
        std::vector<unsigned char> buffer(size, 0);
        bool ok = DbgMemRead(addr, buffer.data(), static_cast<duint>(size));
        result["success"] = ok;
        result["address"] = addrStr;
        result["size"] = size;
        if (ok)
        {
            result["data"] = BytesToHex(buffer.data(), size);
            result["ascii"] = BytesToAscii(buffer.data(), size);
        }
    }
    catch (const std::exception& e)
    {
        result["success"] = false;
        result["error"] = std::string("mem_read: ") + e.what();
    }
    return result;
}

// ---------------------------------------------------------------------------
// Tool: mem_write
// ---------------------------------------------------------------------------

static nlohmann::json HandleMemWrite(const nlohmann::json& params)
{
    nlohmann::json result;
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        std::string hexData = params.at("data").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        std::vector<unsigned char> bytes = ParseHexBytes(hexData);
        if (bytes.empty())
            return {{"success", false}, {"error", "No valid hex bytes"}};
        bool ok = DbgMemWrite(addr, bytes.data(), static_cast<duint>(bytes.size()));
        result["success"] = ok;
        result["address"] = addrStr;
        result["bytes_written"] = bytes.size();
    }
    catch (const std::exception& e)
    {
        result["success"] = false;
        result["error"] = std::string("mem_write: ") + e.what();
    }
    return result;
}

// ---------------------------------------------------------------------------
// Tool: mem_map
// ---------------------------------------------------------------------------

namespace {

constexpr size_t kDefaultMemMapLimit = 100;
constexpr const char* kDumpDir = ".\\plugins\\mcp_dump\\";

static nlohmann::json MemRegionToJson(const MEMPAGE& page)
{
    return {
        {"base", RegToHex((ULONG_PTR)page.mbi.BaseAddress)},
        {"allocation_base", RegToHex((ULONG_PTR)page.mbi.AllocationBase)},
        {"size", RegToHex(page.mbi.RegionSize)},
        {"state", page.mbi.State},
        {"protect", page.mbi.Protect},
        {"type", page.mbi.Type},
        {"info", std::string(page.info)}
    };
}

static bool ContainsInsensitive(const std::string& text, const std::string& needle)
{
    if (needle.empty())
        return true;

    auto lowerText = text;
    auto lowerNeedle = needle;
    std::transform(lowerText.begin(), lowerText.end(), lowerText.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::transform(lowerNeedle.begin(), lowerNeedle.end(), lowerNeedle.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return lowerText.find(lowerNeedle) != std::string::npos;
}

} // namespace

static nlohmann::json HandleMemMap(const nlohmann::json& params)
{
    MEMMAP memmap = {};
    bool ok = DbgMemMap(&memmap);
    nlohmann::json result;
    result["success"] = ok;
    if (!ok)
        return result;

    size_t offset = params.value("offset", static_cast<size_t>(0));
    size_t limit = params.value("limit", kDefaultMemMapLimit);
    bool all = params.value("all", false);
    std::string infoContains = params.value("info_contains", std::string());
    std::string baseEquals = params.value("base", std::string());
    int stateFilter = params.value("state", -1);
    int protectFilter = params.value("protect", -1);
    int typeFilter = params.value("type", -1);

    auto matched = nlohmann::json::array();
    size_t matchedCount = 0;
    size_t skipped = 0;

    for (int i = 0; i < memmap.count; ++i)
    {
        auto& page = memmap.page[i];
        auto base = RegToHex((ULONG_PTR)page.mbi.BaseAddress);
        auto info = std::string(page.info);

        if (!baseEquals.empty() && _stricmp(base.c_str(), baseEquals.c_str()) != 0)
            continue;
        if (stateFilter >= 0 && static_cast<int>(page.mbi.State) != stateFilter)
            continue;
        if (protectFilter >= 0 && static_cast<int>(page.mbi.Protect) != protectFilter)
            continue;
        if (typeFilter >= 0 && static_cast<int>(page.mbi.Type) != typeFilter)
            continue;
        if (!ContainsInsensitive(info, infoContains))
            continue;

        ++matchedCount;
        if (skipped < offset)
        {
            ++skipped;
            continue;
        }
        if (!all && matched.size() >= limit)
            continue;

        matched.push_back(MemRegionToJson(page));
    }

    result["count"] = memmap.count;
    result["matched_count"] = matchedCount;
    result["offset"] = offset;
    result["limit"] = all ? matchedCount : limit;
    result["truncated"] = !all && (offset + matched.size() < matchedCount);
    result["returned_count"] = matched.size();
    result["filters"] = {
        {"all", all},
        {"base", baseEquals},
        {"info_contains", infoContains},
        {"state", stateFilter >= 0 ? nlohmann::json(stateFilter) : nlohmann::json(nullptr)},
        {"protect", protectFilter >= 0 ? nlohmann::json(protectFilter) : nlohmann::json(nullptr)},
        {"type", typeFilter >= 0 ? nlohmann::json(typeFilter) : nlohmann::json(nullptr)}
    };
    result["regions"] = matched;
    return result;
}

// ---------------------------------------------------------------------------
// Tool: mem_find (byte pattern search)
// ---------------------------------------------------------------------------

static nlohmann::json HandleMemFind(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        duint startAddr = ParseHexAddress(addrStr);
        std::string pattern = params.at("pattern").get<std::string>();
        size_t maxResults = params.value("max_results", 100);
        size_t searchSize = params.value("size", 0x10000);

        struct PB { unsigned char value; bool wildcard; };
        std::vector<PB> pbs;
        std::istringstream iss(pattern);
        std::string tok;
        while (iss >> tok)
        {
            PB pb;
            if (tok == "??" || tok == "?") { pb.wildcard = true; pb.value = 0; }
            else { pb.wildcard = false; pb.value = static_cast<unsigned char>(std::stoul(tok, nullptr, 16)); }
            pbs.push_back(pb);
        }
        if (pbs.empty())
            return {{"success", false}, {"error", "Empty pattern"}};

        const size_t chunk = 0x1000;
        std::vector<unsigned char> buf(chunk);
        auto matches = nlohmann::json::array();
        size_t found = 0;

        for (size_t off = 0; off < searchSize && found < maxResults; off += chunk)
        {
            duint raddr = startAddr + off;
            size_t toRead = std::min(chunk, searchSize - off);
            if (!DbgMemRead(raddr, buf.data(), static_cast<duint>(toRead))) continue;
            for (size_t i = 0; i + pbs.size() <= toRead && found < maxResults; ++i)
            {
                bool match = true;
                for (size_t j = 0; j < pbs.size() && match; ++j)
                    if (!pbs[j].wildcard && buf[i + j] != pbs[j].value) match = false;
                if (match) { matches.push_back(RegToHex(raddr + i)); ++found; i += pbs.size() - 1; }
            }
        }
        return {{"success", true}, {"address", addrStr}, {"pattern", pattern},
                {"search_size", searchSize}, {"found", found}, {"matches", matches}};
    }
    catch (const std::exception& e)
    {
        return {{"success", false}, {"error", std::string("mem_find: ") + e.what()}};
    }
}

// ---------------------------------------------------------------------------
// Tool: str_search (string search)
// ---------------------------------------------------------------------------

static nlohmann::json HandleStrSearch(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        duint startAddr = ParseHexAddress(addrStr);
        std::string searchString = params.at("string").get<std::string>();
        bool wide = params.value("wide", false);
        size_t maxResults = params.value("max_results", 50);
        size_t searchSize = params.value("size", 0x100000);

        std::vector<unsigned char> pat;
        for (unsigned char c : searchString) { pat.push_back(c); if (wide) pat.push_back(0); }

        const size_t chunk = 0x1000;
        std::vector<unsigned char> buf(chunk);
        auto matches = nlohmann::json::array();
        size_t found = 0;

        for (size_t off = 0; off < searchSize && found < maxResults; off += chunk)
        {
            duint raddr = startAddr + off;
            size_t toRead = std::min(chunk, searchSize - off);
            if (!DbgMemRead(raddr, buf.data(), static_cast<duint>(toRead))) continue;
            for (size_t i = 0; i + pat.size() <= toRead && found < maxResults; ++i)
            {
                if (std::memcmp(buf.data() + i, pat.data(), pat.size()) == 0)
                {
                    size_t ctxStart = (i >= 16) ? i - 16 : 0;
                    size_t ctxEnd = std::min(i + pat.size() + 48, toRead);
                    nlohmann::json m;
                    m["address"] = RegToHex(raddr + i);
                    m["context_ascii"] = BytesToAscii(buf.data() + ctxStart, ctxEnd - ctxStart);
                    m["context_hex"] = BytesToHex(buf.data() + ctxStart, ctxEnd - ctxStart);
                    matches.push_back(m);
                    ++found; i += pat.size() - 1;
                }
            }
        }
        return {{"success", true}, {"address", addrStr}, {"string", searchString},
                {"wide", wide}, {"search_size", searchSize}, {"found", found}, {"matches", matches}};
    }
    catch (const std::exception& e)
    {
        return {{"success", false}, {"error", std::string("str_search: ") + e.what()}};
    }
}

// ---------------------------------------------------------------------------
// Tool: alloc_mem
// ---------------------------------------------------------------------------

static nlohmann::json HandleAllocMem(const nlohmann::json& params)
{
    try
    {
        size_t size = params.at("size").get<size_t>();
        std::ostringstream cmd;
        cmd << "alloc 0x" << std::hex << size;
        if (!DbgCmdExecDirect(cmd.str().c_str()))
            return {{"success", false}, {"error", "alloc command failed"}, {"size", size}};

        duint addr = DbgValFromString("$result");
        bool ok = (addr != 0);
        nlohmann::json r = {{"success", ok}, {"size", size}};
        if (ok)
            r["address"] = RegToHex(addr);
        else
            r["error"] = "alloc returned null";
        return r;
    }
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("alloc_mem: ") + e.what()}}; }
}

// ---------------------------------------------------------------------------
// Tool: free_mem
// ---------------------------------------------------------------------------

static nlohmann::json HandleFreeMem(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        return SimpleCmd(AddrCmd("free", addr));
    }
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("free_mem: ") + e.what()}}; }
}

// ---------------------------------------------------------------------------
// Tool: set_mem_protect
// ---------------------------------------------------------------------------

static nlohmann::json HandleSetMemProtect(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        size_t size = params.at("size").get<size_t>();
        std::string prot = params.at("protection").get<std::string>(); // e.g. "rwx"
        std::ostringstream cmd;
        cmd << "SetMemoryProtection 0x" << std::hex << addr << ", 0x" << size << ", \"" << prot << "\"";
        return SimpleCmd(cmd.str());
    }
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("set_mem_protect: ") + e.what()}}; }
}

// ---------------------------------------------------------------------------
// Tool: dump_mem
// ---------------------------------------------------------------------------

static nlohmann::json HandleDumpMem(const nlohmann::json& params)
{
    try
    {
        std::string addrStr = params.at("address").get<std::string>();
        duint addr = ParseHexAddress(addrStr);
        size_t size = params.at("size").get<size_t>();
        std::string path = params.at("path").get<std::string>();

        auto slash = path.find_last_of("\\/");
        std::string filename = (slash == std::string::npos) ? path : path.substr(slash + 1);
        if (filename.empty())
            return {{"success", false}, {"error", "Invalid output filename"}};

        std::error_code ec;
        if (!std::filesystem::create_directories(kDumpDir, ec) && ec)
            return {{"success", false}, {"error", "failed to create dump directory"}, {"directory", kDumpDir}};

        std::vector<unsigned char> buffer(size, 0);
        if (!DbgMemRead(addr, buffer.data(), static_cast<duint>(size)))
            return {{"success", false}, {"error", "failed to read memory"}, {"address", addrStr}, {"size", size}};

        std::string finalPath = std::string(kDumpDir) + filename;
        std::ofstream out(finalPath, std::ios::binary | std::ios::trunc);
        if (!out)
            return {{"success", false}, {"error", "failed to open output file"}, {"path", finalPath}};

        out.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        if (!out)
            return {{"success", false}, {"error", "failed to write output file"}, {"path", finalPath}};

        out.close();
        return {
            {"success", true},
            {"directory", kDumpDir},
            {"path", finalPath},
            {"size", size},
            {"file_size", std::filesystem::file_size(finalPath)}
        };
    }
    catch (const std::exception& e) { return {{"success", false}, {"error", std::string("dump_mem: ") + e.what()}}; }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void RegisterMemoryTools(ToolMap& tools)
{
    tools["mem_read"]        = HandleMemRead;
    tools["mem_write"]       = HandleMemWrite;
    tools["mem_map"]         = HandleMemMap;
    tools["mem_find"]        = HandleMemFind;
    tools["str_search"]      = HandleStrSearch;
    tools["alloc_mem"]       = HandleAllocMem;
    tools["free_mem"]        = HandleFreeMem;
    tools["set_mem_protect"] = HandleSetMemProtect;
    tools["dump_mem"]        = HandleDumpMem;
}
