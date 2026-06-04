// IRClient -- simple IRC client with Lua plugin support
// Copyright (C) 2026 JohnMarkusDoe1973
// SPDX-License-Identifier: GPL-3.0-or-later
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <cctype>
#include <cstring>
#include <ncurses.h>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdio>
#include <sys/socket.h>
#include <openssl/ssl.h> // May God save us all.
#include <openssl/err.h>
#include <openssl/evp.h>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <ctime>
extern "C" {
    #include <lua.h>
    #include <lauxlib.h>
    #include <lualib.h>
}
bool capNegotiating = false;
bool saslRequested = false;
bool saslDone = false;
bool sentCapEnd = false;
struct Connection {
    int sock = -1;
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    bool tls = false;
};
struct AuthConfig {
    std::string nick;
    std::string username;
    std::string realname;
    std::string password;
    std::string saslUsername;
    std::string saslPassword;
};
static std::string base64Encode(const std::string& input) {
    int outLen = 4 * ((int(input.size()) + 2) / 3);
    std::string out(outLen, '\0');
    int actual = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&out[0]),reinterpret_cast<const unsigned char*>(input.data()),(int)input.size());
    out.resize(actual);
    return out;
}
static std::string sha256Fingerprint(const unsigned char* data, int len) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdLen = 0;
    if (!EVP_Digest(data, len, md, &mdLen, EVP_sha256(), nullptr)) {
        return "";
    }
    std::string out;
    char buf[4];
    for (unsigned int i = 0; i < mdLen; ++i) {
        if (i > 0) out += ":";
        std::snprintf(buf, sizeof(buf), "%02X", md[i]);
        out += buf;
    }
    return out;
}
namespace fs = std::filesystem;
static fs::path configDir() {
    const char* xdg = std::getenv("XDG_CONFIG_HOME");
    if (xdg && *xdg) return fs::path(xdg) / "IRClient";
    const char* home = std::getenv("HOME");
    if (home && *home) return fs::path(home) / ".config" / "IRClient";
    return fs::path(".") / "IRClient";
}
static fs::path pluginDir() {
    return configDir() / "plugins";
}
static fs::path authPath() {
    return configDir() / "auth.conf";
}
static std::string trim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && std::isspace((unsigned char)s[start])) {
        start++;
    }
    size_t end = s.size();
    while (end > start && std::isspace((unsigned char)s[end - 1])) {
        end--;
    }
    return s.substr(start, end - start);
}
static AuthConfig loadAuthConfig() {
    AuthConfig auth;
    FILE* f = std::fopen(authPath().c_str(), "r");
    if (!f) return auth;
    char buf[1024];
    while (std::fgets(buf, sizeof(buf), f)) {
        std::string line = trim(buf);
        if (line.empty()) continue;
        if (line[0] == '#') continue;
        if (line[0] == ';') continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = trim(line.substr(0, eq));
        std::string value = trim(line.substr(eq + 1));
        if (key == "nick") {
            auth.nick = value;
        } else if (key == "username") {
            auth.username = value;
        } else if (key == "realname") {
            auth.realname = value;
        } else if (key == "password") {
            auth.password = value;
        }else if (key == "sasl_username") {
            auth.saslUsername = value;
        } else if (key == "sasl_password") {
            auth.saslPassword = value;
        }
    }
    std::fclose(f);
    return auth;
}
static void closeConnection(Connection& c) {
    if (c.ssl) {
        SSL_shutdown(c.ssl);
        SSL_free(c.ssl);
        c.ssl = nullptr;
    }
    if (c.ctx) {
        SSL_CTX_free(c.ctx);
        c.ctx = nullptr;
    }
    if (c.sock != -1) {
        close(c.sock);
        c.sock = -1;
    }
}
static ssize_t connRecv(Connection& conn, char* buf, size_t len) {
    if (conn.tls) {
        int n = SSL_read(conn.ssl, buf, (int)len);
        if (n <= 0) {
            int err = SSL_get_error(conn.ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 0;
            return -1;
        }
        return n;
    }
    return recv(conn.sock, buf, len, 0);
}
static bool sendAll(Connection& conn, const char* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n;
        if (conn.tls) {
            n = SSL_write(conn.ssl, data + sent, (int)(len - sent));
            if (n <= 0) {
                int err = SSL_get_error(conn.ssl, n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)continue;
                return false;
            }
        } else {
            ssize_t r = send(conn.sock, data + sent, len - sent, 0);
            if (r <= 0) return false;
            n = (int)r;
        }
        sent += (size_t)n;
    }
    return true;
}
static std::string timestamp() {
    std::time_t now = std::time(nullptr);
    std::tm* tm = std::localtime(&now);
    char buf[16];
    std::strftime(buf, sizeof(buf), "%H:%M", tm);
    return "[" + std::string(buf) + "] ";
}
static bool sendLine(Connection& conn, const std::string& line) {
    std::string msg = line + "\r\n";
    return sendAll(conn, msg.c_str(), msg.size());
}
static std::string uppercase(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),[](unsigned char c) {return std::toupper(c);});
    return s;
}
static int connectToServer(const std::string& host, const std::string& port) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) {
        return -1;
    }
    int sock = -1;
    for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock == -1) continue;
        if (connect(sock, p->ai_addr, p->ai_addrlen) == 0) break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    return sock;
}
static bool enableTLS(Connection& conn, const std::string& host) {
    SSL_library_init();
    SSL_load_error_strings();
    conn.ctx = SSL_CTX_new(TLS_client_method());
    if (!conn.ctx) return false;
    SSL_CTX_set_default_verify_paths(conn.ctx);
    conn.ssl = SSL_new(conn.ctx);
    if (!conn.ssl) return false;
    SSL_set_fd(conn.ssl, conn.sock);
    SSL_set_tlsext_host_name(conn.ssl, host.c_str());
    SSL_set1_host(conn.ssl, host.c_str());
    SSL_set_verify(conn.ssl, SSL_VERIFY_PEER, nullptr);
    if (SSL_connect(conn.ssl) != 1) return false;
    conn.tls = true;
    return true;
}
struct StyledChunk {
    std::string text;
    short colorPair = 0;
    attr_t attrs = A_NORMAL;
};
struct LogEntry {
    std::vector<StyledChunk> chunks;
};
static std::vector<LogEntry> scrollback;
static constexpr size_t MAX_SCROLLBACK = 2000;
static short colorIdFromName(const std::string& name) {
    if (name == "red") return 1;
    if (name == "green") return 2;
    if (name == "yellow") return 3;
    if (name == "blue") return 4;
    if (name == "magenta") return 5;
    if (name == "cyan") return 6;
    if (name == "white") return 7;
    return 0;
}
static attr_t attrFromName(const std::string& name) {
    if (name == "bold") return A_BOLD;
    if (name == "underline") return A_UNDERLINE;
    if (name == "reverse") return A_REVERSE;
    if (name == "dim") return A_DIM;
    return A_NORMAL;
}
static void drawChunksRaw(WINDOW* win, const std::vector<StyledChunk>& chunks) {
    int h, w;
    getmaxyx(win, h, w);
    if (w <= 1) return;
    int y, x;
    getyx(win, y, x);
    for (const StyledChunk& chunk : chunks) {
        attr_t finalAttrs = chunk.attrs;
        if (chunk.colorPair > 0 && has_colors())finalAttrs |= COLOR_PAIR(chunk.colorPair);
        wattron(win, finalAttrs);
        for (char c : chunk.text) {
            if (c == '\n') {
                waddch(win, '\n');
                getyx(win, y, x);
                continue;
            }
            getyx(win, y, x);
            if (x >= w - 1) waddch(win, '\n');
            waddch(win, c);
        }
        wattroff(win, finalAttrs);
    }
    waddch(win, '\n');
}
static void trimScrollback() {
    if (scrollback.size() > MAX_SCROLLBACK) scrollback.erase(scrollback.begin(),scrollback.begin() + (scrollback.size() - MAX_SCROLLBACK));
}
static void redrawLog(WINDOW* logwin) {
    werase(logwin);
    for (const LogEntry& entry : scrollback)
        drawChunksRaw(logwin, entry.chunks);
    wrefresh(logwin);
}
static void addLogStyled(WINDOW* logwin,const std::string& line,short colorPair,attr_t attrs) {
    scrollback.push_back({{{ line, colorPair, attrs }}});
    trimScrollback();
    redrawLog(logwin);
}
static void addLog(WINDOW* logwin, const std::string& line) {
    LogEntry entry;
    entry.chunks.push_back({ timestamp() + line, 0, A_NORMAL });
    scrollback.push_back(entry);
    trimScrollback();
    redrawLog(logwin);
}
static void logTlsInfo(WINDOW* logwin, Connection& conn) {
    if (!conn.tls || !conn.ssl) return;
    const char* version = SSL_get_version(conn.ssl);
    const SSL_CIPHER* cipher = SSL_get_current_cipher(conn.ssl);
    if (cipher) {
        int secretBits = 0;
        int algBits = SSL_CIPHER_get_bits(cipher, &secretBits);
        addLog(logwin,std::string("TLS: ") +(version ? version : "unknown") +" (" + std::to_string(secretBits) +" bit, " + SSL_CIPHER_get_name(cipher) + ")");
    }
    X509* cert = SSL_get_peer_certificate(conn.ssl);
    if (!cert) {
        addLog(logwin, "TLS: no peer certificate");
        return;
    }
    char subject[512];
    char issuer[512];
    X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
    X509_NAME_oneline(X509_get_issuer_name(cert), issuer, sizeof(issuer));
    addLog(logwin, std::string("TLS certificate subject: ") + subject);
    addLog(logwin, std::string("TLS certificate issuer: ") + issuer);
    int certLen = i2d_X509(cert, nullptr);
    if (certLen > 0) {
        unsigned char* der = (unsigned char*)OPENSSL_malloc(certLen);
        unsigned char* p = der;
        if (der && i2d_X509(cert, &p) == certLen)addLog(logwin, "TLS certificate SHA256: " + sha256Fingerprint(der, certLen));
        OPENSSL_free(der);
    }
    X509_free(cert);
}
static void loadPlugins(lua_State* L, WINDOW* logwin) {
    fs::path dir = pluginDir();
    std::error_code ec;
    fs::create_directories(dir, ec);
    std::vector<fs::path> paths;
    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (ec) break;
        if (!entry.is_regular_file()) continue;
        if (entry.path().extension() != ".lua") continue;
        paths.push_back(entry.path());
    }
    std::sort(paths.begin(), paths.end());
    for (const auto& path : paths) {
        std::string pathStr = path.string();
        if (luaL_dofile(L, pathStr.c_str()) != LUA_OK) {
            const char* err = lua_tostring(L, -1);
            addLog(logwin, std::string("Lua plugin error in ") + pathStr + ": " + (err ? err : "unknown"));
            lua_pop(L, 1);
        } else {addLog(logwin, "Loaded plugin: " + pathStr);}
    }
}
static void drawInput(WINDOW* inputwin, const std::string& input, const std::string& channel) {
    werase(inputwin);
    int h, w;
    getmaxyx(inputwin, h, w);
    std::string prefix = "[" + channel + "] > ";
    std::string shown = prefix + input;
    if ((int)shown.size() > w - 1) shown = shown.substr(shown.size() - (w - 1));
    wattron(inputwin, A_REVERSE);
    mvwaddnstr(inputwin, 0, 0, shown.c_str(), w - 1);
    for (int i = shown.size(); i < w; ++i) waddch(inputwin, ' ');
    wattroff(inputwin, A_REVERSE);
    wmove(inputwin, 0, std::min((int)shown.size(), w - 1));
    wrefresh(inputwin);
}
static void drawStatus(WINDOW* statuswin,const std::string& server,const std::string& nick,const std::string& channel,bool tls) {
    werase(statuswin);
    int h, w;
    getmaxyx(statuswin, h, w);
    std::time_t now = std::time(nullptr);
    std::tm* tm = std::localtime(&now);
    char timebuf[16];
    std::strftime(timebuf, sizeof(timebuf), "%H:%M", tm);
    std::string line;
    line += "[";
    line += timebuf;
    line += "] [";
    line += nick;
    line += "] [";
    line += tls ? "tls:" : "";
    line += server;
    line += "/";
    line += channel;
    line += "]";
    if ((int)line.size() > w - 1) line = line.substr(0, w - 1);
    wattron(statuswin, A_REVERSE);
    mvwaddnstr(statuswin, 0, 0, line.c_str(), w - 1);
    for (int i = line.size(); i < w; ++i) waddch(statuswin, ' ');
    wattroff(statuswin, A_REVERSE);
    wrefresh(statuswin);
}
static void addLogChunks(WINDOW* logwin,const std::vector<StyledChunk>& chunks) {
    scrollback.push_back({ chunks });
    trimScrollback();
    redrawLog(logwin);
}
static std::string nickFromPrefix(const std::string& prefix) {
    size_t bang = prefix.find('!');
    if (bang == std::string::npos) return prefix;
    return prefix.substr(0, bang);
}
static std::vector<std::string> splitWords(const std::string& s) {
    std::vector<std::string> out;
    size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && s[i] == ' ') i++;
        if (i >= s.size()) break;
        size_t j = s.find(' ', i);
        if (j == std::string::npos) {
            out.push_back(s.substr(i));
            break;
        }
        out.push_back(s.substr(i, j - i));
        i = j + 1;
    }
    return out;
}
static std::string stripIrcFormatting(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        unsigned char c = (unsigned char)s[i];
        if (
            c == 0x02 || c == 0x03 || c == 0x0F ||
            c == 0x16 || c == 0x1F || c == 0x1D ||
            c == 0x11 || c == 0x1E
        ) {
            if (c == 0x03) {
                if (i + 1 < s.size() && std::isdigit((unsigned char)s[i + 1])) i++;
                if (i + 1 < s.size() && std::isdigit((unsigned char)s[i + 1])) i++;
                if (i + 1 < s.size() && s[i + 1] == ',') {
                    i++;
                    if (i + 1 < s.size() && std::isdigit((unsigned char)s[i + 1])) i++;
                    if (i + 1 < s.size() && std::isdigit((unsigned char)s[i + 1])) i++;
                }
            }
            continue;
        }
        out.push_back((char)c);
    }
    return out;
}
static std::string formatIRCLine(const std::string& line) {
    if (line.rfind("PING :", 0) == 0) return "";
    std::string rest = line;
    std::string prefix;
    if (!rest.empty() && rest[0] == ':') {
        size_t space = rest.find(' ');
        if (space == std::string::npos) return line;
        prefix = rest.substr(1, space - 1);
        rest = rest.substr(space + 1);
    }
    std::string trailing;
    size_t colon = rest.find(" :");
    if (colon != std::string::npos) {
        trailing = rest.substr(colon + 2);
        rest = rest.substr(0, colon);
    }
    trailing = stripIrcFormatting(trailing);
    std::vector<std::string> parts = splitWords(rest);
    if (parts.empty()) return line;
    std::string cmd = parts[0];
    if (cmd == "PRIVMSG" && parts.size() >= 2) {
        std::string from = nickFromPrefix(prefix);
        std::string target = parts[1];
        if (!trailing.empty() && trailing[0] == '\001') {
            std::string action = trailing;
            if (action.rfind("\001ACTION ", 0) == 0) {
                action = action.substr(8);
                if (!action.empty() && action.back() == '\001') action.pop_back();
                return "* " + from + " " + action;
            }
        }
        return "<" + from + "> " + trailing;
    }
    if (cmd == "NOTICE") return "-notice- " + trailing;
    if (cmd == "JOIN") {
        std::string from = nickFromPrefix(prefix);
        std::string chan = !trailing.empty() ? trailing : (parts.size() > 1 ? parts[1] : "");
        return "--> " + from + " joined " + chan;
    }
    if (cmd == "PART") {
        std::string from = nickFromPrefix(prefix);
        std::string chan = parts.size() > 1 ? parts[1] : "";
        return "<-- " + from + " left " + chan;
    }
    if (cmd == "QUIT") {
        std::string from = nickFromPrefix(prefix);
        return "<-- " + from + " quit: " + trailing;
    }
    if (cmd == "NICK") {
        std::string from = nickFromPrefix(prefix);
        return "*** " + from + " is now known as " + trailing;
    }
    if (cmd == "TOPIC" && parts.size() >= 2) {
        std::string from = nickFromPrefix(prefix);
        return "*** " + from + " changed topic for " + parts[1] + ": " + trailing;
    }
    if (cmd == "001") return "*** " + trailing;
    if (cmd == "005") return "";
    if (cmd == "353") return "";
    if (cmd == "366") return "";
    if (cmd == "321") return "*** Channel list:";
    if (cmd == "322" && parts.size() >= 4) return "[" + parts[2] + "] " + parts[3] + " users - " + trailing;
    if (cmd == "375") return "*** Message of the day:";
    if (cmd == "372") return "*** " + trailing;
    if (cmd == "376") return "*** End of MOTD";
    if (cmd == "332" && parts.size() >= 3)return "*** Topic for " + parts[2] + ": " + trailing;
    if (cmd == "333" && parts.size() >= 4)return "*** Topic set by " + parts[3];
    if (cmd == "311" && parts.size() >= 5)return "*** WHOIS " + parts[2] + ": " + parts[3] + "@" + parts[4] + " - " + trailing;
    if (cmd == "312" && parts.size() >= 4)return "*** WHOIS server: " + parts[3] + " - " + trailing;
    if (cmd == "317" && parts.size() >= 4)return "*** WHOIS idle: " + parts[3] + " seconds";
    if (cmd == "318" && parts.size() >= 3)return "*** End of WHOIS for " + parts[2];
    if (cmd == "401" && parts.size() >= 3)return "*** No such nick/channel: " + parts[2];
    if (cmd == "403" && parts.size() >= 3)return "*** No such channel: " + parts[2];
    if (cmd == "404" && parts.size() >= 3)return "*** Cannot send to channel " + parts[2] + ": " + trailing;
    if (cmd == "433" && parts.size() >= 3)return "*** Nick already in use: " + parts[2];
    if (cmd == "474" && parts.size() >= 3)return "*** Banned from " + parts[2] + ": " + trailing;
    if (cmd == "475" && parts.size() >= 3)return "*** Bad channel key for " + parts[2];
    if (cmd == "323") return "*** End of channel list";
    if (cmd == "002" || cmd == "003" || cmd == "004" || cmd == "250" || cmd == "251" || cmd == "252" || cmd == "253" || cmd == "254" || cmd == "255" || cmd == "265" || cmd == "266" || cmd == "396" || cmd == "900" || cmd == "353" || cmd == "366" || cmd == "MODE") return "";
    return line;
}
static int luaSend(lua_State* L) {
    Connection* conn = static_cast<Connection*>(lua_touserdata(L, lua_upvalueindex(1)));
    const char* line = luaL_checkstring(L, 1);
    lua_pushboolean(L, sendLine(*conn, line));
    return 1;
}
static int luaJoin(lua_State* L) {
    Connection* conn = static_cast<Connection*>(lua_touserdata(L, lua_upvalueindex(1)));
    const char* channel = luaL_checkstring(L, 1);
    std::string command = "JOIN ";
    command += channel;
    lua_pushboolean(L, sendLine(*conn, command));
    return 1;
}
static int luaPrivMsg(lua_State* L) {
    Connection* conn = static_cast<Connection*>(lua_touserdata(L, lua_upvalueindex(1)));
    WINDOW* logwin = static_cast<WINDOW*>(lua_touserdata(L, lua_upvalueindex(2)));
    const char* target = luaL_checkstring(L, 1);
    const char* message = luaL_checkstring(L, 2);
    std::string command = "PRIVMSG ";
    command += target;
    command += " :";
    command += message;
    bool ok = sendLine(*conn, command);
    if (ok) addLog(logwin, std::string("[lua -> ") + target + "] " + message);
    lua_pushboolean(L, ok);
    return 1;
}
static int luaNick(lua_State* L) {
    std::string* nick = static_cast<std::string*>(lua_touserdata(L, lua_upvalueindex(1)));
    lua_pushstring(L, nick->c_str());
    return 1;
}
static int luaLog(lua_State* L) {
    WINDOW* logwin = static_cast<WINDOW*>(lua_touserdata(L, lua_upvalueindex(1)));
    const char* message = luaL_checkstring(L, 1);
    addLog(logwin, std::string("[lua] ") + message);
    return 0;
}
static int luaLogStyled(lua_State* L) {
    WINDOW* logwin = static_cast<WINDOW*>(lua_touserdata(L, lua_upvalueindex(1)));
    const char* message = luaL_checkstring(L, 1);
    const char* color = luaL_optstring(L, 2, "");
    const char* attr1 = luaL_optstring(L, 3, "");
    const char* attr2 = luaL_optstring(L, 4, "");
    short colorPair = colorIdFromName(color);
    attr_t attrs = A_NORMAL;
    attrs |= attrFromName(attr1);
    attrs |= attrFromName(attr2);
    addLogStyled(logwin, std::string("[lua] ") + message, colorPair, attrs);
    return 0;
}
static void registerLuaApi(lua_State* L, Connection& conn, WINDOW* logwin, std::string& nick) {
    lua_newtable(L);
    struct LuaFn {const char* name;lua_CFunction fn;};
    LuaFn connFuncs[] = {{"send", luaSend},{"join", luaJoin},};
    for (const auto& f : connFuncs) {
        lua_pushlightuserdata(L, &conn);
        lua_pushcclosure(L, f.fn, 1);
        lua_setfield(L, -2, f.name);
    }
    lua_pushlightuserdata(L, &conn);
    lua_pushlightuserdata(L, logwin);
    lua_pushcclosure(L, luaPrivMsg, 2);
    lua_setfield(L, -2, "privmsg");
    lua_pushlightuserdata(L, logwin);
    lua_pushcclosure(L, luaLog, 1);
    lua_setfield(L, -2, "log");
    lua_pushlightuserdata(L, logwin);
    lua_pushcclosure(L, luaLogStyled, 1);
    lua_setfield(L, -2, "logStyled");
    lua_pushlightuserdata(L, &nick);
    lua_pushcclosure(L, luaNick, 1);
    lua_setfield(L, -2, "nick");
    lua_setglobal(L, "irc");
}
static void callLuaEvent(lua_State* L,    WINDOW* logwin,    const char* functionName,    const std::vector<std::string>& args) {
    lua_getglobal(L, functionName);
    if (!lua_isfunction(L, -1)) {
        lua_pop(L, 1);
        return;
    }
    for (const std::string& arg : args) {
        lua_pushstring(L, arg.c_str());
    }
    if (lua_pcall(L, (int)args.size(), 0, 0) != LUA_OK) {
        const char* err = lua_tostring(L, -1);
        addLog(logwin,std::string("Lua error in ") + functionName + ": " +(err ? err : "unknown"));
        lua_pop(L, 1);
    }
}
static bool callLuaCommand(lua_State* L,    WINDOW* logwin,    const std::string& command,    const std::string& args,    const std::string& channel) {
    lua_getglobal(L, "onCommand");
    if (!lua_isfunction(L, -1)) {
        lua_pop(L, 1);
        return false;
    }
    lua_pushstring(L, command.c_str());
    lua_pushstring(L, args.c_str());
    lua_pushstring(L, channel.c_str());
    if (lua_pcall(L, 3, 1, 0) != LUA_OK) {
        const char* err = lua_tostring(L, -1);
        addLog(logwin,std::string("Lua error in onCommand: ") + (err ? err : "unknown"));
        lua_pop(L, 1);
        return false;
    }
    bool handled = lua_toboolean(L, -1);
    lua_pop(L, 1);
    return handled;
}
struct LuaStyle {
    bool hasStyle = false;
    short colorPair = 0;
    attr_t attrs = A_NORMAL;
};
static LuaStyle readLuaStyleTable(lua_State* L, int index) {
    LuaStyle style;
    if (!lua_istable(L, index)) return style;
    if (index < 0) index = lua_gettop(L) + index + 1;
    std::string color;
    bool bold = false;
    bool underline = false;
    bool reverse = false;
    bool dim = false;
    lua_getfield(L, index, "color");
    if (lua_isstring(L, -1)) color = lua_tostring(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, index, "bold");
    bold = lua_toboolean(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, index, "underline");
    underline = lua_toboolean(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, index, "reverse");
    reverse = lua_toboolean(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, index, "dim");
    dim = lua_toboolean(L, -1);
    lua_pop(L, 1);
    style.hasStyle = true;
    style.colorPair = colorIdFromName(color);
    style.attrs = A_NORMAL;
    if (bold) style.attrs |= A_BOLD;
    if (underline) style.attrs |= A_UNDERLINE;
    if (reverse) style.attrs |= A_REVERSE;
    if (dim) style.attrs |= A_DIM;
    return style;
}
struct LuaMessageStyle {
    bool hasStyle = false;
    LuaStyle nick;
    LuaStyle body;
    LuaStyle brackets;
};
static LuaMessageStyle callLuaStyleMessage(
    lua_State* L,
    WINDOW* logwin,
    const std::string& from,
    const std::string& target,
    const std::string& text,
    const std::string& raw
) {
    LuaMessageStyle out;
    lua_getglobal(L, "styleMessage");
    if (!lua_isfunction(L, -1)) {
        lua_pop(L, 1);
        return out;
    }
    lua_pushstring(L, from.c_str());
    lua_pushstring(L, target.c_str());
    lua_pushstring(L, text.c_str());
    lua_pushstring(L, raw.c_str());
    if (lua_pcall(L, 4, 1, 0) != LUA_OK) {
        const char* err = lua_tostring(L, -1);
        addLog(logwin, std::string("Lua error in styleMessage: ") + (err ? err : "unknown"));
        lua_pop(L, 1);
        return out;
    }
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        return out;
    }
    lua_getfield(L, -1, "nick");
    out.nick = readLuaStyleTable(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, -1, "body");
    out.body = readLuaStyleTable(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, -1, "brackets");
    out.brackets = readLuaStyleTable(L, -1);
    lua_pop(L, 1);
    lua_pop(L, 1);
    out.hasStyle = out.nick.hasStyle || out.body.hasStyle || out.brackets.hasStyle;
    return out;
}
static void addMessageWithLuaStyle(
    lua_State* L,
    WINDOW* logwin,
    const std::string& from,
    const std::string& target,
    const std::string& text,
    const std::string& raw
) {
    LuaMessageStyle style = callLuaStyleMessage(L, logwin, from, target, text, raw);
    if (!style.hasStyle) {
        addLog(logwin, "<" + from + "> " + text);
        return;
    }
    LuaStyle plain;
    plain.hasStyle = true;
    plain.colorPair = 0;
    plain.attrs = A_NORMAL;
    LuaStyle brackets = style.brackets.hasStyle ? style.brackets : plain;
    LuaStyle nickStyle = style.nick.hasStyle ? style.nick : plain;
    LuaStyle bodyStyle = style.body.hasStyle ? style.body : plain;
    addLogChunks(logwin, {
        {"<", brackets.colorPair, brackets.attrs},
        {from, nickStyle.colorPair, nickStyle.attrs},
        {"> ", brackets.colorPair, brackets.attrs},
        {text, bodyStyle.colorPair, bodyStyle.attrs}
    });
}
static LuaStyle callLuaStyleLine(lua_State* L,WINDOW* logwin,const std::string& event,const std::string& from,const std::string& target,const std::string& text,const std::string& raw) {
    LuaStyle style;
    lua_getglobal(L, "styleLine");
    if (!lua_isfunction(L, -1)) {
        lua_pop(L, 1);
        return style;
    }
    lua_pushstring(L, event.c_str());
    lua_pushstring(L, from.c_str());
    lua_pushstring(L, target.c_str());
    lua_pushstring(L, text.c_str());
    lua_pushstring(L, raw.c_str());
    if (lua_pcall(L, 5, 1, 0) != LUA_OK) {
        const char* err = lua_tostring(L, -1);
        addLog(logwin, std::string("Lua error in styleLine: ") + (err ? err : "unknown"));
        lua_pop(L, 1);
        return style;
    }
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        return style;
    }
    std::string color;
    bool bold = false;
    bool underline = false;
    bool reverse = false;
    bool dim = false;
    lua_getfield(L, -1, "color");
    if (lua_isstring(L, -1)) color = lua_tostring(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, -1, "bold");
    bold = lua_toboolean(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, -1, "underline");
    underline = lua_toboolean(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, -1, "reverse");
    reverse = lua_toboolean(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, -1, "dim");
    dim = lua_toboolean(L, -1);
    lua_pop(L, 1);
    lua_pop(L, 1);
    style.hasStyle = true;
    style.colorPair = colorIdFromName(color);
    style.attrs = A_NORMAL;
    if (bold) style.attrs |= A_BOLD;
    if (underline) style.attrs |= A_UNDERLINE;
    if (reverse) style.attrs |= A_REVERSE;
    if (dim) style.attrs |= A_DIM;
    return style;
}
struct ParsedIRC {
    std::string prefix;
    std::string command;
    std::vector<std::string> params;
    std::string trailing;
};
static bool parseIRCLine(const std::string& line, ParsedIRC& out) {
    std::string rest = line;
    out = ParsedIRC{};
    if (!rest.empty() && rest[0] == ':') {
        size_t space = rest.find(' ');
        if (space == std::string::npos) return false;
        out.prefix = rest.substr(1, space - 1);
        rest = rest.substr(space + 1);
    }
    size_t colon = rest.find(" :");
    if (colon != std::string::npos) {
        out.trailing = rest.substr(colon + 2);
        rest = rest.substr(0, colon);
    }
    std::vector<std::string> parts = splitWords(rest);
    if (parts.empty()) return false;
    out.command = parts[0];
    for (size_t i = 1; i < parts.size(); ++i) out.params.push_back(parts[i]);
    return true;
}
static std::string ircEventType(const ParsedIRC& parsed) {
    std::string command = uppercase(parsed.command);
    if (command == "PRIVMSG") {
        if (!parsed.trailing.empty() && parsed.trailing[0] == '\001') return "ctcp";
        return "message";
    }
    if (command == "NOTICE") return "notice";
    if (command == "JOIN") return "join";
    if (command == "PART") return "part";
    if (command == "QUIT") return "quit";
    if (command == "NICK") return "nick";
    if (command == "TOPIC") return "topic";
    if (command == "001") return "welcome";
    if (command == "353") return "names";
    if (command == "366") return "endnames";
    return "raw";
}
int main(int argc, char** argv) {
    if (argc < 4) {
        printf("Usage: %s <server> <port> <channel> [--tls]\n", argv[0]);
        printf("Or:    %s <server> <port> <nick> <channel> [--tls]\n", argv[0]);
        return 1;
    }
    AuthConfig auth = loadAuthConfig();
    std::string server = argv[1];
    std::string port = argv[2];
    std::string nick;
    std::string channel;
    bool use_tls = false;
    if (argc >= 5 && std::string(argv[4]) != "--tls") {
        nick = argv[3];
        channel = argv[4];
        use_tls = argc >= 6 && std::string(argv[5]) == "--tls";
    } else {
        nick = auth.nick;
        channel = argv[3];
        use_tls = argc >= 5 && std::string(argv[4]) == "--tls";
    }
    if (nick.empty()) {
        printf("No nick provided. Put nick=yourNick in %s or pass nick on CLI.\n",authPath().c_str());
        return 1;
    }
    std::string username = auth.username.empty() ? nick : auth.username;
    std::string realname = auth.realname.empty() ? nick : auth.realname;
    Connection conn;
    conn.sock = connectToServer(server, port);
    if (conn.sock == -1) {
        printf("Could not connect.\n");
        return 1;
    }
    if (use_tls) {
        if (!enableTLS(conn, server)) {
            fprintf(stderr, "TLS handshake failed.\n");
            ERR_print_errors_fp(stderr);
            closeConnection(conn);
            return 1;
        }
    }
    lua_State* L = luaL_newstate();
    luaL_openlibs(L);
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(1);
    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(1, COLOR_RED,     -1);
        init_pair(2, COLOR_GREEN,   -1);
        init_pair(3, COLOR_YELLOW,  -1);
        init_pair(4, COLOR_BLUE,    -1);
        init_pair(5, COLOR_MAGENTA, -1);
        init_pair(6, COLOR_CYAN,    -1);
        init_pair(7, COLOR_WHITE,   -1);
    }
    int rows, cols;
    getmaxyx(stdscr, rows, cols);
    WINDOW* logwin = newwin(rows - 2, cols, 0, 0);
    WINDOW* statuswin = newwin(1, cols, rows - 2, 0);
    WINDOW* inputwin = newwin(1, cols, rows - 1, 0);
    scrollok(logwin, TRUE);
    nodelay(inputwin, TRUE);
    keypad(inputwin, TRUE);
    scrollok(statuswin, FALSE);

    bool wantSasl = !auth.saslPassword.empty() || !auth.password.empty();
    if (wantSasl) {
        capNegotiating = true;
        sendLine(conn, "CAP LS 302");
    }
    sendLine(conn, "NICK " + nick);
    sendLine(conn, "USER " + username + " 0 * :" + realname);
    if (!wantSasl)sendLine(conn, "JOIN " + channel);
    addLog(logwin, "Connected to " + server + ". Type /QUIT :bye to exit.");
    addLog(logwin, "Use /JOIN #chan then /channel #chan to switch target.");
    if (use_tls) logTlsInfo(logwin, conn);
    std::string input;
    std::string server_buffer;
    drawStatus(statuswin, server, nick, channel, use_tls);
    drawInput(inputwin, input, channel);
    pollfd fds[1]{};
    fds[0].fd = conn.sock;
    fds[0].events = POLLIN;
    bool running = true;
    bool registered = false;
    bool joinedInitialChannel = false;
    registerLuaApi(L, conn, logwin, nick);
    loadPlugins(L, logwin);
    std::time_t lastStatusMinute = 0;
    while (running) {
        std::time_t now = std::time(nullptr);
        std::time_t currentMinute = now / 60;
        if (currentMinute != lastStatusMinute) {
            lastStatusMinute = currentMinute;
            drawStatus(statuswin, server, nick, channel, use_tls);
            drawInput(inputwin, input, channel);
        }
        int ready = poll(fds, 1, 50);
        if (ready > 0 && (fds[0].revents & POLLIN)) {
            char temp[512];
            ssize_t n = connRecv(conn, temp, sizeof(temp) - 1);
            if (n < 0) {
                addLog(logwin, "Disconnected.");
                break;
            }
            if (n == 0) {
                continue;
            }
            temp[n] = '\0';
            server_buffer += temp;
            size_t pos;
            while ((pos = server_buffer.find("\r\n")) != std::string::npos) {
                std::string line = server_buffer.substr(0, pos);
                server_buffer.erase(0, pos + 2);
                if (line.rfind("PING :", 0) == 0) {
                    std::string token = line.substr(6);
                    sendLine(conn, "PONG :" + token);
                    continue;
                }
                callLuaEvent(L, logwin, "onRaw", {line});
                ParsedIRC parsed;
                if (parseIRCLine(line, parsed)) {
                    std::string command = uppercase(parsed.command);
                    if (command == "CAP") {
                        std::string subcmd = parsed.params.size() >= 2 ? uppercase(parsed.params[1]) : "";
                        std::string caps = parsed.trailing;
                        if (subcmd == "LS") {
                            addLog(logwin, "Capabilities supported: " + caps);
                            if (wantSasl && caps.find("sasl") != std::string::npos && !saslRequested) {
                                sendLine(conn, "CAP REQ :sasl");
                                addLog(logwin, "Capabilities requested: sasl");
                                saslRequested = true;
                            } else if (!sentCapEnd) {
                                sendLine(conn, "CAP END");
                                sentCapEnd = true;
                            }
                            continue;
                        }
                        if (subcmd == "ACK") {
                            addLog(logwin, "Capabilities acknowledged: " + caps);
                            if (wantSasl && caps.find("sasl") != std::string::npos) {
                                sendLine(conn, "AUTHENTICATE PLAIN");
                            } else if (!sentCapEnd) {
                                sendLine(conn, "CAP END");
                                sentCapEnd = true;
                            }
                            continue;
                        }
                        if (subcmd == "NAK") {
                            addLog(logwin, "Capabilities denied: " + caps);
                            if (!sentCapEnd) {
                                sendLine(conn, "CAP END");
                                sentCapEnd = true;
                            }
                            continue;
                        }
                    }
                    if (command == "AUTHENTICATE") {
                        std::string token = !parsed.trailing.empty()
                        ? parsed.trailing
                        : (!parsed.params.empty() ? parsed.params[0] : "");
                        if (token == "+") {
                            std::string saslUser = auth.saslUsername.empty() ? nick : auth.saslUsername;
                            std::string saslPass = !auth.saslPassword.empty() ? auth.saslPassword : auth.password;
                            std::string payload;
                            payload.push_back('\0');
                            payload += saslUser;
                            payload.push_back('\0');
                            payload += saslPass;
                            sendLine(conn, "AUTHENTICATE " + base64Encode(payload));
                            continue;
                        }
                    }
                    if (command == "903") {
                        addLog(logwin, "SASL authentication succeeded");
                        saslDone = true;
                        if (!sentCapEnd) {
                            sendLine(conn, "CAP END");
                            sentCapEnd = true;
                        }
                        continue;
                    }
                    if (command == "904" || command == "905" || command == "906" || command == "907") {
                        addLog(logwin, "SASL authentication failed or unavailable");
                        if (!sentCapEnd) {
                            sendLine(conn, "CAP END");
                            sentCapEnd = true;
                        }
                        continue;
                    }
                    if (command == "001" && !registered) {
                        registered = true;
                        if (!joinedInitialChannel) {
                            sendLine(conn, "JOIN " + channel);
                            joinedInitialChannel = true;
                        }
                    }
                    if (command == "NOTICE" &&!joinedInitialChannel &&nickFromPrefix(parsed.prefix) == "NickServ" &&parsed.trailing.find("You are now identified") != std::string::npos) {
                        sendLine(conn, "JOIN " + channel);
                        joinedInitialChannel = true;
                    }
                    if (command == "PRIVMSG" && parsed.params.size() >= 1) {
                        std::string from = nickFromPrefix(parsed.prefix);
                        std::string target = parsed.params[0];
                        std::string text = parsed.trailing;
                        callLuaEvent(L, logwin, "onMessage", {from,target,text,line});
                        if (!text.empty() && text[0] == '\001') {
                            callLuaEvent(L, logwin, "onCtcp", {from,target,text,line});
                        }
                    } else if (command == "NOTICE" && parsed.params.size() >= 1) {
                        callLuaEvent(L, logwin, "onNotice", {nickFromPrefix(parsed.prefix),parsed.params[0],parsed.trailing,line});
                    } else if (command == "JOIN") {
                        std::string from = nickFromPrefix(parsed.prefix);
                        std::string joinedChannel =!parsed.trailing.empty()? parsed.trailing: (!parsed.params.empty() ? parsed.params[0] : "");
                        callLuaEvent(L, logwin, "onJoin", {from,joinedChannel,line});
                    } else if (command == "PART" && parsed.params.size() >= 1) {
                        callLuaEvent(L, logwin, "onPart", {
                            nickFromPrefix(parsed.prefix),parsed.params[0],parsed.trailing,line});
                    } else if (command == "QUIT") {
                        callLuaEvent(L, logwin, "onQuit", {
                            nickFromPrefix(parsed.prefix),parsed.trailing,line});
                    }
                }
                bool renderedByStyleMessage = false;
                if (parseIRCLine(line, parsed)) {
                    std::string messageCommand = uppercase(parsed.command);
                    if (messageCommand == "PRIVMSG" &&
                        parsed.params.size() >= 1 &&
                        (parsed.trailing.empty() || parsed.trailing[0] != '\001')) {
                        std::string from = nickFromPrefix(parsed.prefix);
                        std::string target = parsed.params[0];
                        std::string text = parsed.trailing;
                        LuaMessageStyle messageStyle = callLuaStyleMessage(L, logwin, from, target, text, line);
                        if (messageStyle.hasStyle) {
                            LuaStyle plain;
                            plain.hasStyle = true;
                            plain.colorPair = 0;
                            plain.attrs = A_NORMAL;
                            LuaStyle brackets = messageStyle.brackets.hasStyle ? messageStyle.brackets : plain;
                            LuaStyle nickStyle = messageStyle.nick.hasStyle ? messageStyle.nick : plain;
                            LuaStyle bodyStyle = messageStyle.body.hasStyle ? messageStyle.body : plain;
                            addLogChunks(logwin, {
                                {"<", brackets.colorPair, brackets.attrs},
                                {from, nickStyle.colorPair, nickStyle.attrs},
                                {"> ", brackets.colorPair, brackets.attrs},
                                {text, bodyStyle.colorPair, bodyStyle.attrs}
                            });
                            renderedByStyleMessage = true;
                        }
                    }
                }
                if (renderedByStyleMessage) continue;
                std::string pretty = formatIRCLine(line);
                if (!pretty.empty()) {
                    LuaStyle style;
                    ParsedIRC styleParsed;
                    if (parseIRCLine(line, styleParsed)) {
                        std::string event = ircEventType(styleParsed);
                        std::string from = nickFromPrefix(styleParsed.prefix);
                        std::string target;
                        std::string text = styleParsed.trailing;
                        if (!styleParsed.params.empty()) target = styleParsed.params[0];
                        style = callLuaStyleLine(L, logwin, event, from, target, text, line);
                    }
                    if (style.hasStyle) addLogStyled(logwin, pretty, style.colorPair, style.attrs); else addLog(logwin, pretty);
                }
            }
            drawInput(inputwin, input, channel);
        }
        int ch = wgetch(inputwin);
        if (ch != ERR) {
            if (ch == KEY_RESIZE) {
                getmaxyx(stdscr, rows, cols);
                wresize(logwin, rows - 2, cols);
                wresize(statuswin, 1, cols);
                wresize(inputwin, 1, cols);
                mvwin(logwin, 0, 0);
                mvwin(statuswin, rows - 2, 0);
                mvwin(inputwin, rows - 1, 0);
                werase(stdscr);
                wrefresh(stdscr);
                redrawLog(logwin);
                drawStatus(statuswin, server, nick, channel, use_tls);
                drawInput(inputwin, input, channel);
            } else if (ch == '\n' || ch == '\r') {
                if (!input.empty()) {
                    if (input.rfind("/channel ", 0) == 0) {
                        channel = input.substr(9);
                        drawStatus(statuswin, server, nick, channel, use_tls);
                        addLog(logwin, "Now sending messages to " + channel);
                    } else if (input[0] == '/') {
                        std::string raw = input.substr(1);
                        addLog(logwin, "[debug] slash raw=[" + raw + "]");
                        std::vector<std::string> words = splitWords(raw);
                        std::string command = words.empty() ? "" : words[0];
                        std::string args;
                        if (raw.size() > command.size()) {
                            args = raw.substr(command.size());
                            while (!args.empty() && args[0] == ' ') {
                                args.erase(0, 1);
                            }
                        }
                        if (uppercase(command) != "JOIN" &&uppercase(command) != "QUIT" &&uppercase(command) != "NICK" &&uppercase(command) != "CHANNEL") {
                            bool handled = callLuaCommand(L, logwin, command, args, channel);
                        if (handled) {
                            input.clear();
                            drawInput(inputwin, input, channel);
                            continue;
                        }
                            }
                            sendLine(conn, raw);
                            std::string raw_upper = uppercase(raw);

                            if (raw_upper.rfind("JOIN ", 0) == 0) {
                                std::vector<std::string> words = splitWords(raw);
                                if (words.size() >= 2) {
                                    channel = words[1];
                                    drawStatus(statuswin, server, nick, channel, use_tls);
                                    addLog(logwin, "Now sending messages to " + channel);
                                }
                            }

                            if (raw_upper.rfind("NICK ", 0) == 0) {
                                std::vector<std::string> words = splitWords(raw);
                                if (words.size() >= 2) {
                                    nick = words[1];
                                    drawStatus(statuswin, server, nick, channel, use_tls);
                                }
                            }

                            if (raw_upper.rfind("QUIT", 0) == 0) running = false;
                    } else {
                        sendLine(conn, "PRIVMSG " + channel + " :" + input);
                        addMessageWithLuaStyle(L, logwin, nick, channel, input, "");
                    }
                    input.clear();
                }
            } else if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
                if (!input.empty()) {
                    input.pop_back();
                }
            } else if (ch >= 32 && ch <= 126) {
                input.push_back((char)ch);
            }
            drawInput(inputwin, input, channel);
        }
    }
    lua_close(L);
    delwin(logwin);
    delwin(statuswin);
    delwin(inputwin);
    endwin();
    closeConnection(conn);
    return 0;
}
