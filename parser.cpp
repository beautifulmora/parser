#include <iostream>
#include <string>
#include <cctype>
#include <cstring>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

using namespace std;

static string trim(const string &s) {
    size_t start = 0;
    while (start < s.size() && isspace(static_cast<unsigned char>(s[start]))) start++;
    size_t end = s.size();
    while (end > start && isspace(static_cast<unsigned char>(s[end - 1]))) end--;
    return s.substr(start, end - start);
}

struct ParsedUrl {
    string protocol;
    string host;
    string port;
};

static ParsedUrl parse_url(const string &input) {
    ParsedUrl out;
    string s = trim(input);

    // Basic scheme parsing
    size_t scheme_pos = s.find("://");
    if (scheme_pos != string::npos) {
        out.protocol = s.substr(0, scheme_pos);
        s = s.substr(scheme_pos + 3);
    } else {
        // Default to http if scheme missing
        out.protocol = "http";
    }

    // Strip path/query/fragment
    size_t path_pos = s.find_first_of("/?#");
    string hostport = (path_pos == string::npos) ? s : s.substr(0, path_pos);

    // Separate host and port
    size_t port_pos = hostport.find(":");
    if (port_pos != string::npos) {
        out.host = hostport.substr(0, port_pos);
        out.port = hostport.substr(port_pos + 1);
    } else {
        out.host = hostport;
        if (out.protocol == "https") out.port = "443";
        else if (out.protocol == "http") out.port = "80";
        else out.port = "unknown";
    }

    return out;
}

static bool is_ipv4(const string &host) {
    int parts = 0;
    int num = -1;
    for (size_t i = 0; i <= host.size(); ++i) {
        if (i == host.size() || host[i] == '.') {
            if (num < 0 || num > 255) return false;
            parts++;
            num = -1;
        } else if (isdigit(static_cast<unsigned char>(host[i]))) {
            if (num == -1) num = 0;
            num = num * 10 + (host[i] - '0');
        } else {
            return false;
        }
    }
    return parts == 4;
}

static string resolve_ip(const string &host) {
    if (host.empty()) return "N/A";
    if (is_ipv4(host)) return host;

    addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo *res = nullptr;
    int rc = getaddrinfo(host.c_str(), nullptr, &hints, &res);
    if (rc != 0 || res == nullptr) return "N/A";

    string ip = "N/A";
    for (addrinfo *p = res; p != nullptr; p = p->ai_next) {
        char buf[INET6_ADDRSTRLEN];
        void *addr = nullptr;
        if (p->ai_family == AF_INET) {
            sockaddr_in *ipv4 = reinterpret_cast<sockaddr_in *>(p->ai_addr);
            addr = &(ipv4->sin_addr);
        } else if (p->ai_family == AF_INET6) {
            sockaddr_in6 *ipv6 = reinterpret_cast<sockaddr_in6 *>(p->ai_addr);
            addr = &(ipv6->sin6_addr);
        } else {
            continue;
        }
        if (inet_ntop(p->ai_family, addr, buf, sizeof(buf))) {
            ip = buf;
            break;
        }
    }

    freeaddrinfo(res);
    return ip;
}

int main() {
    cout << "Which website should be scanned? (enter link)\n";
    string link;
    if (!getline(cin, link)) return 0;

    ParsedUrl p = parse_url(link);

    cout << "\nIP:\n";
    cout << resolve_ip(p.host) << "\n";

    cout << "MAC:\n";
    cout << "N/A\n";

    cout << "domain:\n";
    cout << (p.host.empty() ? "N/A" : p.host) << "\n";

    cout << "protocol:\n";
    cout << (p.protocol.empty() ? "N/A" : p.protocol);

    cout << "port:\n";
    cout << (p.port.empty() ? "N/A" : p.port) << "\n";

    return 0;
}
