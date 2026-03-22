#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstring>
#include <chrono>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <resolv.h>
#include <arpa/nameser.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

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
    string path;
};

static ParsedUrl parse_url(const string &input) {
    ParsedUrl out;
    string s = trim(input);

    size_t scheme_pos = s.find("://");
    if (scheme_pos != string::npos) {
        out.protocol = s.substr(0, scheme_pos);
        s = s.substr(scheme_pos + 3);
    } else {
        out.protocol = "http";
    }

    size_t path_pos = s.find_first_of("/?#");
    string hostport = (path_pos == string::npos) ? s : s.substr(0, path_pos);
    out.path = (path_pos == string::npos) ? "/" : s.substr(path_pos);

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

static vector<string> resolve_ips(const string &host) {
    vector<string> ips;
    if (host.empty()) return ips;
    if (is_ipv4(host)) {
        ips.push_back(host);
        return ips;
    }

    addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo *res = nullptr;
    int rc = getaddrinfo(host.c_str(), nullptr, &hints, &res);
    if (rc != 0 || res == nullptr) return ips;

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
            string ip = buf;
            bool exists = false;
            for (const auto &x : ips) if (x == ip) { exists = true; break; }
            if (!exists) ips.push_back(ip);
        }
    }

    freeaddrinfo(res);
    return ips;
}

static vector<string> dns_query(const string &host, int qtype) {
    vector<string> out;
    if (host.empty()) return out;

    unsigned char answer[4096];
    int len = res_query(host.c_str(), ns_c_in, qtype, answer, sizeof(answer));
    if (len < 0) return out;

    ns_msg handle;
    if (ns_initparse(answer, len, &handle) < 0) return out;

    int count = ns_msg_count(handle, ns_s_an);
    for (int i = 0; i < count; ++i) {
        ns_rr rr;
        if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) continue;
        if (ns_rr_type(rr) != qtype) continue;

        const unsigned char *rdata = ns_rr_rdata(rr);
        char buf[NS_MAXDNAME];

        if (qtype == ns_t_cname || qtype == ns_t_ns) {
            if (ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle), rdata, buf, sizeof(buf)) >= 0) {
                out.push_back(buf);
            }
        } else if (qtype == ns_t_mx) {
            if (ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle), rdata + 2, buf, sizeof(buf)) >= 0) {
                out.push_back(buf);
            }
        } else if (qtype == ns_t_txt) {
            // TXT can contain multiple strings; take the first chunk for simplicity
            if (ns_rr_rdlen(rr) > 0) {
                int txt_len = rdata[0];
                if (txt_len > 0 && txt_len < ns_rr_rdlen(rr)) {
                    out.push_back(string(reinterpret_cast<const char *>(rdata + 1), txt_len));
                }
            }
        }
    }

    return out;
}

static string guess_cdn(const vector<string> &cname_chain) {
    for (const auto &c : cname_chain) {
        string lc = c;
        for (char &ch : lc) ch = static_cast<char>(tolower(static_cast<unsigned char>(ch)));
        if (lc.find("cloudflare") != string::npos) return "Cloudflare";
        if (lc.find("akamai") != string::npos) return "Akamai";
        if (lc.find("fastly") != string::npos) return "Fastly";
        if (lc.find("cloudfront") != string::npos || lc.find("amazonaws") != string::npos) return "AWS/CloudFront";
        if (lc.find("azure") != string::npos) return "Microsoft Azure";
        if (lc.find("google") != string::npos || lc.find("gcp") != string::npos) return "Google Cloud";
    }
    return "Unknown";
}

static int connect_tcp(const string &host, const string &port, long long &latency_ms) {
    addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo *res = nullptr;
    int rc = getaddrinfo(host.c_str(), port.c_str(), &hints, &res);
    if (rc != 0 || res == nullptr) return -1;

    int sock = -1;
    auto start = chrono::steady_clock::now();

    for (addrinfo *p = res; p != nullptr; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) continue;
        if (connect(sock, p->ai_addr, p->ai_addrlen) == 0) {
            auto end = chrono::steady_clock::now();
            latency_ms = chrono::duration_cast<chrono::milliseconds>(end - start).count();
            freeaddrinfo(res);
            return sock;
        }
        close(sock);
        sock = -1;
    }

    freeaddrinfo(res);
    return -1;
}

static string read_http_headers_plain(int sock, const string &host, const string &path) {
    string req = "HEAD " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\nUser-Agent: simple-parser\r\n\r\n";
    send(sock, req.c_str(), req.size(), 0);

    string data;
    char buf[2048];
    ssize_t n;
    while ((n = recv(sock, buf, sizeof(buf), 0)) > 0) {
        data.append(buf, buf + n);
        size_t pos = data.find("\r\n\r\n");
        if (pos != string::npos) {
            data.resize(pos + 2);
            break;
        }
    }
    return data;
}

static string read_http_headers_tls(SSL *ssl, const string &host, const string &path) {
    string req = "HEAD " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\nUser-Agent: simple-parser\r\n\r\n";
    SSL_write(ssl, req.c_str(), static_cast<int>(req.size()));

    string data;
    char buf[2048];
    int n;
    while ((n = SSL_read(ssl, buf, sizeof(buf))) > 0) {
        data.append(buf, buf + n);
        size_t pos = data.find("\r\n\r\n");
        if (pos != string::npos) {
            data.resize(pos + 2);
            break;
        }
    }
    return data;
}

static string fetch_page_title_plain(int sock, const string &host, const string &path) {
    string req = "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\nUser-Agent: simple-parser\r\n\r\n";
    send(sock, req.c_str(), req.size(), 0);

    string data;
    char buf[2048];
    ssize_t n;
    while ((n = recv(sock, buf, sizeof(buf), 0)) > 0) {
        data.append(buf, buf + n);
        if (data.size() > 65536) break;
    }

    size_t title_pos = data.find("<title>");
    if (title_pos == string::npos) return "N/A";
    size_t title_end = data.find("</title>", title_pos + 7);
    if (title_end == string::npos) return "N/A";

    string title = data.substr(title_pos + 7, title_end - (title_pos + 7));
    return trim(title);
}

static string fetch_page_title_tls(SSL *ssl, const string &host, const string &path) {
    string req = "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\nUser-Agent: simple-parser\r\n\r\n";
    SSL_write(ssl, req.c_str(), static_cast<int>(req.size()));

    string data;
    char buf[2048];
    int n;
    while ((n = SSL_read(ssl, buf, sizeof(buf))) > 0) {
        data.append(buf, buf + n);
        if (data.size() > 65536) break;
    }

    size_t title_pos = data.find("<title>");
    if (title_pos == string::npos) return "N/A";
    size_t title_end = data.find("</title>", title_pos + 7);
    if (title_end == string::npos) return "N/A";

    string title = data.substr(title_pos + 7, title_end - (title_pos + 7));
    return trim(title);
}

static void print_list(const vector<string> &items, const string &indent) {
    if (items.empty()) {
        cout << indent << "N/A\n";
        return;
    }
    for (const auto &x : items) cout << indent << x << "\n";
}

int main() {
    cout << "Which website should be scanned? (enter link)\n";
    string link;
    if (!getline(cin, link)) return 0;

    ParsedUrl p = parse_url(link);

    cout << "\nIP:\n";
    vector<string> ips = resolve_ips(p.host);
    print_list(ips, "");

    cout << "MAC:\n";
    cout << "N/A (remote MAC not visible over the Internet)\n";

    cout << "domain:\n";
    cout << (p.host.empty() ? "N/A" : p.host) << "\n";

    cout << "protocol:\n";
    cout << (p.protocol.empty() ? "N/A" : p.protocol) << "\n";

    cout << "port:\n";
    cout << (p.port.empty() ? "N/A" : p.port) << "\n";

    cout << "DNS CNAME:\n";
    vector<string> cname = dns_query(p.host, ns_t_cname);
    print_list(cname, "");

    cout << "DNS NS:\n";
    vector<string> ns = dns_query(p.host, ns_t_ns);
    print_list(ns, "");

    cout << "DNS MX:\n";
    vector<string> mx = dns_query(p.host, ns_t_mx);
    print_list(mx, "");

    cout << "DNS TXT:\n";
    vector<string> txt = dns_query(p.host, ns_t_txt);
    print_list(txt, "");

    cout << "CDN/Hosting guess:\n";
    cout << guess_cdn(cname) << "\n";

    long long latency_ms = -1;
    int sock = connect_tcp(p.host, p.port, latency_ms);
    cout << "Reachability/Latency:\n";
    if (sock >= 0) cout << "reachable, " << latency_ms << " ms\n";
    else cout << "unreachable\n";

    string headers = "N/A";
    string title = "N/A";
    string cert_subject = "N/A";
    string cert_issuer = "N/A";
    string cert_valid_from = "N/A";
    string cert_valid_to = "N/A";

    if (p.protocol == "https" && sock >= 0) {
        SSL_library_init();
        SSL_load_error_strings();
        const SSL_METHOD *method = TLS_client_method();
        SSL_CTX *ctx = SSL_CTX_new(method);
        SSL *ssl = SSL_new(ctx);
        SSL_set_tlsext_host_name(ssl, p.host.c_str());
        SSL_set_fd(ssl, sock);

        if (SSL_connect(ssl) == 1) {
            headers = read_http_headers_tls(ssl, p.host, p.path);
            title = fetch_page_title_tls(ssl, p.host, p.path);

            X509 *cert = SSL_get_peer_certificate(ssl);
            if (cert) {
                char buf[512];
                X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));
                cert_subject = buf;
                X509_NAME_oneline(X509_get_issuer_name(cert), buf, sizeof(buf));
                cert_issuer = buf;

                const ASN1_TIME *not_before = X509_get0_notBefore(cert);
                const ASN1_TIME *not_after = X509_get0_notAfter(cert);
                BIO *bio = BIO_new(BIO_s_mem());
                if (bio) {
                    ASN1_TIME_print(bio, not_before);
                    char timebuf[128];
                    int n = BIO_read(bio, timebuf, sizeof(timebuf) - 1);
                    if (n > 0) {
                        timebuf[n] = 0;
                        cert_valid_from = timebuf;
                    }
                    BIO_free(bio);
                }
                bio = BIO_new(BIO_s_mem());
                if (bio) {
                    ASN1_TIME_print(bio, not_after);
                    char timebuf[128];
                    int n = BIO_read(bio, timebuf, sizeof(timebuf) - 1);
                    if (n > 0) {
                        timebuf[n] = 0;
                        cert_valid_to = timebuf;
                    }
                    BIO_free(bio);
                }
                X509_free(cert);
            }
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sock);
    } else if (sock >= 0) {
        headers = read_http_headers_plain(sock, p.host, p.path);
        title = fetch_page_title_plain(sock, p.host, p.path);
        close(sock);
    }

    cout << "HTTP headers:\n";
    cout << headers << "\n";

    cout << "Page title:\n";
    cout << title << "\n";

    if (p.protocol == "https") {
        cout << "TLS certificate subject:\n";
        cout << cert_subject << "\n";
        cout << "TLS certificate issuer:\n";
        cout << cert_issuer << "\n";
        cout << "TLS valid from:\n";
        cout << cert_valid_from << "\n";
        cout << "TLS valid to:\n";
        cout << cert_valid_to << "\n";
    }

    return 0;
}
