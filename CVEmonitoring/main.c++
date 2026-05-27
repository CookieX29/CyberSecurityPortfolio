#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using json = nlohmann::json;

namespace {

constexpr const char* NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
constexpr const char* CISA_KEV_JSON =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

struct Options {
    std::optional<std::string> cve_id;
    std::optional<std::string> keyword;
    std::optional<std::string> severity;
    int days = 7;
    int limit = 20;
    bool json_output = false;
    bool include_kev = true;
    int watch_minutes = 0;
    std::optional<std::string> api_key;
};

struct HttpResponse {
    long status_code = 0;
    std::string body;
};

struct CveFinding {
    std::string id;
    std::string published;
    std::string last_modified;
    std::string severity = "UNKNOWN";
    double score = 0.0;
    std::string description;
    bool known_exploited = false;
    std::string kev_due_date;
    std::string kev_action;
    std::vector<std::string> references;
};

size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    auto* buffer = static_cast<std::string*>(userp);
    const size_t total_size = size * nmemb;
    buffer->append(static_cast<char*>(contents), total_size);
    return total_size;
}

std::string get_env(const char* key) {
    const char* value = std::getenv(key);
    return value == nullptr ? "" : std::string(value);
}

std::string url_encode(CURL* curl, const std::string& value) {
    char* encoded = curl_easy_escape(curl, value.c_str(), static_cast<int>(value.size()));
    if (encoded == nullptr) {
        throw std::runtime_error("Failed to URL encode value.");
    }

    std::string result(encoded);
    curl_free(encoded);
    return result;
}

std::string iso_utc_time(std::chrono::system_clock::time_point value) {
    const std::time_t raw_time = std::chrono::system_clock::to_time_t(value);
    std::tm utc_time{};
#if defined(_WIN32)
    gmtime_s(&utc_time, &raw_time);
#else
    gmtime_r(&raw_time, &utc_time);
#endif

    std::ostringstream out;
    out << std::put_time(&utc_time, "%Y-%m-%dT%H:%M:%S.000Z");
    return out.str();
}

HttpResponse http_get(const std::string& url, const std::vector<std::string>& headers = {}) {
    CURL* curl = curl_easy_init();
    if (curl == nullptr) {
        throw std::runtime_error("Unable to initialize libcurl.");
    }

    std::string body;
    curl_slist* header_list = nullptr;
    for (const auto& header : headers) {
        header_list = curl_slist_append(header_list, header.c_str());
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "cve-monitor/1.0");
    if (header_list != nullptr) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
    }

    const CURLcode code = curl_easy_perform(curl);
    long status_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);

    if (header_list != nullptr) {
        curl_slist_free_all(header_list);
    }
    curl_easy_cleanup(curl);

    if (code != CURLE_OK) {
        throw std::runtime_error(std::string("HTTP request failed: ") + curl_easy_strerror(code));
    }

    return {status_code, body};
}

std::string build_nvd_url(const Options& options) {
    CURL* curl = curl_easy_init();
    if (curl == nullptr) {
        throw std::runtime_error("Unable to initialize libcurl for URL creation.");
    }

    std::ostringstream url;
    url << NVD_CVE_API << "?resultsPerPage=" << options.limit;

    if (options.cve_id.has_value()) {
        url << "&cveId=" << url_encode(curl, *options.cve_id);
    } else {
        const auto now = std::chrono::system_clock::now();
        const auto start = now - std::chrono::hours(24 * options.days);
        url << "&pubStartDate=" << url_encode(curl, iso_utc_time(start));
        url << "&pubEndDate=" << url_encode(curl, iso_utc_time(now));
    }

    if (options.keyword.has_value()) {
        url << "&keywordSearch=" << url_encode(curl, *options.keyword);
    }
    if (options.severity.has_value()) {
        url << "&cvssV3Severity=" << url_encode(curl, *options.severity);
    }

    curl_easy_cleanup(curl);
    return url.str();
}

std::string first_description(const json& cve) {
    for (const auto& item : cve.value("descriptions", json::array())) {
        if (item.value("lang", "") == "en") {
            return item.value("value", "");
        }
    }
    return "No English description provided.";
}

void apply_cvss(CveFinding& finding, const json& metrics) {
    const std::vector<std::string> metric_keys = {"cvssMetricV31", "cvssMetricV30", "cvssMetricV2"};
    for (const auto& key : metric_keys) {
        if (!metrics.contains(key) || metrics[key].empty()) {
            continue;
        }

        const auto& metric = metrics[key][0];
        const auto& cvss_data = metric.value("cvssData", json::object());
        finding.severity = metric.value("baseSeverity", cvss_data.value("baseSeverity", "UNKNOWN"));
        finding.score = cvss_data.value("baseScore", 0.0);
        return;
    }
}

std::vector<CveFinding> parse_nvd_findings(const json& payload) {
    std::vector<CveFinding> findings;
    for (const auto& item : payload.value("vulnerabilities", json::array())) {
        const auto& cve = item.value("cve", json::object());
        CveFinding finding;
        finding.id = cve.value("id", "");
        finding.published = cve.value("published", "");
        finding.last_modified = cve.value("lastModified", "");
        finding.description = first_description(cve);
        apply_cvss(finding, cve.value("metrics", json::object()));

        if (cve.contains("references")) {
            const auto& references = cve["references"];
            const json reference_items = references.is_array()
                                             ? references
                                             : references.value("referenceData", json::array());

            for (const auto& ref : reference_items) {
                const std::string url = ref.value("url", "");
                if (!url.empty() && finding.references.size() < 3) {
                    finding.references.push_back(url);
                }
            }
        }

        findings.push_back(finding);
    }

    std::sort(findings.begin(), findings.end(), [](const CveFinding& left, const CveFinding& right) {
        if (left.score == right.score) {
            return left.published > right.published;
        }
        return left.score > right.score;
    });

    return findings;
}

std::map<std::string, json> fetch_kev_catalog() {
    const auto response = http_get(CISA_KEV_JSON);
    if (response.status_code < 200 || response.status_code >= 300) {
        throw std::runtime_error("CISA KEV request returned HTTP " + std::to_string(response.status_code));
    }

    const json payload = json::parse(response.body);
    std::map<std::string, json> kev_by_cve;
    for (const auto& item : payload.value("vulnerabilities", json::array())) {
        const std::string cve_id = item.value("cveID", "");
        if (!cve_id.empty()) {
            kev_by_cve[cve_id] = item;
        }
    }
    return kev_by_cve;
}

void annotate_with_kev(std::vector<CveFinding>& findings, const std::map<std::string, json>& kev_by_cve) {
    for (auto& finding : findings) {
        const auto match = kev_by_cve.find(finding.id);
        if (match == kev_by_cve.end()) {
            continue;
        }

        finding.known_exploited = true;
        finding.kev_due_date = match->second.value("dueDate", "");
        finding.kev_action = match->second.value("requiredAction", "");
    }
}

std::vector<CveFinding> fetch_findings(const Options& options) {
    std::vector<std::string> headers = {"Accept: application/json"};
    if (options.api_key.has_value() && !options.api_key->empty()) {
        headers.push_back("apiKey: " + *options.api_key);
    }

    const auto response = http_get(build_nvd_url(options), headers);
    if (response.status_code < 200 || response.status_code >= 300) {
        throw std::runtime_error("NVD request returned HTTP " + std::to_string(response.status_code) +
                                 ". If you are being rate limited, set NVD_API_KEY.");
    }

    auto findings = parse_nvd_findings(json::parse(response.body));
    if (options.include_kev) {
        annotate_with_kev(findings, fetch_kev_catalog());
    }
    return findings;
}

json finding_to_json(const CveFinding& finding) {
    return {
        {"id", finding.id},
        {"published", finding.published},
        {"lastModified", finding.last_modified},
        {"severity", finding.severity},
        {"score", finding.score},
        {"description", finding.description},
        {"knownExploited", finding.known_exploited},
        {"kevDueDate", finding.kev_due_date},
        {"kevRequiredAction", finding.kev_action},
        {"references", finding.references},
    };
}

void print_json_report(const std::vector<CveFinding>& findings) {
    json report;
    report["generatedAt"] = iso_utc_time(std::chrono::system_clock::now());
    report["total"] = findings.size();
    report["findings"] = json::array();
    for (const auto& finding : findings) {
        report["findings"].push_back(finding_to_json(finding));
    }

    std::cout << report.dump(2) << '\n';
}

void print_text_report(const std::vector<CveFinding>& findings) {
    std::cout << "================================================================================\n";
    std::cout << "CVE MONITORING REPORT\n";
    std::cout << "================================================================================\n";
    std::cout << "Generated: " << iso_utc_time(std::chrono::system_clock::now()) << "\n";
    std::cout << "Findings:  " << findings.size() << "\n\n";

    if (findings.empty()) {
        std::cout << "No CVEs matched the current filters.\n";
        return;
    }

    for (const auto& finding : findings) {
        std::cout << "[" << finding.severity << " " << finding.score << "] " << finding.id;
        if (finding.known_exploited) {
            std::cout << "  KEV";
        }
        std::cout << "\n";
        std::cout << "Published: " << finding.published << "\n";
        std::cout << "Modified:  " << finding.last_modified << "\n";
        std::cout << "Summary:   " << finding.description << "\n";

        if (finding.known_exploited) {
            std::cout << "CISA KEV:  Known exploited vulnerability";
            if (!finding.kev_due_date.empty()) {
                std::cout << " | Due: " << finding.kev_due_date;
            }
            std::cout << "\n";
            if (!finding.kev_action.empty()) {
                std::cout << "Action:    " << finding.kev_action << "\n";
            }
        }

        if (!finding.references.empty()) {
            std::cout << "References:\n";
            for (const auto& ref : finding.references) {
                std::cout << "  - " << ref << "\n";
            }
        }
        std::cout << "\n";
    }
}

std::string uppercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });
    return value;
}

void print_usage(const char* executable) {
    std::cout << "CVE Monitor - query NVD CVE data and CISA KEV exploit status\n\n";
    std::cout << "Usage:\n";
    std::cout << "  " << executable << " [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --cve CVE-ID              Look up one CVE, e.g. CVE-2024-3094\n";
    std::cout << "  --keyword TEXT            Search CVE descriptions by keyword\n";
    std::cout << "  --severity LEVEL          Filter by LOW, MEDIUM, HIGH, or CRITICAL\n";
    std::cout << "  --days N                  Search CVEs published in the last N days (default: 7)\n";
    std::cout << "  --limit N                 Max NVD results to request (default: 20)\n";
    std::cout << "  --api-key KEY             NVD API key; can also use NVD_API_KEY env var\n";
    std::cout << "  --no-kev                  Skip CISA KEV enrichment\n";
    std::cout << "  --json                    Print machine-readable JSON\n";
    std::cout << "  --watch-minutes N         Re-run the same query every N minutes\n";
    std::cout << "  --help                    Show this help\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << executable << " --days 3 --severity CRITICAL\n";
    std::cout << "  " << executable << " --keyword openssl --limit 10\n";
    std::cout << "  " << executable << " --cve CVE-2024-3094 --json\n";
}

Options parse_args(int argc, char* argv[]) {
    Options options;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto require_value = [&](const std::string& name) -> std::string {
            if (i + 1 >= argc) {
                throw std::invalid_argument(name + " requires a value.");
            }
            return argv[++i];
        };

        if (arg == "--cve") {
            options.cve_id = uppercase(require_value(arg));
        } else if (arg == "--keyword") {
            options.keyword = require_value(arg);
        } else if (arg == "--severity") {
            options.severity = uppercase(require_value(arg));
        } else if (arg == "--days") {
            options.days = std::stoi(require_value(arg));
        } else if (arg == "--limit") {
            options.limit = std::stoi(require_value(arg));
        } else if (arg == "--api-key") {
            options.api_key = require_value(arg);
        } else if (arg == "--json") {
            options.json_output = true;
        } else if (arg == "--no-kev") {
            options.include_kev = false;
        } else if (arg == "--watch-minutes") {
            options.watch_minutes = std::stoi(require_value(arg));
        } else if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            std::exit(0);
        } else {
            throw std::invalid_argument("Unknown argument: " + arg);
        }
    }

    if (!options.api_key.has_value()) {
        const std::string env_key = get_env("NVD_API_KEY");
        if (!env_key.empty()) {
            options.api_key = env_key;
        }
    }

    if (options.days < 1 || options.days > 120) {
        throw std::invalid_argument("--days must be between 1 and 120.");
    }
    if (options.limit < 1 || options.limit > 2000) {
        throw std::invalid_argument("--limit must be between 1 and 2000.");
    }
    if (options.watch_minutes < 0) {
        throw std::invalid_argument("--watch-minutes cannot be negative.");
    }
    if (options.severity.has_value()) {
        static const std::set<std::string> allowed = {"LOW", "MEDIUM", "HIGH", "CRITICAL"};
        if (allowed.count(*options.severity) == 0) {
            throw std::invalid_argument("--severity must be LOW, MEDIUM, HIGH, or CRITICAL.");
        }
    }

    return options;
}

}  // namespace

int main(int argc, char* argv[]) {
    try {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        const Options options = parse_args(argc, argv);

        do {
            const auto findings = fetch_findings(options);
            if (options.json_output) {
                print_json_report(findings);
            } else {
                print_text_report(findings);
            }

            if (options.watch_minutes > 0) {
                std::cerr << "Waiting " << options.watch_minutes << " minute(s) before next check...\n";
                std::this_thread::sleep_for(std::chrono::minutes(options.watch_minutes));
            }
        } while (options.watch_minutes > 0);

        curl_global_cleanup();
        return 0;
    } catch (const std::exception& error) {
        curl_global_cleanup();
        std::cerr << "Error: " << error.what() << "\n\n";
        print_usage(argv[0]);
        return 1;
    }
}
