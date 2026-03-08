#include <chrono>
#include <curl/curl.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
// Note: You will need to bring in nlohmann/json.hpp
#include "../include/json.hpp"

// Minimal Skeleton for the C++ Log Agent (SIEM prototype)

void send_to_elasticsearch(const std::string &json_data) {
  CURL *curl;
  CURLcode res;
  curl = curl_easy_init();
  if (curl) {
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    // By default use Elasticsearch Docker container hostname, fallback to
    // localhost if standalone
    const char *env_url = std::getenv("ELASTICSEARCH_URL");
    std::string es_url =
        env_url ? std::string(env_url) : "http://localhost:9200";
    es_url += "/siem-events/_doc/";

    curl_easy_setopt(curl, CURLOPT_URL, es_url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data.c_str());

    // Perform the request
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
      std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res)
                << "\n";
    }

    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
  }
}

void tail_file(const std::string &filepath) {
  std::ifstream file(filepath);
  if (!file.is_open()) {
    std::cerr << "Failed to open " << filepath << "\n";
    return;
  }

  // Seek to the end for production, or beginning for testing
  file.seekg(0, std::ios::end);

  std::string line;
  std::cout << "Monitoring " << filepath << "...\n";

  while (true) {
    if (std::getline(file, line)) {
      // Process the appended line
      std::cout << "Read line: " << line << "\n";

      // Step 1 - Parsing logic (e.g., standard SSH auth failure)
      if (line.find("Failed password") != std::string::npos) {
        std::string username = "unknown";
        std::string source_ip = "unknown";

        size_t user_start = line.find("for ");
        if (user_start != std::string::npos &&
            line.find("invalid user ", user_start) != std::string::npos) {
          user_start = line.find("invalid user ") + 13;
        } else if (user_start != std::string::npos) {
          user_start += 4;
        }

        size_t from_start = line.find(" from ");
        if (user_start != std::string::npos &&
            from_start != std::string::npos) {
          username = line.substr(user_start, from_start - user_start);
        }

        size_t port_start = line.find(" port ", from_start);
        if (from_start != std::string::npos &&
            port_start != std::string::npos) {
          source_ip =
              line.substr(from_start + 6, port_start - (from_start + 6));
        }

        // Generate Current ISO-8601 Timestamp
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%dT%H:%M:%SZ");
        std::string timestamp = ss.str();

        // Rules Evaluation Settings
        std::string event_type = "failed_login";
        std::string severity = "medium";
        std::string message = "Detected failed SSH login.";

        // Static trackers to maintain state across loop iterations
        static std::map<std::string, int> failed_attempts;
        static std::vector<std::string> blocked_ips = {"10.0.0.50",
                                                       "192.168.100.100"};

        // RULE 2: Blocked IP Check
        bool is_blocked = false;
        for (const auto &blocked_ip : blocked_ips) {
          if (source_ip == blocked_ip) {
            is_blocked = true;
            break;
          }
        }

        if (is_blocked) {
          event_type = "blocked_ip_access";
          severity = "critical";
          message = "ALERT: Access attempt from known BLOCKED IP address!";
        } else {
          // RULE 1: Brute Force Detection
          failed_attempts[source_ip]++;
          if (failed_attempts[source_ip] >= 5) {
            event_type = "brute_force_attempt";
            severity = "high";
            message = "ALERT: Brute force detected! 5 or more failed logins "
                      "from this IP.";
            // Reset counter so it doesn't spam infinitely after triggering once
            failed_attempts[source_ip] = 0;
          }
        }

        // Construct Final JSON String using nlohmann/json
        nlohmann::json event;
        event["timestamp"] = timestamp;
        event["host"] = "agent-node";
        event["event_type"] = event_type;
        event["source_ip"] = source_ip;
        event["target_user"] = username;
        event["severity"] = severity;
        event["message"] = message;

        std::string eventPayload = event.dump();

        std::cout << "[SIEM] Dispatching payload -> Event Type: " << event_type
                  << " | IP: " << source_ip << "\n";
        send_to_elasticsearch(eventPayload);
      }

    } else {
      // No new lines, wait slightly and try again
      file.clear(); // Clear the EOF flag
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
  }
}

int main(int argc, char *argv[]) {
  // Unbuffer stdout and stderr so Docker picks up logs immediately
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  curl_global_init(CURL_GLOBAL_ALL);

  // Default file path for Docker container mount
  std::string logFilePath = "/var/log/siem_test/test_auth.log";

  // Override if provided via command line
  if (argc > 1) {
    logFilePath = argv[1];
  } else {
    // Auto-create a dummy test log if it does not exist (so tailing doesnt
    // immediately fail)
    std::ofstream dummy_log(logFilePath, std::ios::app);
    dummy_log.close();
  }

  tail_file(logFilePath);

  curl_global_cleanup();
  return 0;
}
