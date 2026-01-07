# // [
# //     {
# //         "id": "NGINX_HIGH_REQUEST_RATE",
# //         "description": "High request rate from single IP",
# //         "source": "nginx",
# //         "match": {
# //             "field": "src_ip"
# //         },
# //         "condition": {
# //             "type": "count",
# //             "threshold": 100,
# //             "window": 60
# //         },
# //         "severity": "medium",
# //         "run_agent": false
# //     },
# //     {
# //         "id": "NGINX_XSS_ATTEMPT",
# //         "description": "Cross-site scripting attempt",
# //         "source": "nginx",
# //         "match": {
# //             "request_contains": [
# //                 "<script",
# //                 "javascript:",
# //                 "onerror=",
# //                 "onload="
# //             ]
# //         },
# //         "severity": "high",
# //         "run_agent": true
# //     },
# //     {
# //         "id": "NGINX_PATH_TRAVERSAL",
# //         "description": "Path traversal attempt",
# //         "source": "nginx",
# //         "match": {
# //             "request_contains": [
# //                 "../",
# //                 "..%2f",
# //                 "%2e%2e%2f",
# //                 "/etc/passwd"
# //             ]
# //         },
# //         "severity": "high",
# //         "run_agent": true
# //     },
# //     {
# //         "id": "NGINX_SUSPICIOUS_USER_AGENT",
# //         "description": "Suspicious user-agent detected",
# //         "source": "nginx",
# //         "match": {
# //             "user_agent_contains": [
# //                 "curl",
# //                 "wget",
# //                 "python",
# //                 "go-http-client",
# //                 "sqlmap",
# //                 "nikto"
# //             ]
# //         },
# //         "severity": "medium",
# //         "run_agent": false
# //     },
# //     {
# //         "id": "NGINX_TOO_MANY_404",
# //         "description": "Excessive 404 responses from single IP",
# //         "source": "nginx",
# //         "match": {
# //             "field": "src_ip"
# //         },
# //         "condition": {
# //             "type": "status_count",
# //             "status": 404,
# //             "threshold": 50,
# //             "window": 120
# //         },
# //         "severity": "medium",
# //         "run_agent": false
# //     },
# //     {
# //         "id": "NGINX_SLOW_REQUEST",
# //         "description": "Slow request may indicate abuse",
# //         "source": "nginx",
# //         "match": {
# //             "request_time_gt": 5
# //         },
# //         "severity": "low",
# //         "run_agent": false
# //     },
# //     {
# //         "id": "NGINX_ADMIN_PANEL_PROBE",
# //         "description": "Admin panel probing attempt",
# //         "source": "nginx",
# //         "match": {
# //             "request_contains": [
# //                 "/admin",
# //                 "/wp-admin",
# //                 "/phpmyadmin",
# //                 "/manager/html"
# //             ]
# //         },
# //         "severity": "high",
# //         "run_agent": true
# //     },
# //     {
# //         "id": "NGINX_HTTP_METHOD_ABUSE",
# //         "description": "Suspicious HTTP method usage",
# //         "source": "nginx",
# //         "match": {
# //             "method_not_in": [
# //                 "GET",
# //                 "POST",
# //                 "HEAD"
# //             ]
# //         },
# //         "severity": "medium",
# //         "run_agent": false
# //     }
# // ]