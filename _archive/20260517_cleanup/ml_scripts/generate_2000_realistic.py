import csv
import random
import urllib.parse

OUTPUT_FILE = "augmented_attack_dataset.csv"
NUM_SAMPLES = 2000

methods = ["GET", "POST"]
paths = ["/search", "/login", "/api/data", "/file", "/product", "/submit"]

headers = "User-Agent: Chrome/120.0; Content-Type: application/x-www-form-urlencoded"

# ===== Attack payloads =====
xss_payloads = [
    "<script>alert(1)</script>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "<img src=x onerror=alert(1)>",
    "\" onmouseover=alert(1) x=\"",
]

sqli_payloads = [
    "' OR '1'='1",
    "UNION SELECT password FROM users",
    "UN/**/ION SEL/**/ECT",
    "' OR 1=1--",
]

cmd_payloads = [
    "127.0.0.1; ls",
    "127.0.0.1 && whoami",
    "127.0.0.1 | cat /etc/passwd",
]

path_payloads = [
    "../../etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

# ===== Normal tricky payloads =====
normal_tricky = [
    "selectproduct",
    "javascript_book",
    "union_jacket",
    "scripture_notes",
]

def random_string():
    return ''.join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(5, 20)))

def generate_row():
    method = random.choice(methods)
    path = random.choice(paths)

    rand = random.random()

    # 70% normal (realistic)
    if rand < 0.7:
        label = "normal"
        attack_type = "Normal"

        if random.random() < 0.5:
            query = random.choice(normal_tricky)
        else:
            query = random_string()

        body = "" if method == "GET" else f"data={random_string()}"

    else:
        label = "attack"

        attack_choice = random.choice(["XSS", "SQL Injection", "Command Injection", "Path Traversal"])

        if attack_choice == "XSS":
            payload = random.choice(xss_payloads)
        elif attack_choice == "SQL Injection":
            payload = random.choice(sqli_payloads)
        elif attack_choice == "Command Injection":
            payload = random.choice(cmd_payloads)
        else:
            payload = random.choice(path_payloads)

        attack_type = attack_choice

        if method == "GET":
            query = payload
            body = ""
        else:
            query = ""
            body = f"data={payload}"

    request_raw = f"{method} {path}?{query} HTTP/1.1"

    return [
        request_raw,
        method,
        path,
        query,
        body,
        headers,
        label,
        attack_type
    ]

def main():
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        writer.writerow([
            "request_raw",
            "method",
            "path",
            "query_params",
            "body",
            "headers",
            "label",
            "attack_type"
        ])

        for _ in range(NUM_SAMPLES):
            writer.writerow(generate_row())

    print(f"✅ Generated {NUM_SAMPLES} rows → {OUTPUT_FILE}")

if __name__ == "__main__":
    main()