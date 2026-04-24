import os
import random
from collections import Counter
from urllib.parse import parse_qsl, quote, urlencode

import numpy as np
import pandas as pd


COLUMNS = [
    "request_raw",
    "method",
    "path",
    "query_params",
    "body",
    "headers",
    "label",
    "attack_type",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Chrome/120.0",
    "Edge/120.0",
    "Safari/537.36",
]

PATH_SEGMENTS = [
    "course",
    "mod",
    "forum",
    "assign",
    "profile",
    "calendar",
    "grade",
    "message",
    "backup",
    "report",
    "view",
    "edit",
    "export",
    "import",
    "search",
    "api",
    "v2",
    "ajax",
]

BENIGN_SUSPICIOUS_VALUES = [
    "select course materials",
    "drop by later",
    "script for class presentation",
    "union student clubs",
    "sleep schedule tips",
    "onload workshop notes",
    "../resources/week1/notes.pdf",
    "cmd command reference",
    "admin dashboard guide",
    "how to use onerror handler safely",
    "path traversal explained in class",
    "normalize query params for report",
]

SAFE_PARAM_KEYS = [
    "q",
    "search",
    "keyword",
    "topic",
    "lang",
    "page",
    "sort",
    "view",
    "tab",
    "courseid",
    "section",
    "module",
    "id",
    "next",
    "redirect",
    "format",
]

SAFE_PARAM_VALUES = [
    "intro",
    "advanced",
    "week-1",
    "assignment",
    "discussion",
    "latest",
    "popular",
    "en",
    "id",
    "json",
    "html",
    "compact",
    "full",
    "notes",
    "overview",
    "course-101",
]

XSS_PAYLOADS = [
    "<ScRiPt>alert(1)</sCrIpT>",
    "%3Cscript%3Ealert%281%29%3C/script%3E",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=confirm(1)>",
    "\"><body onload=prompt(1)>",
    "<details open ontoggle=alert(1)>",
    "<math href=javascript:alert(1)>",
    "<iframe srcdoc='<img src=x onerror=alert(1)>'>",
]

SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "'/**/oR/**/1=1--",
    "1 uni/**/on sel/**/ect 1,2",
    "admin' AND SLEEP(5)--",
    "' OR '1'='1' #",
    "1;WAITFOR DELAY '0:0:3'--",
    "' AnD (SeLeCt 1)=1 --",
    "' OR EXISTS(SELECT 1) --",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//windows/win.ini",
    "..\\..\\..\\..\\boot.ini",
    "..%252f..%252f..%252fetc%252fshadow",
    "../../moodle/config.php",
]

COMMAND_INJECTION_PAYLOADS = [
    "; ls -la",
    "&& whoami",
    "| id",
    "`cat /etc/passwd`",
    "$(uname -a)",
    "; ping -c 1 127.0.0.1",
    "&& powershell -Command Get-Process",
]

RFI_PAYLOADS = [
    "http://example.org/safe.txt",
    "https://cdn.example.org/theme.php",
    "http://localhost/mock.php",
    "https://raw.githubusercontent.com/example/demo/main/a.php",
]

CSRF_STYLE_PAYLOADS = [
    "token=missing&confirm=1",
    "csrf=none&action=change_email",
    "nonce=0000&transfer=1",
    "session=stale&submit=1",
]


def _resolve_input_path(filename: str) -> str:
    candidates = [
        filename,
        os.path.join("proxy", "ml", "training_data", filename),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    raise FileNotFoundError(f"Input file not found: {filename}")


def _resolve_output_path(filename: str) -> str:
    if os.path.dirname(filename):
        return filename
    return os.path.join("proxy", "ml", "training_data", filename)


def _safe_text(value) -> str:
    if pd.isna(value):
        return ""
    return str(value)


def _parse_pairs(text: str) -> dict:
    value = _safe_text(text).strip()
    if not value:
        return {}
    if value.startswith("?"):
        value = value[1:]
    if "=" not in value:
        return {"data": value}
    return {k: v for k, v in parse_qsl(value, keep_blank_values=True)}


def _headers(rng: random.Random) -> str:
    parts = [f"User-Agent: {rng.choice(USER_AGENTS)}"]
    if rng.random() < 0.9:
        parts.append(f"Content-Type: {rng.choice(['application/x-www-form-urlencoded', 'application/json', 'text/plain'])}")
    if rng.random() < 0.8:
        parts.append(f"Accept-Language: {rng.choice(['en-US,en;q=0.9', 'id-ID,id;q=0.9,en;q=0.8', 'en-GB,en;q=0.8'])}")
    if rng.random() < 0.45:
        parts.append(f"Referer: {rng.choice(['/course/view.php', '/login/index.php', '/mod/forum/post.php'])}")
    if rng.random() < 0.35:
        parts.append(f"Cookie: MoodleSession={rng.randint(100000, 999999)}")
    if rng.random() < 0.25:
        parts.append("X-Requested-With: XMLHttpRequest")
    if rng.random() < 0.20:
        parts.append(f"X-Forwarded-For: 10.0.{rng.randint(0, 255)}.{rng.randint(1, 254)}")
    return "; ".join(parts)


def _mutate_path(path: str, rng: random.Random, attack: bool) -> str:
    raw = _safe_text(path).strip()
    if not raw.startswith("/"):
        raw = "/" + raw if raw else "/course/view.php"

    segments = [seg for seg in raw.split("/") if seg]
    if not segments:
        segments = ["course", "view.php"]

    add_depth = rng.randint(1, 4) if attack else rng.randint(0, 3)
    for _ in range(add_depth):
        segments.insert(max(1, len(segments) - 1), rng.choice(PATH_SEGMENTS))

    if rng.random() < 0.3:
        segments.insert(0, f"v{rng.randint(1, 3)}")

    return "/" + "/".join(segments)


def _compose_request_raw(method: str, path: str, query: str, body: str) -> str:
    first = f"{method} {path}" + (f"?{query}" if query else "")
    if body:
        return f"{first} BODY:{body}"
    return first


def _choose_payload(attack_type: str, rng: random.Random) -> str:
    normalized = _safe_text(attack_type).strip().lower()
    if "xss" in normalized:
        pool = XSS_PAYLOADS
    elif "sql" in normalized:
        pool = SQLI_PAYLOADS
    elif "path" in normalized or "lfi" in normalized:
        pool = PATH_TRAVERSAL_PAYLOADS
    elif "command" in normalized or "cmd" in normalized:
        pool = COMMAND_INJECTION_PAYLOADS
    elif "rfi" in normalized:
        pool = RFI_PAYLOADS
    elif "csrf" in normalized:
        pool = CSRF_STYLE_PAYLOADS
    else:
        pool = XSS_PAYLOADS + SQLI_PAYLOADS + PATH_TRAVERSAL_PAYLOADS
    return rng.choice(pool)


def _inject_noise_params(params: dict, rng: random.Random, attack: bool) -> dict:
    result = dict(params)
    extra_count = rng.randint(2, 8)
    for _ in range(extra_count):
        key = rng.choice(SAFE_PARAM_KEYS)
        if attack and rng.random() < 0.35:
            value = rng.choice(BENIGN_SUSPICIOUS_VALUES)
        else:
            value = f"{rng.choice(SAFE_PARAM_VALUES)}-{rng.randint(1, 99)}"
        if rng.random() < 0.35:
            value = quote(value, safe="")
        result[key] = value
    return result


def _build_attack_variant(row: dict, rng: random.Random, force_type: str = "") -> dict:
    attack_type = force_type or _safe_text(row.get("attack_type", "")).strip() or "XSS"
    method = rng.choice(["GET", "POST"])
    path = _mutate_path(row.get("path", ""), rng, attack=True)
    payload = _choose_payload(attack_type, rng)

    query_params = _parse_pairs(row.get("query_params", ""))
    body_params = _parse_pairs(row.get("body", ""))

    target_key = rng.choice(["q", "id", "file", "path", "search", "next", "url", "cmd", "redirect"])
    mode = rng.choices(["query", "body", "both"], weights=[0.50, 0.25, 0.25], k=1)[0]

    if mode in {"query", "both"}:
        query_params[target_key] = payload
    if mode in {"body", "both"}:
        body_params[target_key] = payload

    if rng.random() < 0.12:
        cross_payload = _choose_payload(rng.choice(["XSS", "SQLi", "Path Traversal"]), rng)
        if mode == "query":
            body_params["note"] = cross_payload
        else:
            query_params["note"] = cross_payload

    query_params = _inject_noise_params(query_params, rng, attack=True)
    if rng.random() < 0.30:
        query_params["comment"] = rng.choice(BENIGN_SUSPICIOUS_VALUES)

    if method == "POST" and not body_params:
        body_params["data"] = payload

    if method == "GET" and rng.random() < 0.65:
        body_params = {}

    query_text = urlencode(query_params, doseq=True, safe="/:@-_.~*()!$,'")
    body_text = urlencode(body_params, doseq=True, safe="/:@-_.~*()!$,'") if body_params else ""
    headers = _headers(rng)

    return {
        "request_raw": _compose_request_raw(method, path, query_text, body_text),
        "method": method,
        "path": path,
        "query_params": query_text,
        "body": body_text,
        "headers": headers,
        "label": "attack",
        "attack_type": attack_type,
    }


def _build_hard_negative(seed_row: dict, rng: random.Random) -> dict:
    method = rng.choice(["GET", "POST"])
    path = _mutate_path(seed_row.get("path", "/course/view.php"), rng, attack=False)

    query_params = _parse_pairs(seed_row.get("query_params", ""))
    body_params = _parse_pairs(seed_row.get("body", ""))

    suspicious_key = rng.choice(["search", "note", "comment", "topic", "query", "description"])
    query_params[suspicious_key] = rng.choice(BENIGN_SUSPICIOUS_VALUES)

    query_params = _inject_noise_params(query_params, rng, attack=False)
    if rng.random() < 0.35:
        query_params["deep_path"] = quote("../docs/course-outline.pdf", safe="")

    if method == "POST":
        if not body_params or rng.random() < 0.85:
            body_params = {
                "message": rng.choice(BENIGN_SUSPICIOUS_VALUES),
                "details": f"section-{rng.randint(1, 15)}",
            }
        if rng.random() < 0.25:
            body_params["hint"] = "use select wisely in SQL lesson"
    else:
        body_params = {}

    query_text = urlencode(query_params, doseq=True, safe="/:@-_.~*()!$,'")
    body_text = urlencode(body_params, doseq=True, safe="/:@-_.~*()!$,'") if body_params else ""
    headers = _headers(rng)

    return {
        "request_raw": _compose_request_raw(method, path, query_text, body_text),
        "method": method,
        "path": path,
        "query_params": query_text,
        "body": body_text,
        "headers": headers,
        "label": "normal",
        "attack_type": "normal",
    }


def _validate_columns(df: pd.DataFrame):
    missing = [col for col in COLUMNS if col not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")


def main():
    rng = random.Random(42)
    np.random.seed(42)

    input_path = _resolve_input_path("moodle_attack_dataset.csv")
    output_path = _resolve_output_path("moodle_attack_dataset_augmented.csv")

    df = pd.read_csv(input_path)
    _validate_columns(df)
    df = df[COLUMNS].copy()

    for col in COLUMNS:
        df[col] = df[col].fillna("").astype(str)

    attack_df = df[df["label"].str.strip().str.lower() == "attack"].copy()
    normal_df = df[df["label"].str.strip().str.lower() == "normal"].copy()

    if attack_df.empty:
        raise ValueError("No attack rows found in source dataset.")

    original_attack_counts = Counter(attack_df["attack_type"].tolist())
    attack_rows = attack_df.to_dict(orient="records")
    normal_rows = normal_df.to_dict(orient="records")

    generated_attack = []
    for row in attack_rows:
        generated_attack.append(_build_attack_variant(row, rng))

    current_attack_counts = Counter(attack_df["attack_type"].tolist()) + Counter(
        [row["attack_type"] for row in generated_attack]
    )

    xss_target = max(current_attack_counts.get("XSS", 0), int(np.ceil(original_attack_counts.get("XSS", 0) * 4.6)))
    sqli_target = max(current_attack_counts.get("SQLi", 0), int(np.ceil(original_attack_counts.get("SQLi", 0) * 4.6)))
    command_target = max(current_attack_counts.get("Command Injection", 0), int(np.ceil(np.median(list(original_attack_counts.values())) * 1.2)))

    for attack_type, target_count in [("XSS", xss_target), ("SQLi", sqli_target), ("Command Injection", command_target)]:
        need = target_count - current_attack_counts.get(attack_type, 0)
        if need <= 0:
            continue

        if attack_type in {"XSS", "SQLi"}:
            pool_df = attack_df[attack_df["attack_type"] == attack_type]
            pool = pool_df.to_dict(orient="records") if not pool_df.empty else attack_rows
        else:
            pool = attack_rows

        for _ in range(need):
            seed = rng.choice(pool)
            generated_attack.append(_build_attack_variant(seed, rng, force_type=attack_type))

        current_attack_counts[attack_type] = target_count

    attack_final_count = len(attack_df) + len(generated_attack)
    normal_target_ratio = 0.40
    target_normal_total = int(np.ceil((normal_target_ratio / (1.0 - normal_target_ratio)) * attack_final_count))
    hard_negative_needed = max(0, target_normal_total - len(normal_df))

    if not normal_rows:
        normal_rows = df.to_dict(orient="records")

    hard_negatives = []
    for _ in range(hard_negative_needed):
        hard_negatives.append(_build_hard_negative(rng.choice(normal_rows), rng))

    augmented_df = pd.concat(
        [
            df,
            pd.DataFrame(generated_attack, columns=COLUMNS),
            pd.DataFrame(hard_negatives, columns=COLUMNS),
        ],
        ignore_index=True,
    )

    augmented_df = augmented_df[COLUMNS].sample(frac=1.0, random_state=42).reset_index(drop=True)

    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    augmented_df.to_csv(output_path, index=False)

    print(f"Saved: {output_path}")
    print(f"total samples: {len(augmented_df)}")
    attack_type_counts = augmented_df["attack_type"].value_counts().to_dict()
    print(f"samples per attack_type: {attack_type_counts}")

    min_count = int(min(attack_type_counts.values())) if attack_type_counts else 0
    print(f"min class count: {min_count}")
    if min_count < 100:
        print("warning: some classes are still small")
    else:
        print("class balance check: no extremely small classes")


if __name__ == "__main__":
    main()
