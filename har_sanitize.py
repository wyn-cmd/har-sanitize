#!/usr/bin/env python3
# har_sanitize strips credentials and personal data out of HTTP Archive files.
# Three modes: redact writes a cleaned copy, check reports secrets and exits
# non-zero, summary describes what the capture actually contains.

import argparse
import copy
import json
import re
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "[REDACTED]"

# Header names whose whole value is a credential. Compared case-insensitively.
SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-access-token",
    "x-session-id",
    "x-csrf-token",
    "x-xsrf-token",
    "x-amz-security-token",
    "x-goog-api-key",
    "private-token",
}

# Substrings that mark a parameter or JSON key as secret bearing.
SENSITIVE_WORDS = (
    "token",
    "secret",
    "password",
    "passwd",
    "passphrase",
    "apikey",
    "api_key",
    "api-key",
    "auth",
    "signature",
    "session",
    "credential",
    "private_key",
    "access_key",
)

# Ordinary names that contain a sensitive substring but are not secrets.
SAFE_NAMES = {"author", "authors", "authority", "authenticity"}

# Free text patterns worth scrubbing inside body content.
BEARER_RE = re.compile(r"(?i)\b(bearer\s+)([A-Za-z0-9\-._~+/]{8,}=*)")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def is_sensitive_name(name):
    # Normalise first, then look for credential words inside the name so that
    # access_token_v2, X-Api-Key and client_secret_hash all get caught.
    lowered = str(name).strip().lower()
    if lowered in SAFE_NAMES:
        return False
    if lowered in SENSITIVE_HEADERS:
        return True
    for word in SENSITIVE_WORDS:
        if word in lowered:
            return True
    return False


def redact_headers(headers, counter):
    # HAR stores headers as a list of name/value dicts.
    if not isinstance(headers, list):
        return
    for header in headers:
        if not isinstance(header, dict):
            continue
        value = header.get("value")
        if not is_sensitive_name(header.get("name")):
            continue
        if isinstance(value, str) and value and value != REDACTED:
            header["value"] = REDACTED
            counter["headers"] += 1


def redact_cookies(cookies, counter):
    # Cookie values act as live credentials whatever the cookie is called,
    # so the value is always blanked and the name kept for readability.
    if not isinstance(cookies, list):
        return
    for cookie in cookies:
        if not isinstance(cookie, dict):
            continue
        value = cookie.get("value")
        if isinstance(value, str) and value and value != REDACTED:
            cookie["value"] = REDACTED
            counter["cookies"] += 1


def redact_query(url, counter):
    # Only the query string is rewritten, scheme host path and fragment survive.
    parts = urlsplit(url)
    if not parts.query:
        return url
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    changed = False
    rebuilt = []
    for name, value in pairs:
        if value and value != REDACTED and is_sensitive_name(name):
            rebuilt.append((name, REDACTED))
            counter["query"] += 1
            changed = True
        else:
            rebuilt.append((name, value))
    if not changed:
        return url
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(rebuilt), parts.fragment))


def redact_query_pairs(pairs, counter):
    # HAR duplicates the query string as a structured array; clean that too.
    if not isinstance(pairs, list):
        return
    for pair in pairs:
        if not isinstance(pair, dict):
            continue
        value = pair.get("value")
        if not is_sensitive_name(pair.get("name", "")):
            continue
        if isinstance(value, str) and value and value != REDACTED:
            pair["value"] = REDACTED
            counter["query"] += 1


def redact_json_value(node, counter, scrub_emails=False):
    # Walk the decoded body, blanking values under sensitive keys and scrubbing
    # free text leaves so a token pasted into an unrelated field still goes.
    if isinstance(node, dict):
        for key in list(node.keys()):
            value = node[key]
            if (
                is_sensitive_name(key)
                and isinstance(value, (str, int, float))
                and value != ""
                and value != REDACTED
            ):
                node[key] = REDACTED
                counter["body"] += 1
            elif isinstance(value, str):
                node[key] = redact_text(value, counter, scrub_emails)
            else:
                redact_json_value(value, counter, scrub_emails)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            if isinstance(item, str):
                node[index] = redact_text(item, counter, scrub_emails)
            else:
                redact_json_value(item, counter, scrub_emails)


def redact_form(text, counter):
    # Rewrite an urlencoded form body, replacing credential values.
    pairs = parse_qsl(text, keep_blank_values=True)
    changed = False
    rebuilt = []
    for name, value in pairs:
        if value and value != REDACTED and is_sensitive_name(name):
            rebuilt.append((name, REDACTED))
            counter["body"] += 1
            changed = True
        else:
            rebuilt.append((name, value))
    if not changed:
        return text
    return urlencode(rebuilt)


def redact_text(text, counter, scrub_emails=False):
    # Scrub bearer tokens and JWTs out of free text bodies.
    if not isinstance(text, str) or not text:
        return text
    changed, count = BEARER_RE.subn(lambda match: match.group(1) + REDACTED, text)
    counter["text"] += count
    changed, count = JWT_RE.subn(REDACTED, changed)
    counter["text"] += count
    if scrub_emails:
        changed, count = EMAIL_RE.subn(REDACTED, changed)
        counter["text"] += count
    return changed


def redact_body(text, mime, counter, scrub_emails):
    # One entry point for any text body: decode JSON and forms, scrub the rest.
    if not isinstance(text, str) or not text:
        return text
    mime = mime.lower()
    if "json" in mime:
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
        if parsed is not None:
            redact_json_value(parsed, counter, scrub_emails)
            return json.dumps(parsed, ensure_ascii=False)
        return redact_text(text, counter, scrub_emails)
    if "form-urlencoded" in mime:
        return redact_form(text, counter)
    return redact_text(text, counter, scrub_emails)


def redact_post_data(post_data, counter, scrub_emails):
    if not isinstance(post_data, dict):
        return
    mime = str(post_data.get("mimeType", ""))
    text = post_data.get("text")
    if isinstance(text, str) and text:
        post_data["text"] = redact_body(text, mime, counter, scrub_emails)
    params = post_data.get("params")
    if isinstance(params, list):
        for param in params:
            if not isinstance(param, dict):
                continue
            value = param.get("value")
            if is_sensitive_name(param.get("name", "")) and isinstance(value, str) and value:
                if value != REDACTED:
                    param["value"] = REDACTED
                    counter["body"] += 1


def redact_entry(entry, options, counter):
    request = entry.get("request") or {}
    response = entry.get("response") or {}

    url = request.get("url")
    if isinstance(url, str):
        request["url"] = redact_query(url, counter)

    redact_headers(request.get("headers"), counter)
    redact_cookies(request.get("cookies"), counter)
    redact_query_pairs(request.get("queryString"), counter)
    redact_post_data(request.get("postData"), counter, options.scrub_emails)

    redact_headers(response.get("headers"), counter)
    redact_cookies(response.get("cookies"), counter)

    content = response.get("content")
    if not isinstance(content, dict):
        return
    if options.drop_content:
        removed = content.get("size") or 0
        content.pop("text", None)
        content.pop("encoding", None)
        content["size"] = 0
        counter["content"] += 1
        try:
            counter["bytes"] += int(removed)
        except (TypeError, ValueError):
            pass
    else:
        text = content.get("text")
        # Base64 content is binary; decoding it would corrupt the capture.
        if isinstance(text, str) and content.get("encoding") != "base64":
            mime = str(content.get("mimeType", ""))
            content["text"] = redact_body(text, mime, counter, options.scrub_emails)


def iter_entries(har):
    log = har.get("log")
    if not isinstance(log, dict):
        return []
    entries = log.get("entries")
    return entries if isinstance(entries, list) else []


def redact_har(har, options):
    counter = {
        "headers": 0,
        "cookies": 0,
        "query": 0,
        "body": 0,
        "text": 0,
        "content": 0,
        "bytes": 0,
    }
    for entry in iter_entries(har):
        if isinstance(entry, dict):
            redact_entry(entry, options, counter)
    return counter


def total_findings(counter):
    # Dropped bodies are not secrets, so they stay out of the finding count.
    return sum(counter[key] for key in ("headers", "cookies", "query", "body", "text"))


def format_counter(counter):
    parts = []
    if counter["headers"]:
        parts.append("%d header values" % counter["headers"])
    if counter["cookies"]:
        parts.append("%d cookie values" % counter["cookies"])
    if counter["query"]:
        parts.append("%d query values" % counter["query"])
    if counter["body"]:
        parts.append("%d body fields" % counter["body"])
    if counter["text"]:
        parts.append("%d text tokens" % counter["text"])
    if counter["content"]:
        parts.append("%d response bodies dropped" % counter["content"])
    if not parts:
        return "nothing found"
    return ", ".join(parts)


def summarize(har):
    entries = [entry for entry in iter_entries(har) if isinstance(entry, dict)]
    hosts = {}
    buckets = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}
    timings = []
    total_bytes = 0
    started = None

    for entry in entries:
        request = entry.get("request") or {}
        response = entry.get("response") or {}
        content = response.get("content") or {}

        url = request.get("url") or ""
        host = urlsplit(url).netloc or "(no host)"
        size = content.get("size") or 0
        try:
            size = int(size)
        except (TypeError, ValueError):
            size = 0
        total_bytes += size

        record = hosts.setdefault(host, {"requests": 0, "bytes": 0, "errors": 0})
        record["requests"] += 1
        record["bytes"] += size

        status = response.get("status") or 0
        try:
            status = int(status)
        except (TypeError, ValueError):
            status = 0
        if 200 <= status < 300:
            buckets["2xx"] += 1
        elif 300 <= status < 400:
            buckets["3xx"] += 1
        elif 400 <= status < 500:
            buckets["4xx"] += 1
            record["errors"] += 1
        elif 500 <= status < 600:
            buckets["5xx"] += 1
            record["errors"] += 1
        else:
            buckets["other"] += 1

        started_at = entry.get("startedDateTime")
        if started is None or (started_at and started_at < started):
            started = started_at or started

        elapsed = entry.get("time") or 0
        try:
            elapsed = float(elapsed)
        except (TypeError, ValueError):
            elapsed = 0.0
        # The summary is printed to a terminal and pasted into tickets, so the
        # URL shown here loses its sensitive parameters too.
        display_url = redact_query(url, {"query": 0})
        timings.append((elapsed, str(request.get("method", "?")), display_url))

    timings.sort(reverse=True)
    slowest = [
        {"time_ms": round(elapsed, 1), "method": method, "url": url[:120]}
        for elapsed, method, url in timings[:5]
    ]
    return {
        "entries": len(entries),
        "started": started,
        "total_bytes": total_bytes,
        "hosts": hosts,
        "status": buckets,
        "slowest": slowest,
    }


def print_summary(data, stream):
    stream.write("Entries: %d\n" % data["entries"])
    if data["started"]:
        stream.write("First request: %s\n" % data["started"])
    stream.write("Response bytes recorded: %d\n" % data["total_bytes"])
    stream.write("Hosts:\n")
    for host in sorted(data["hosts"], key=lambda h: -data["hosts"][h]["requests"]):
        record = data["hosts"][host]
        stream.write(
            "  %-40s %5d requests %10d bytes %3d errors\n"
            % (host[:40], record["requests"], record["bytes"], record["errors"])
        )
    status = data["status"]
    stream.write(
        "Status buckets: 2xx %d, 3xx %d, 4xx %d, 5xx %d, other %d\n"
        % (status["2xx"], status["3xx"], status["4xx"], status["5xx"], status["other"])
    )
    if data["slowest"]:
        stream.write("Slowest requests:\n")
        for index, item in enumerate(data["slowest"], start=1):
            stream.write(
                "  %d. %8.1f ms %-6s %s\n" % (index, item["time_ms"], item["method"], item["url"])
            )


def build_parser():
    parser = argparse.ArgumentParser(
        prog="har-sanitize",
        description="Redact credentials and personal data from HTTP Archive files.",
    )
    parser.add_argument("--version", action="version", version="har-sanitize 0.1.0")
    sub = parser.add_subparsers(dest="command")

    redact_parser = sub.add_parser("redact", help="write a redacted copy of a HAR file")
    redact_parser.add_argument("input")
    redact_parser.add_argument("-o", "--output", help="destination file, defaults to stdout")
    redact_parser.add_argument(
        "--drop-content", action="store_true", help="strip response bodies to shrink the file"
    )
    redact_parser.add_argument(
        "--scrub-emails", action="store_true", help="also replace email addresses in body text"
    )

    check_parser = sub.add_parser("check", help="report secrets without writing a file")
    check_parser.add_argument("input")
    check_parser.add_argument("--scrub-emails", action="store_true")

    summary_parser = sub.add_parser("summary", help="describe hosts, statuses and timings")
    summary_parser.add_argument("input")
    summary_parser.add_argument("--json", action="store_true", help="emit JSON instead of text")

    return parser


def default_options():
    # Handy for tests and for callers that only want the redaction pass.
    return argparse.Namespace(drop_content=False, scrub_emails=False)


def load_har(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 1

    try:
        har = load_har(args.input)
    except OSError as error:
        sys.stderr.write("cannot read %s: %s\n" % (args.input, error))
        return 1
    except ValueError as error:
        sys.stderr.write("%s is not valid JSON: %s\n" % (args.input, error))
        return 1

    # A JSON array or bare string parses cleanly but has no log object to walk,
    # so say what is wrong instead of failing later with an attribute error.
    if not isinstance(har, dict):
        sys.stderr.write(
            "%s: top level is %s, a HAR file must be a JSON object\n"
            % (args.input, type(har).__name__)
        )
        return 1

    if args.command == "summary":
        data = summarize(har)
        if args.json:
            json.dump(data, sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
        else:
            print_summary(data, sys.stdout)
        return 0

    if args.command == "check":
        options = argparse.Namespace(drop_content=False, scrub_emails=args.scrub_emails)
        # Work on a copy so the in-memory document stays untouched.
        working = copy.deepcopy(har)
        counter = redact_har(working, options)
        findings = total_findings(counter)
        sys.stdout.write("%s: %s\n" % (args.input, format_counter(counter)))
        return 2 if findings else 0

    options = argparse.Namespace(drop_content=args.drop_content, scrub_emails=args.scrub_emails)
    counter = redact_har(har, options)
    payload = json.dumps(har, ensure_ascii=False)
    if args.output:
        # A read-only directory or a bad path used to surface as a traceback
        # after the work was done, which reads as a crash rather than a refusal.
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(payload)
        except OSError as error:
            sys.stderr.write("cannot write %s: %s\n" % (args.output, error))
            return 1
        sys.stderr.write("%s: %s\n" % (args.output, format_counter(counter)))
    else:
        sys.stdout.write(payload)
        sys.stdout.write("\n")
        sys.stderr.write("%s\n" % format_counter(counter))
    return 0


if __name__ == "__main__":
    sys.exit(main())
