# har-sanitize

Strip credentials and personal data out of a HAR file before you attach it to a bug report, drop it in a chat, or hand it to someone who should not see your session tokens.

A HAR capture from browser devtools contains more than the timing data you wanted. Request headers carry `Authorization` and `Cookie` values, signed URLs carry `X-Amz-Signature`, JSON bodies carry API keys and login payloads, and response bodies carry the same tokens coming back. Sharing that file raw is handing over a working credential.

har-sanitize rewrites a copy of the capture, blanks every value it recognises as a secret, and tells you how many fields it touched. It uses only the Python standard library.

## Install

Run it straight from the checkout, or install the console script:

```
python3 har_sanitize.py --help
pip install -e .
har-sanitize --help
```

## Usage

Write a cleaned copy, keeping everything else intact:

```
har-sanitize redact capture.har -o capture.clean.har
```

Write to stdout so you can pipe it:

```
har-sanitize redact capture.har | gzip > capture.clean.har.gz
```

Shrink it as well as sanitise it, for captures where the response payloads are not needed:

```
har-sanitize redact capture.har -o capture.clean.har --drop-content
```

Also replace email addresses in body text, useful when the capture touches user data:

```
har-sanitize redact capture.har -o capture.clean.har --scrub-emails
```

Check a capture without writing anything, for a pre-commit hook or a CI step:

```
har-sanitize check capture.har
```

`check` exits 0 when it finds nothing, 2 when it found and would redact at least one secret, and 1 on a read or parse error. That makes it usable as a gate:

```
har-sanitize check capture.har || echo "sanitise this file before sharing it"
```

Describe what the capture holds, which is often the only part you actually needed:

```
har-sanitize summary capture.har
har-sanitize summary capture.har --json
```

Summary output lists entry count, the first request time, total recorded body bytes, a per-host table of request counts, bytes and error counts, status code buckets, and the five slowest requests. Sensitive query parameters are masked in that output too, so the report can go straight into a ticket.

## What gets redacted

- Request and response headers whose name is a known credential header, including `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `X-Auth-Token`, `X-Amz-Security-Token`, `X-CSRF-Token` and `Private-Token`.
- Every cookie value in the cookie arrays, keeping the cookie name and domain so the capture still reads sensibly.
- Query string parameters whose name contains `token`, `secret`, `password`, `apikey`, `auth`, `signature`, `session`, `credential` or `access_key`. The URL is rebuilt rather than string-replaced, so unrelated parameters survive untouched.
- JSON request and response bodies, walked recursively, with the value blanked whenever the key looks sensitive. Nested objects and arrays are covered.
- `application/x-www-form-urlencoded` bodies, parsed and rebuilt the same way.
- Free text bodies, where bearer tokens and JWT-shaped strings are replaced wherever they appear.
- The structured `queryString` and `postData.params` arrays that HAR duplicates alongside the URL and body.

Values are replaced with the literal string `[REDACTED]`. Names are kept so the sanitised file still shows what the request was doing.

## What is left alone

Timings, status codes, URLs apart from their sensitive parameters, header names, JSON keys, non-secret body fields, and the capture structure itself. A sanitised HAR still opens in devtools and still replays through the network panel.

Names such as `author` or `authority` contain `auth` but are not credentials, so they are explicitly exempted.

## Limits worth knowing

The redactor is heuristic. A secret sent under an innocuous parameter name, or a token pasted into an unrelated field, will not be caught. Header-level redaction is exhaustive for the listed names, body-level redaction depends on the key name looking like a secret.

Emails inside body text are only replaced when you pass `--scrub-emails`, because a capture full of redacted emails can be useless for debugging a mail flow.

Binary content is left alone unless it is text.

## Tests

```
python3 -m unittest discover -s tests -v
```

Eight tests cover header and query redaction, JSON body redaction, form bodies, the finding counter, idempotence of a second pass, content dropping, the opt-in email scrub, the summary aggregation and the summary's own URL handling.

## License

MIT, see LICENSE.
