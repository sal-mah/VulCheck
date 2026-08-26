# SQL Injection Scanner - Scope & Evidence Format

Owner: Salma (Member 3) — matches the Deliverables Matrix documentation
requirement for this module: "Scope + evidence format".

## Scope

- Runs only against web URLs already carrying query parameters, supplied
  via `recon_data["urls"]` (produced by Recon, or by whoever's testing
  this module standalone).
- Skips (does not run) if `recon_data` has no web service, or no URL has
  a query string - there's nothing to inject into.
- Tests three SQL injection types per parameter:
  1. **Error-based** — a syntax-breaking payload (`'`, `"`, `' OR '1'='1`, `'--`)
     is sent, and the response is checked against a list of common
     database error signatures (MySQL, PostgreSQL, SQLite, generic
     SQLSTATE messages).
  2. **Boolean-based (blind)** — a `TRUE` payload (`' OR '1'='1`) and a
     `FALSE` payload (`' AND '1'='2`) are compared against each other and
     against the normal (baseline) page. A parameter is flagged only when
     TRUE closely matches the baseline AND FALSE differs meaningfully -
     this two-sided check is the false-positive reduction logic.
  3. **Time-based (blind)** — a `SLEEP()`/`pg_sleep()` payload is sent; if
     the response takes at least 4 seconds longer than the baseline
     request, it's flagged.
- One authorized test only. This module does not attempt to extract real
  data (no dumping of tables/columns) - it only confirms that a
  parameter *appears* injectable and returns evidence of that.

## What this module does NOT cover

- Second-order SQL injection (payload stored now, triggered elsewhere later).
- POST-body or JSON-body injection - only GET query parameters are tested.
- Exploitation/data extraction beyond confirming the vulnerability exists.
- WAF/filter bypass techniques.

## Evidence format

Every finding's `evidence` field is a short, inspectable string, not a
generic description - so a teammate can verify the result:

| Finding type | Evidence field contains |
|---|---|
| Error-based | the exact payload used and the URL requested |
| Boolean-based | baseline / TRUE / FALSE response lengths, so the size comparison is visible |
| Time-based | the payload, the measured response time, and the baseline response time |

Example (from a real finding dict):
```
"evidence": "payload=\"' OR SLEEP(3)-- -\" elapsed=3.42s baseline=0.18s url=http://192.168.64.129/page.php?id=%27+OR+SLEEP%283%29--+-"
```

## Confidence note

Boolean-based and time-based results are inherently probabilistic (blind
techniques), so they're only reported when both sides of the comparison
line up (TRUE-matches-baseline AND FALSE-differs; or elapsed time clears
a fixed threshold) - this is the module's confidence check in place of a
separate numeric score.
