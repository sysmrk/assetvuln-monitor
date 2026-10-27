# Software normalization and mapping review — v0.2 (initial implementation)

The **candidate generation and review report are offline prototypes**, not a production automated mapping service. The CSV tool does not contact Endpoint Central or the CVE feed, approve software identities, or modify live mappings. The v0.2 worker now also uses the same conservative normalized exact-key rules for *explicitly approved* mappings; it never consumes suggested candidates.

## Motivation

Endpoint Central software labels often differ by case, Unicode width or spacing. The existing worker only correlates CVEs for software with a **verified, exact vendor/name mapping** to an advisory ecosystem/package. A fuzzy name match alone is not reliable evidence of vulnerability.

## Model and safeguards

1. Preserve the raw `vendor`, `name`, and `version` text.
2. Produce normalized vendor/name labels via Unicode NFKC, Unicode case folding and whitespace collapsing. Do not drop numbers, editions, architectures or version tokens from product names.
3. Load a catalogue of **already-approved** identities using the four-field YAML mapping format. Reject incomplete or duplicate identities.
4. Count an inventory product as mapped **only** if both normalized vendor and name equal an approved identity.
5. For unmapped products, **suggest** up to three already-approved catalogue entries with the exact normalized vendor and a similar product name. `name_similarity` is a string metric, **not confidence that two products are identical**.
6. Mark all candidates `review_required`; do not add them to the application's approved mappings automatically.

For actual Live usage, `config/product-mappings.live.yaml` starts empty. Therefore the candidate pool is initially empty, by design. A reviewed seed catalogue is required before suggestions become useful.

## Run an offline example

From a checkout of `develop/v0.2`, install the Python requirements in a local environment if needed (`PyYAML` is required), then run:

```bash
python3 scripts/suggest_mappings.py \
  --inventory-csv examples/software-inventory.sample.csv \
  --approved-mappings examples/mapping-catalog.sample.yaml \
  --min-similarity 0.88 \
  --output mapping-review.json
```

Both example files contain **synthetic company/product identities** and do not correspond to real vulnerabilities.

The JSON report contains inventory counts, distinct software counts, approved mapping counts, unmapped counts and review-only candidate suggestions. The report file is created with permission `0600`, because a real exported software inventory can be sensitive.

## Test real inventory without invoking APIs

Export or prepare a CSV file (UTF-8) with these headers:

```csv
vendor,name,version
Example Vendor,Example Application,1.2.3
```

Then:

```bash
python3 scripts/suggest_mappings.py \
  --inventory-csv /secure/path/software-export.csv \
  --approved-mappings config/product-mappings.live.yaml \
  --output /secure/path/mapping-review.json
```

The script reads only local files and writes the **report** only when `--output` is provided; it never modifies the mapping YAML or contacts Endpoint Central. Treat the report as sensitive asset information, and never commit exported inventory or candidate reports to Git.

## How to review a suggestion

Check the software identity and exact vendor/product against an authoritative source, check whether the proposed package ecosystem really describes that product, and verify whether the advisory's version semantics apply (including vendor patch backports). **Only then** manually add the approved four-field record to your private live mapping file. Human approval is not implemented as a separate workflow yet.

## Limitations and follow-up

- The report operates on a CSV snapshot; the v0.2 runtime worker only adopts **approved exact normalized keys**, not fuzzy suggestions.
- No built-in vendor synonym catalogue, PURL/CPE resolution, review audit trail or operator UI yet.
- Similar names (e.g. different major product editions) can score highly but still be unrelated.
- Coverage metrics refer to exact approved identities **within the supplied catalogue**, not to full CVE intelligence coverage.
- Proposed future work: verified alias catalogue, persisted review queue, review history and Metabase mapping-quality dashboard.

## Quality checks

```bash
python3 -m pytest -q tests/test_normalization.py tests/test_compose_isolation.py tests/test_api_smoke.py
python3 scripts/check_compose_isolation.py --baseline-dir /path/to/v0.1 --candidate-dir /path/to/v0.2
```

The isolation checker compares resolved Docker Compose configurations, never starts containers, and returns nonzero on resource/port overlap.
