### smartbugs-curated - mode `hybrid` (gemini:gemini-3.5-flash-lite)

143 contracts, 0.27 s, verilens 0.1.0, 2026-10-06.

| Granularity | Precision | Recall | F1 |
|---|---:|---:|---:|
| Category (micro) | 62.2 | 74.8 | 67.9 |
| Line (micro, ±2) | 51.0 | 61.7 | - |

Category-level macro F1: **46.7**.
Upper bound for a perfect verifier on these candidates: category-level P 100.0 / R 83.9 / F1 91.2.
LLM rejected 241 of 492 static candidates.

| Category | P | R | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Access control | 65.0 | 72.2 | 68.4 | 13 | 7 | 5 |
| Integer overflow / underflow | 37.8 | 93.3 | 53.8 | 14 | 23 | 1 |
| Bad randomness | 53.8 | 87.5 | 66.7 | 7 | 6 | 1 |
| Denial of service | 25.0 | 66.7 | 36.4 | 4 | 12 | 2 |
| Front running / transaction-order dependence | 40.0 | 50.0 | 44.4 | 2 | 3 | 2 |
| Other | 0.0 | 0.0 | 0.0 | 0 | 0 | 3 |
| Reentrancy | 84.4 | 87.1 | 85.7 | 27 | 5 | 4 |
| Short address | 0.0 | 0.0 | 0.0 | 0 | 0 | 1 |
| Timestamp dependence | 100.0 | 20.0 | 33.3 | 1 | 0 | 4 |
| Unchecked low-level call | 81.2 | 75.0 | 78.0 | 39 | 9 | 13 |
