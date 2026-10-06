### smartbugs-curated - mode `static`

143 contracts, 0.46 s, verilens 0.1.0, 2026-10-06.

| Granularity | Precision | Recall | F1 |
|---|---:|---:|---:|
| Category (micro) | 46.0 | 89.5 | 60.8 |
| Line (micro, ±2) | 33.5 | 78.8 | - |

Category-level macro F1: **42.4**.
Upper bound for a perfect verifier on these candidates: category-level P 100.0 / R 83.9 / F1 91.2.

| Category | P | R | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Access control | 51.8 | 77.8 | 62.2 | 14 | 13 | 4 |
| Integer overflow / underflow | 19.2 | 100.0 | 32.3 | 15 | 63 | 0 |
| Bad randomness | 38.9 | 87.5 | 53.8 | 7 | 11 | 1 |
| Denial of service | 20.0 | 83.3 | 32.3 | 5 | 20 | 1 |
| Front running / transaction-order dependence | 23.1 | 75.0 | 35.3 | 3 | 10 | 1 |
| Other | 0.0 | 0.0 | 0.0 | 0 | 0 | 3 |
| Reentrancy | 71.8 | 90.3 | 80.0 | 28 | 11 | 3 |
| Short address | 0.0 | 0.0 | 0.0 | 0 | 0 | 1 |
| Timestamp dependence | 23.5 | 80.0 | 36.4 | 4 | 13 | 1 |
| Unchecked low-level call | 85.2 | 100.0 | 92.0 | 52 | 9 | 0 |
