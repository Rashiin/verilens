### contrastive-pairs - mode `static`

34 contracts, 0.03 s, verilens 0.1.0, 2026-10-06.

| Granularity | Precision | Recall | F1 |
|---|---:|---:|---:|
| Category (micro) | 68.0 | 100.0 | 81.0 |
| Line (micro, ±2) | 69.0 | 100.0 | - |

Category-level macro F1: **81.6**.
False-alarm rate on safe twins: **29.4%** (17 patched contracts).
Upper bound for a perfect verifier on these candidates: category-level P 100.0 / R 100.0 / F1 100.0.

| Category | P | R | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Access control | 80.0 | 100.0 | 88.9 | 4 | 1 | 0 |
| Integer overflow / underflow | 66.7 | 100.0 | 80.0 | 2 | 1 | 0 |
| Bad randomness | 100.0 | 100.0 | 100.0 | 2 | 0 | 0 |
| Denial of service | 66.7 | 100.0 | 80.0 | 2 | 1 | 0 |
| Front running / transaction-order dependence | 66.7 | 100.0 | 80.0 | 2 | 1 | 0 |
| Reentrancy | 40.0 | 100.0 | 57.1 | 2 | 3 | 0 |
| Timestamp dependence | 50.0 | 100.0 | 66.7 | 1 | 1 | 0 |
| Unchecked low-level call | 100.0 | 100.0 | 100.0 | 2 | 0 | 0 |
