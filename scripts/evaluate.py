"""在測試集上比較 v1（比賽版）與 v2（賽後改進版）的偵測表現。

用法：python scripts/evaluate.py
「判定為釣魚」的標準與前端一致：風險等級為 Medium 或 High（總分 >= 30）。
"""
from __future__ import annotations

from dataset import load_splits
from legacy_v1 import LegacyDetector

from detector import MEDIUM_THRESHOLD, Detector, normalize_address
from rules import load_keywords_csv, load_senders_csv


def metrics(y_true: list[int], y_pred: list[int]) -> dict[str, float]:
    tp = sum(t and p for t, p in zip(y_true, y_pred))
    fp = sum((not t) and p for t, p in zip(y_true, y_pred))
    fn = sum(t and (not p) for t, p in zip(y_true, y_pred))
    tn = sum((not t) and (not p) for t, p in zip(y_true, y_pred))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "Precision": precision,
        "Recall": recall,
        "F1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "誤判率 (FPR)": fp / (fp + tn) if fp + tn else 0.0,
        "Accuracy": (tp + tn) / len(y_true),
    }


def main() -> None:
    _, test = load_splits()
    y_true = test["label"].tolist()
    senders = [normalize_address(s) for s in test["sender"]]
    contents = test["content"].tolist()

    v1 = LegacyDetector()
    v2 = Detector(load_senders_csv(), load_keywords_csv())
    results = {
        "v1.0 比賽版": [int(v1.score(s, c) >= MEDIUM_THRESHOLD) for s, c in zip(senders, contents)],
        "v2.0 賽後改進": [int(v2.analyze(s, c).is_phishing) for s, c in zip(senders, contents)],
    }

    print(f"測試集：{len(test)} 封（spam {sum(y_true)} / ham {len(y_true) - sum(y_true)}）\n")
    names = list(metrics(y_true, y_true))
    print("| 版本 | " + " | ".join(names) + " |")
    print("|---|" + "---|" * len(names))
    for version, y_pred in results.items():
        m = metrics(y_true, y_pred)
        print(f"| {version} | " + " | ".join(f"{m[n]:.1%}" for n in names) + " |")


if __name__ == "__main__":
    main()
