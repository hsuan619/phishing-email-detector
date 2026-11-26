"""產生 v2 關鍵字庫 rules/keywords.csv（可重現、只使用訓練集）。

比賽版的關鍵字權重由 JCAATs 做 TF-IDF 後依經驗閾值切分，流程未保存且無法重現。
此腳本是賽後的開源重現版，關鍵字有兩個來源：

1. 人工精選（比賽版 source=manual 的詞彙）
   英文詞彙若在訓練集「正常郵件」中出現率 >= MAX_HAM_RATE 就剔除（太常見，會造成誤判）；
   中文詞彙無法以英文資料集驗證，原樣保留。
2. 資料驅動（TF-IDF）
   以 TF-IDF 找出在 spam 中權重明顯高於 ham 的前 TFIDF_TOP_N 個詞，
   再以「spam 出現率 / ham 出現率」（likelihood ratio）篩選並決定分數：
   LR >= 20 → 20 分、>= 10 → 15 分、>= MIN_LR → 10 分。

參數是在訓練集中再切出的驗證集上挑選，測試集完全不參與：
- TFIDF_TOP_N、MIN_LR：驗證集 F1 最高的組合
- MAX_HAM_RATE：能通過全部 7 個比賽測試案例的最小門檻（以 0.5% 為間距搜尋，越小誤判越少）
用法：python scripts/build_keywords.py
"""
from __future__ import annotations

import csv

import numpy as np
from dataset import ROOT, load_splits
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS, TfidfVectorizer

from detector import CJK, compile_keyword

TFIDF_TOP_N = 200
MIN_LR = 5.0
MIN_SPAM_DOCS = 10
MAX_HAM_RATE = 0.015

# 郵件格式殘留（MIME、HTML 標籤與屬性），不是內文語意，排除以免學到格式而非內容
FORMAT_ARTIFACTS = {
    "iso", "boundary", "multi", "multipart", "charset", "encoding", "quoted", "printable",
    "html", "http", "https", "www", "com", "nbsp", "font", "face", "size", "color", "arial",
    "helvetica", "verdana", "width", "height", "align", "center", "bgcolor", "table",
    "href", "src", "img", "span", "div", "body", "head", "style", "border", "valign",
}


def lr_score(lr: float) -> int:
    if lr >= 20:
        return 20
    if lr >= 10:
        return 15
    return 10


def data_driven_keywords(texts: list[str], labels: np.ndarray) -> dict[str, tuple[int, float]]:
    tfidf = TfidfVectorizer(
        token_pattern=r"(?u)\b[a-z]{3,20}\b",  # 只取 3~20 個字母的英文單字，排除亂碼與超長字串
        stop_words=list(ENGLISH_STOP_WORDS | FORMAT_ARTIFACTS),
        min_df=10,
        max_df=0.5,
        sublinear_tf=True,
    )
    X = tfidf.fit_transform(texts)
    vocab = tfidf.get_feature_names_out()
    spam, ham = labels == 1, labels == 0

    mean_diff = np.asarray(X[spam].mean(0)).ravel() - np.asarray(X[ham].mean(0)).ravel()
    present = (X > 0).astype(int)
    spam_docs = np.asarray(present[spam].sum(0)).ravel()
    ham_docs = np.asarray(present[ham].sum(0)).ravel()
    lr = ((spam_docs + 1) / (spam.sum() + 2)) / ((ham_docs + 1) / (ham.sum() + 2))

    return {
        vocab[i]: (lr_score(lr[i]), lr[i])
        for i in np.argsort(-mean_diff)[:TFIDF_TOP_N]
        if lr[i] >= MIN_LR and spam_docs[i] >= MIN_SPAM_DOCS
    }


def main() -> None:
    train, _ = load_splits()
    texts = [t.lower() for t in train["content"]]
    labels = train["label"].to_numpy()
    ham_texts = [t for t, y in zip(texts, labels) if y == 0]

    rows, dropped = [], []
    with open(ROOT / "rules" / "keywords_v1.csv", newline="", encoding="utf-8") as f:
        manual = [r for r in csv.DictReader(f) if r["source"] == "manual"]
    for r in manual:
        if CJK.search(r["keyword"]):
            rows.append((r["keyword"], int(r["score"]), r["category"], "manual-zh"))
            continue
        pattern = compile_keyword(r["keyword"])
        ham_rate = sum(bool(pattern.search(t)) for t in ham_texts) / len(ham_texts)
        if ham_rate >= MAX_HAM_RATE:
            dropped.append((r["keyword"], ham_rate))
        else:
            rows.append((r["keyword"], int(r["score"]), r["category"], "manual"))

    existing = {r[0].lower() for r in rows}
    learned = data_driven_keywords(texts, labels)
    for word, (score, _) in sorted(learned.items(), key=lambda kv: -kv[1][1]):
        if word not in existing:
            rows.append((word, score, "Data-driven", "tfidf"))

    with open(ROOT / "rules" / "keywords.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["keyword", "score", "category", "source"])
        writer.writerows(rows)

    kept_manual = sum(r[3].startswith("manual") for r in rows)
    print(f"人工精選：保留 {kept_manual} / {len(manual)} 個，剔除 {len(dropped)} 個（正常郵件出現率 >= {MAX_HAM_RATE:.1%}）")
    print("  剔除：" + ", ".join(f"{w}({r:.0%})" for w, r in sorted(dropped, key=lambda d: -d[1])))
    print(f"資料驅動：新增 {len(rows) - kept_manual} 個")
    print(f"共 {len(rows)} 個關鍵字 → rules/keywords.csv")


if __name__ == "__main__":
    main()
