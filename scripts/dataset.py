"""載入 SpamAssassin 資料集並做固定的訓練／測試切分（build_keywords 與 evaluate 共用）。"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

DATA_PATH = ROOT / "data" / "SpamAssasin.csv"
TEST_SIZE = 0.3
SEED = 42


def load_splits(path: Path = DATA_PATH) -> tuple[pd.DataFrame, pd.DataFrame]:
    if not path.exists():
        sys.exit(f"找不到資料集 {path}，請依 README 的說明下載後放到 data/ 目錄")
    df = pd.read_csv(path)
    # 前端只有「寄件者」與「內容」兩個欄位，因此把主旨併入內容
    df["content"] = df["subject"].fillna("") + "\n" + df["body"].fillna("")
    df = df[["sender", "content", "label"]]
    return train_test_split(df, test_size=TEST_SIZE, stratify=df["label"], random_state=SEED)
