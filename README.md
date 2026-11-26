# 🎣 釣到你了：基於特徵工程與文本分析的釣魚郵件偵測系統

> 🏆 **2025 法遵科技與電腦稽核專題競賽　大專院校組 冠軍**（主辦：國際電腦稽核教育協會 ICAEA）
>
> 📰 [經濟日報報導](https://money.udn.com/money/story/5723/9214361)　🎥 [冠軍隊專訪影片](https://www.youtube.com/watch?v=5hkVm6lX8ik)

**English summary** — An explainable, rule-based phishing email risk scorer (Flask + PostgreSQL). It combines sender reputation checks (blacklist / suspicious patterns) with weighted content keywords, and reports every point it adds so analysts and auditors can trace each decision. Champion of the 2025 RegTech & Computer Auditing Competition (university division, Taiwan). After the competition, I evaluated the original system on a public dataset, found a 99.8% false-positive rate, and rebuilt the keyword pipeline to be reproducible and data-validated: **F1 45.5% → 76.4%, false-positive rate 99.8% → 11.8%**.

<!-- TODO: 放一張系統畫面截圖，例如 docs/images/demo.png -->

## 系統特色

- **可解釋**：每一分從哪裡來都列出來（命中哪條寄件者規則、哪些關鍵字各加幾分），符合稽核與法遵需要追溯判斷依據的需求
- **分層偵測**：先檢查寄件者，再分析內容，最後依總分分為高／中／低風險
- **規則可調整**：黑名單與關鍵字存在 PostgreSQL，企業可依自身郵件情境增修，不需改程式、不需重啟服務

## 運作方式

```
[離線] 郵件語料 ──TF-IDF──▶ 候選關鍵字 ──以正常郵件驗證篩選──▶ rules/*.csv ──init_db──▶ PostgreSQL
[線上] 寄件者 + 內容 ──▶ ① 寄件者檢查 ──▶ ② 內容關鍵字比對 ──▶ ③ 加總分數、風險分級 ──▶ 前端顯示明細
```

| 項目 | 條件 | 分數 |
|---|---|---|
| ① 寄件者 | 命中黑名單（例如 `@paypalload.net`、`no-reply@goog1e.com`） | +100 |
| | 可疑模式：規則庫中的萬用字元規則（例如 `mailserveralert@%`）、名稱含 security／alert 等警示用語、使用 .tk／.xyz 等高濫用率 TLD | +20 |
| | 信任網域（例如 `@paypal.com`） | 0 |
| ② 內容 | 每個命中的關鍵字依權重加分，同一個字只算一次 | +10 / +15 / +20 |
| ③ 分級 | ≥ 60 High、30~59 Medium、< 30 Low；Medium 以上判定為可疑 | |

## 賽後改進：v1.0 → v2.0

比賽版本以 git tag `v1.0-competition` 保留。賽後我用公開的 SpamAssassin 資料集評估，發現比賽版幾乎把**所有郵件都判成釣魚**：正常郵件的平均分數高達 241 分。原因有三：

1. **子字串比對**：`ach` 命中 `attached`、`dat` 命中 `data`、`ello` 命中 `hello`
2. **關鍵字過於常見**：`use`、`new`、`email` 分別出現在 27%、26%、23% 的正常郵件中；TF-IDF 萃取的詞彙裡還混有 `http`（+20）和大量亂碼字串
3. **分數無上限累加**：內容越長，命中越多，一般的長信也會輕易超過 60 分

### 評估結果（測試集 1,743 封，訓練時完全未使用）

| 版本 | Precision | Recall | F1 | 誤判率 (FPR) | Accuracy |
|---|---|---|---|---|---|
| v1.0 比賽版 | 29.5% | 99.4% | 45.5% | **99.8%** | 29.5% |
| v2.0 賽後改進 | 73.8% | 79.2% | **76.4%** | **11.8%** | 85.5% |

執行 `python scripts/evaluate.py` 可重現這張表。

### 改了什麼

| 問題 | v1.0 | v2.0 |
|---|---|---|
| 關鍵字比對 | 子字串 | 英文以單字邊界比對，中文維持子字串比對 |
| 關鍵字來源 | JCAATs 做 TF-IDF，以經驗閾值切分，流程未保存 | [`build_keywords.py`](scripts/build_keywords.py)：TF-IDF 產生候選詞，再以 spam／ham 出現率比值篩選並決定分數，**可重現** |
| 人工精選詞彙 | 全部採用（131 個） | 在正常郵件中出現率 ≥ 1.5% 的詞剔除（43 個） |
| 萬用字元黑名單 | SQL 的 `LIKE` 寫反，`mailserveralert@%` 永遠不會命中 | 正確比對，並涵蓋子網域、不分大小寫 |
| 規則語意 | `is_blacklist=FALSE` 同時代表「可疑」與「信任」 | 以 `list_type` 明確區分 blacklist／suspicious／trusted |
| 可疑 TLD | 包含 .net、.info 等常見 TLD | 只保留高濫用率的 TLD |
| 前端安全 | 後端回傳 HTML 字串，前端以 `innerHTML` 顯示，**有 XSS 漏洞** | 回傳結構化 JSON，前端一律使用 `textContent` |
| 測試 | 無 | 18 個 pytest，包含比賽的 7 個測試案例與各項修正的回歸測試 |

### 方法與限制

- **資料集**：Kaggle [Phishing Email Dataset](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset) 中的 `SpamAssasin.csv`（2002 年，1,718 封 spam／4,091 封 ham），以 7:3 分層切分為訓練集與測試集。它是**垃圾郵件**資料集，不完全等同釣魚郵件，所以這裡的數字是近似評估，不代表實際釣魚郵件的偵測率。
- **參數選擇**：`TFIDF_TOP_N`、`MIN_LR` 在訓練集內再切出的驗證集上挑選。`MAX_HAM_RATE` 取能通過全部 7 個比賽案例的最小值。測試集只在最後評估時使用一次。
- **資料驅動的關鍵字**反映的是 2002 年的垃圾郵件用語（例如 mortgage、refinance）。實際導入時，應該用企業自己的郵件資料重新執行 `build_keywords.py`。
- **中文關鍵字**（23 個）無法用英文資料集驗證，原樣保留自比賽版。
- **v1 的評估可能偏樂觀**：v1 的 TF-IDF 關鍵字很可能就是從同一份資料萃取的，有資料洩漏的疑慮。即使如此，v1 的表現仍然很差。

## 快速開始

需要 Python 3.10 以上與 Docker（或自行安裝的 PostgreSQL）。

```bash
# 1. 安裝套件
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. 啟動 PostgreSQL 並匯入規則
docker compose up -d
cp .env.example .env && export $(grep -v '^#' .env | xargs)
python scripts/init_db.py

# 3. 啟動網站，開啟 http://127.0.0.1:5001
python backend/app.py
```

API 範例：

```bash
curl -s http://127.0.0.1:5001/api/check-phishing \
  -H 'Content-Type: application/json' \
  -d '{"email": "security-alert@verify-service.tk", "content": "Please login immediately to restore access."}'
```

### （選配）啟用本地 LLM 內容分析

系統在規則引擎之上可再疊加一層**本地 LLM**（[Ollama](https://ollama.com) + `gemma3:4b-it-qat`），做詐騙語意判斷與「寄件網域 vs 內文自稱身分」比對（繁體中文原生）。這一層為**選配**：未安裝或未啟動時系統會自動略過，以純規則引擎運作。安裝與啟動步驟見 **[OLLAMA.md](OLLAMA.md)**。

### 測試與評估

```bash
pip install -r requirements-dev.txt
pytest                              # 單元測試，不需要資料庫

# 評估需要 SpamAssassin 資料集：從 Kaggle「Phishing Email Dataset」下載
# SpamAssasin.csv（檔名原本就是這樣拼），放到 data/SpamAssasin.csv
python scripts/build_keywords.py    # 重新產生 rules/keywords.csv
python scripts/evaluate.py          # v1 vs v2 評估
```

## 專案結構

```
backend/
  detector.py         評分引擎（不依賴資料庫）
  rules.py            從 CSV 或 PostgreSQL 載入規則
  app.py              Flask API，並提供前端頁面
frontend/             前端（以 BootstrapMade Dewi 模板修改）
rules/
  senders.csv         寄件者規則（56 筆）
  keywords.csv        v2 關鍵字庫（由 build_keywords.py 產生）
  keywords_v1.csv     比賽版關鍵字庫（保留作為評估基準）
db/schema.sql         資料表定義
scripts/
  init_db.py          建立資料表並匯入 rules/*.csv
  build_keywords.py   產生 v2 關鍵字庫
  evaluate.py         v1 vs v2 評估
  legacy_v1.py        比賽版評分邏輯的忠實重現
tests/                pytest
```

## 未來方向

- **相似網域偵測**：目前已由 LLM 層標記疑似仿冒網域（typosquatting），並提供「一鍵加入黑名單」的人工確認流程（見 [OLLAMA.md](OLLAMA.md)）。後續可再加上以編輯距離與同形字正規化（`1→l`、`0→o`、`rn→m`）比對知名品牌網域的**演算法自動偵測**，進一步提高精準度、減少逐一列入黑名單的需求
- **以真實釣魚郵件評估**：同一個 Kaggle 資料集中的 Nazario 是真正的釣魚郵件語料，可以取代 SpamAssassin 做更貼近目標的評估
- **中文語料評估**：蒐集中文釣魚郵件，驗證並擴充中文關鍵字
- **郵件標頭分析**：SPF、DKIM、DMARC 驗證結果，以及 Reply-To 與 From 不一致的偵測

## 團隊

中正大學「AI打詐隊」：高冠傑、鄧梓廷、陳昱淳、蔡欣彤

**我（高冠傑）的角色**：負責系統架構設計、後端評分邏輯（Python／Flask）、PostgreSQL 資料庫設計與規則庫建置、BEC 詐騙案例與參考資料蒐集，以及決賽報告。前端介面由鄧梓廷負責。賽後的評估、關鍵字流程重建與所有 v2 改進由我獨立完成。

## 致謝與授權

- 比賽階段的 TF-IDF 分析使用 JCAATs（競賽主辦方提供的稽核分析軟體）
- 評估資料集：Kaggle [Phishing Email Dataset](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset)
- 人工關鍵字參考 [simplerhacking/Phishing-Keyword-List](https://github.com/simplerhacking/Phishing-Keyword-List)
- 前端模板：[Dewi](https://bootstrapmade.com/dewi-free-multi-purpose-html-template/) by BootstrapMade（[授權條款](https://bootstrapmade.com/license/)）
