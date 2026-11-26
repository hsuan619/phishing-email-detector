# 本地 LLM（Ollama）安裝與啟動指南

本系統的釣魚判斷以**規則引擎（v2）為骨幹**；在其上疊加一層**本地 LLM 內容分析**，用來做詐騙語意判斷與「寄件網域 vs 內文自稱身分」比對（繁體中文原生）。

LLM 層走 [Ollama](https://ollama.com) 跑在本機，模型是 **`gemma3:4b-it-qat`**。

> **這一層是選配。** 沒安裝或沒啟動 Ollama，系統仍可正常運作——只是結果少掉 LLM 的內容分析與身分比對，風險分級退回純規則引擎。後端偵測到 Ollama 未回應時會自動略過（回報 `本地 LLM 未回應，已略過`），不會報錯或當掉。

---

## 一、安裝 Ollama

### Windows（本專案主要環境）
1. 到 <https://ollama.com/download> 下載 Windows 安裝檔並安裝。
2. 安裝後 Ollama 會以背景服務自動啟動，並在系統匣（右下角）常駐，服務位址為 `http://127.0.0.1:11434`。
3. 開一個新的終端機，確認 CLI 可用：
   ```powershell
   ollama --version
   ```

### macOS / Linux（參考）
- macOS：下載 <https://ollama.com/download> 的 App，或 `brew install ollama`。
- Linux：`curl -fsSL https://ollama.com/install.sh | sh`

---

## 二、下載模型

```powershell
ollama pull gemma3:4b-it-qat
```

- 下載約數 GB（QAT int4 量化版），只需做**一次**，之後會留在本機。
- 執行時約佔 **3.3 GB VRAM**；在 8 GB 顯卡（本專案為 RTX 4060 Laptop 8GB）可 100% 跑在 GPU。
- 顯存不足會自動改用 CPU／部分 CPU，仍可運作但明顯變慢。

確認模型已安裝：
```powershell
ollama list
```
輸出應包含一列 `gemma3:4b-it-qat`。

---

## 三、啟動與確認

Windows 安裝版通常**已自動在背景執行**，不需要手動啟動。若需手動啟動（例如關過、或在無桌面環境）：
```powershell
ollama serve
```

確認服務有在聽：
```powershell
# 回傳一段 JSON（已安裝模型清單）代表服務正常
curl http://localhost:11434/api/tags
```

第一次呼叫模型會先把模型載入顯存（冷啟動），可能等 **10 秒以上**；之後的呼叫約 5–6 秒。本系統預設逾時 180 秒就是為了容忍冷啟動。

---

## 四、與本系統連接

後端透過環境變數讀取 Ollama 設定（可寫進專案根目錄的 `.env`，或留空用預設值）：

| 變數 | 預設值 | 說明 |
|---|---|---|
| `OLLAMA_URL` | `http://localhost:11434` | Ollama 服務位址 |
| `OLLAMA_MODEL` | `gemma3:4b-it-qat` | 使用的模型標籤 |
| `OLLAMA_TIMEOUT` | `180` | 單次呼叫逾時秒數（容忍冷啟動） |

啟動流程（Ollama 已在背景跑的前提下）：
```powershell
# 啟動網站，開啟 http://127.0.0.1:5001
python backend\app.py
```

驗證 LLM 層有接上——送一封會觸發分析的信：
```powershell
curl -s http://127.0.0.1:5001/api/check-phishing `
  -H "Content-Type: application/json" `
  -d '{\"email\": \"support@paypa1.com\", \"content\": \"您的 PayPal 帳號出現異常，請點此登入驗證。\"}'
```
回應的 JSON 若含有 `llmAnalysis` 物件（裡面有 `is_fraud`、`sender_identity_match`、`reason` 等欄位），代表 LLM 層正常運作。

---

## 五、疑難排解

| 症狀 | 原因與解法 |
|---|---|
| `ConnectionRefusedError [WinError 10061]`／`無法連線` | Ollama 沒在跑。開啟 Ollama App，或執行 `ollama serve`，再用 `curl http://localhost:11434/api/tags` 確認。 |
| 後端回 `本地 LLM 未回應，已略過` | 同上，Ollama 未啟動或模型還沒載入；系統已優雅降級，補開 Ollama 即恢復。 |
| `model 'gemma3:4b-it-qat' not found` | 還沒下載模型，執行 `ollama pull gemma3:4b-it-qat`。 |
| 第一次分析很慢（數十秒） | 冷啟動載入顯存，屬正常；之後會快。逾時可調高 `OLLAMA_TIMEOUT`。 |
| 分析很慢且每次都慢 | 顯存不足被丟到 CPU。關掉其他吃顯存的程式（瀏覽器分頁、遊戲），或改用更小的模型。 |
| 想換模型 | `ollama pull <模型標籤>` 後，設定 `OLLAMA_MODEL=<模型標籤>`（寫進 `.env` 或環境變數）再重啟後端。 |

---

## 六、改動設定後何時生效

- 改 `.env` 裡的 `OLLAMA_*` 變數 → **重啟** `python backend\app.py`。
- `ollama pull` 新模型 → 不需重啟 Ollama；改 `OLLAMA_MODEL` 後重啟後端即可。

> 關於為何選用 `gemma3:4b-it-qat`（單一多語言模型、原生繁中、一次呼叫同時做詐騙判斷與身分比對）的設計背景，另見專案說明與 `backend/llm.py` 的註解。
