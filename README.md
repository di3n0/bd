# Black Duck SCA K8s Service Skill

這個 skill 把 Black Duck 掃描簡化成 `mode + target + project + version`。連線資訊、Token、Group、K8s Service URL、timeout、掃描深度與併發數集中放在 `.env`。

啟動時採兩段式詢問：第一問選 `source` / `binary` / `image` / `image-deep` 或查看使用說明；第二問使用 `.env` 預設參數或調整參數。使用預設時仍會先摘要 endpoint、深度、元件、timeout、Pod CPU/Memory 與狀態輪詢頻率。

## 架構

```text
Black Duck SCA client / Codex skill
              |
       mode + simple args
              |
      +-------+--------+
      |       |        |
    SOURCE  BINARY    IMAGE
      |       |        |
   +--+--+   BDBA   Container Scan
   |     |
Detector Signature
          |
       Snippet (optional)
```

K8s Service URL 是「完整 POST endpoint」。`source` 會同時呼叫 Detect 與 Signature；`binary` 呼叫 BDBA；`image` 與 `image-deep` 呼叫 Image Service。

## 預設 profile

| Mode | 用途 | 深度 | 元件範圍 | 預設併發 |
| --- | --- | ---: | --- | ---: |
| `source` | Detector + Signature | 5 | source | 5 |
| `binary` | BDBA | 1 | all | 5 |
| `image` | 一般 Image Scan | 5 | source | 8 |
| `image-deep` | Image 深度掃描 | 100 | all | 8 |

## 安裝與設定

1. 將整個 `black-duck-sca-service` 目錄放入 Codex skills 目錄。
2. 複製 `assets/.env.example` 為工作目錄中的 `.env`。
3. 修改 `.env` 的 Black Duck URL、Token、Group 與各 K8s endpoint。
4. 確認 `.env` 不會進版控；本 skill 已附 `.gitignore`。

Token 不會出現在 JSON 輸出或 dry-run 中。Client 只會把 Token 放進 `BLACKDUCK_TOKEN_HEADER` 指定的 HTTP header。

Proxy 使用標準 `HTTP_PROXY=http://xxx.xx.xx:xx`、`HTTPS_PROXY=http://xxx.xx.xx:xx`，並可搭配 `NO_PROXY`。Wrapper 依 Black Duck 目標 URL 協定選擇 Proxy。如需帳密，可使用 `http://user:password@host:port`；帳密只放在各自的 HTTP header，不會出現在 dry-run 或結果 JSON。這些 Proxy 不會改變 client 呼叫 K8s Service 的網路路徑。

完整逐步操作可直接開啟 `deploy_step.html`。

## WSL 完整模擬

模擬不會連真實 Black Duck；它會啟動本機 wrapper mock、送出 source 與 image-deep，並輪詢到完成：

```bash
chmod +x scripts/run_wsl_simulation.sh
./scripts/run_wsl_simulation.sh
```

使用的測試設定在 `assets/.env.wsl.example`。Mock 服務程式是 `scripts/mock_blackduck_service.py`。

## 單筆掃描

先預覽，不送出 HTTP：

```bash
python scripts/blackduck_scan.py \
  --env-file .env \
  --mode source \
  --target . \
  --project my-app \
  --version 1.2.3 \
  --dry-run
```

確認後移除 `--dry-run` 即可送出。Image 深度掃描：

```bash
python scripts/blackduck_scan.py \
  --env-file .env \
  --mode image-deep \
  --target registry.example.com/team/app:1.2.3 \
  --project my-app-image \
  --version 1.2.3
```

常用一次性覆寫：

```bash
python scripts/blackduck_scan.py --env-file .env --mode image \
  --target registry.example.com/team/app:1.2.3 \
  --project my-app --version 1.2.3 \
  --depth 20 --components all \
  --property detect.policy.check.fail.on.severities=BLOCKER,CRITICAL
```

## 批次與併發

複製 `assets/jobs.example.json` 後執行：

```bash
python scripts/blackduck_scan.py \
  --env-file .env \
  --batch jobs.json \
  --output scan-results.json
```

Client 會分別套用 `SOURCE_MAX_CONCURRENCY=5`、`BINARY_MAX_CONCURRENCY=5`、`IMAGE_MAX_CONCURRENCY=8`。這些是 client 端上限；K8s 服務端仍應設定自己的資源、併發與 timeout 限制。

## Timeout

- `SOURCE_TIMEOUT_SECONDS`：Detector 與 Signature 共用的 source timeout。
- `BINARY_TIMEOUT_SECONDS`：BDBA timeout。
- `IMAGE_TIMEOUT_SECONDS`：一般與深度 Image Scan timeout。
- `BLACKDUCK_API_TIMEOUT_SECONDS`：傳給服務端的 Black Duck API timeout。

CLI 的 `--timeout` 或 batch job 的 `timeout` 可以覆寫單次工作。發生 timeout 時 client 不會自動重試，避免服務端已收件卻被重複送單。

## Pod 資源與狀態輪詢

`.env` 可分別設定 Source、Binary、Image Job 的 CPU/Memory request 與 limit，例如 `IMAGE_POD_CPU_LIMIT=8`、`IMAGE_POD_MEMORY_LIMIT=16Gi`。這些值會送給 wrapper，由 wrapper 套用到新建的 Kubernetes Job。

`STATUS_POLL_INTERVAL_SECONDS` 決定多久查一次；`STATUS_MAX_WAIT_SECONDS=0` 表示沿用該 mode 的 scan timeout。POST 回傳的 `statusUrl` 優先，`.env` 的 `*_STATUS_URL_TEMPLATE` 是 fallback。

完整變數請看 `references/configuration.md`；K8s wrapper 的 JSON 與 header 契約請看 `references/service-contract.md`。
