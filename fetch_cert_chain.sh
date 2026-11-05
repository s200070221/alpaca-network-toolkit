#!/usr/bin/env bash
# fetch_cert_chain.sh — 抓取網站的憑證鏈與 TLS 版本，交給 Alpaca Network Toolkit 入口頁的「憑證檢查」離線分析。
# 適用 Linux 與 macOS（需要 openssl 或 LibreSSL，系統通常已內建）。
# 只連線到你指定的主機、只記錄伺服器公開送出的憑證與協商結果，不會把資料傳到任何其他地方。
#
# 用法：
#   bash fetch_cert_chain.sh example.com
#   bash fetch_cert_chain.sh example.com:8443 intranet.local
#   bash fetch_cert_chain.sh -f hosts.txt -o result.txt     # hosts.txt 一行一個主機，# 開頭為註解
# 選項：-o 輸出檔（預設 certchain.txt）、-f 主機清單檔、-t 每次連線逾時秒數（預設 10）
# 完成後把輸出檔拖放到入口頁，或貼到「憑證檢查」卡片。

set -u
OUT="certchain.txt"
LIST=""
TIMEOUT=10
usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
while getopts "o:f:t:h" opt; do
  case "$opt" in
    o) OUT="$OPTARG" ;;
    f) LIST="$OPTARG" ;;
    t) TIMEOUT="$OPTARG" ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))

if ! command -v openssl >/dev/null 2>&1; then
  echo "找不到 openssl，請先安裝（Linux：apt／dnf install openssl；macOS 系統已內建）" >&2
  exit 1
fi
case "$TIMEOUT" in ''|*[!0-9]*) echo "-t 必須是數字" >&2; exit 1 ;; esac

TARGETS=()
if [ -n "$LIST" ]; then
  if [ ! -r "$LIST" ]; then echo "讀不到清單檔：$LIST" >&2; exit 1; fi
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%#*}"
    line="$(printf '%s' "$line" | tr -d '[:space:]')"
    [ -n "$line" ] && TARGETS+=("$line")
  done < "$LIST"
fi
for t in "$@"; do TARGETS+=("$t"); done
[ "${#TARGETS[@]}" -gt 0 ] || usage

# 逾時：有 timeout（Linux）或 gtimeout（macOS 裝了 coreutils）時使用，沒有就不限時
TO=()
if command -v timeout >/dev/null 2>&1; then TO=(timeout "$TIMEOUT")
elif command -v gtimeout >/dev/null 2>&1; then TO=(gtimeout "$TIMEOUT"); fi

HELP="$(openssl s_client -help 2>&1)"
supports() { printf '%s\n' "$HELP" | grep -q -- "-$1[[:space:]]"; }
IS_OPENSSL=0
openssl version 2>/dev/null | grep -q '^OpenSSL' && IS_OPENSSL=1

# 單次連線；$3 為額外參數（版本、加密套件）
connect() {
  local host="$1" port="$2"; shift 2
  local sni=()
  case "$host" in *[!0-9.]*) case "$host" in *:*) ;; *) sni=(-servername "$host") ;; esac ;; esac
  local addr="$host:$port"
  case "$host" in *:*) addr="[$host]:$port" ;; esac
  ${TO[@]+"${TO[@]}"} openssl s_client -connect "$addr" ${sni[@]+"${sni[@]}"} "$@" </dev/null 2>&1
}
# 握手成功：有協商出加密套件（不是 (NONE)）
handshake_ok() { printf '%s\n' "$1" | grep -Eq 'Cipher is [A-Za-z0-9_-]+|^[[:space:]]*Cipher[[:space:]]*:[[:space:]]*[A-Za-z0-9_-]+' && ! printf '%s\n' "$1" | grep -q 'Cipher is (NONE)'; }

: > "$OUT" || { echo "無法寫入 $OUT" >&2; exit 1; }
for t in "${TARGETS[@]}"; do
  host="" port=443
  if [[ "$t" =~ ^\[([0-9A-Fa-f:]+)\](:([0-9]{1,5}))?$ ]]; then host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[3]:-443}"
  elif [[ "$t" =~ ^(https?://)?([A-Za-z0-9._-]+)(:([0-9]{1,5}))?(/.*)?$ ]]; then host="${BASH_REMATCH[2]}"; port="${BASH_REMATCH[4]:-443}"
  else echo "略過格式不正確的主機：$t" >&2; continue; fi
  echo "檢查 $host:$port ..." >&2
  {
    echo "=== alpaca-certchain host=$host port=$port ==="
    echo "#tool fetch_cert_chain.sh 1"
    echo "#date $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    main="$(connect "$host" "$port" -showcerts)"
    ok=1
    if ! printf '%s\n' "$main" | grep -q 'BEGIN CERTIFICATE'; then
      ok=0
      echo "#error $(printf '%s\n' "$main" | grep -v '^[[:space:]]*$' | head -n 1 | tr -cd '[:print:]' | cut -c1-200)"
    fi
    for v in 1.0 1.1 1.2 1.3; do
      case "$v" in 1.0) f=tls1 ;; 1.1) f=tls1_1 ;; 1.2) f=tls1_2 ;; 1.3) f=tls1_3 ;; esac
      # 連不上或用戶端不支援該版本時記 untested，不當成伺服器不接受
      if [ "$ok" = 0 ] || ! supports "$f"; then echo "#tls $v untested"; continue; fi
      extra=()
      # OpenSSL 3 預設安全等級不允許 TLS 1.0／1.1，測試時降低等級才能知道伺服器是否接受
      if [ "$IS_OPENSSL" = 1 ] && { [ "$v" = 1.0 ] || [ "$v" = 1.1 ]; }; then extra=(-cipher 'DEFAULT@SECLEVEL=0'); fi
      r="$(connect "$host" "$port" "-$f" ${extra[@]+"${extra[@]}"})"
      if handshake_ok "$r"; then echo "#tls $v yes"; else echo "#tls $v no"; fi
    done
    # SSL-Session 區段含 Master-Key／Session-ID／Resumption PSK 等連線密鑰，不寫進輸出檔
    printf '%s\n' "$main" | sed '/SSL-Session:/,$d'
    echo
  } >> "$OUT"
done
echo "完成：$OUT（只含公開憑證與連線資訊，可拖放到入口頁的「憑證檢查」）" >&2
