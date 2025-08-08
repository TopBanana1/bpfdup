#!/usr/bin/env bash
set -euo pipefail

# hcxdumptool BPF builder from a capture file (pcap/pcapng)
# - Extract BSSIDs for chosen ESSIDs (fzf multi-select if -e omitted)
# - Build a BPF (addr3 or addr1..4) and compile to tcpdump/libpcap -ddd
# - Auto-fallback: if expression too complex -> retry with addr3
# - Auto-chunk: if still too big -> emit multiple .bcf parts
# - DFS channels excluded by default; -D includes them
#
# Usage:
#   bpf_from_capture.sh -f <capture> [-e <essid>]... [--addr-mode=3|all] [-D] [-d]
#
# Outputs:
#   <file>.bcf (or <file>.partNN.bcf if chunked), <file>.bssids, <file>.channels

debug_mode=0
include_dfs=0
addr_mode="3"   # default small/safe
file=""
declare -a essids=()

show_help() {
  cat <<EOF
Usage: $0 -f <file> [-e <essid>]... [--addr-mode=3|all] [-D] [-d] [-h]

Options:
  -f <file>        Capture file (pcap/pcapng)
  -e <essid>       ESSID to include (repeatable). If omitted, choose via fzf.
  --addr-mode=MODE 3   - Match only wlan addr3 (default; smaller filter)
                     all - Match wlan addr1..addr4 (bigger, more complete)
  -D               Include DFS channels in <file>.channels (default: exclude)
  -d               Debug mode (set -x)
  -h               Show help
EOF
  exit 0
}

# --- arg parsing (supports --addr-mode=*) ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    -f) file="${2:-}"; shift 2 ;;
    -e) essids+=("${2:-}"); shift 2 ;;
    -D) include_dfs=1; shift ;;
    -d) debug_mode=1; shift ;;
    --addr-mode=*) addr_mode="${1#*=}"; shift ;;
    -h) show_help ;;
    --) shift; break ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

[[ -z "$file" ]] && { echo "Error: -f <file> is required." >&2; exit 1; }
[[ "$addr_mode" == "3" || "$addr_mode" == "all" ]] || { echo "Error: --addr-mode must be '3' or 'all'." >&2; exit 1; }
[[ -r "$file" ]] || { echo "Error: cannot read capture: $file" >&2; exit 1; }
(( debug_mode )) && set -x

# --- deps ---
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; exit 1; }; }
need tshark
need tcpdump
if [[ ${#essids[@]} -eq 0 ]]; then need fzf; fi

# --- temp workspace & cleanup ---
TMPDIR="$(mktemp -d -t bpfbuild.XXXXXX)"
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT INT TERM

# --- (BSSID, ESSID) extraction ---
mapfile -t pairs < <(
  tshark -r "$file" \
    -Y '(wlan.fc.type == 0 && wlan_mgt.ssid && wlan_mgt.ssid != "")' \
    -T fields -e wlan.bssid -e wlan_mgt.ssid \
    -E occurrence=f -E separator=$'\t' 2>/dev/null \
  | awk -F'\t' 'NF==2 && $1!="" && $2!="" {print tolower($1) "\t" $2}' \
  | sort -u
)
(( ${#pairs[@]} )) || { echo "No (BSSID, ESSID) pairs found in capture." >&2; exit 1; }

declare -A essid_to_bssids
for line in "${pairs[@]}"; do
  bssid=${line%%$'\t'*}
  essid=${line#*$'\t'}
  essid_to_bssids["$essid"]+="$bssid"$'\n'
done

if [[ ${#essids[@]} -eq 0 ]]; then
  mapfile -t essids < <(
    printf '%s\n' "${!essid_to_bssids[@]}" \
    | sort -V \
    | fzf --multi --prompt="Select ESSIDs: " --height=60% --border --reverse
  )
  [[ ${#essids[@]} -eq 0 ]] && { echo "No ESSIDs selected." >&2; exit 1; }
fi

# --- resolve BSSIDs ---
declare -A bssid_set
for e in "${essids[@]}"; do
  if [[ -n "${essid_to_bssids[$e]+x}" ]]; then
    while IFS= read -r b; do
      [[ -n "$b" ]] && bssid_set["$b"]=1
    done <<< "${essid_to_bssids[$e]}"
  else
    echo "Warning: ESSID not found in capture: $e" >&2
  fi
done
(( ${#bssid_set[@]} )) || { echo "No BSSIDs resolved for selected ESSIDs." >&2; exit 1; }

# --- channel collection for these BSSIDs ---
tmp_bssid_re=$(printf '%s\n' "${!bssid_set[@]}" | paste -sd'|' -)
mapfile -t freq_lines < <(
  tshark -r "$file" \
    -Y "(wlan.fc.type == 0) && (wlan.bssid ~= \"(?i)(${tmp_bssid_re})\")" \
    -T fields -e radiotap.channel.freq -e wlan_radio.channel \
    -E occurrence=f -E separator=$'\t' 2>/dev/null
)
declare -A chan_set
for l in "${freq_lines[@]}"; do
  freq=${l%%$'\t'*}
  ch=${l#*$'\t'}
  if [[ -n "$ch" && "$ch" != "$l" ]]; then
    [[ "$ch" =~ ^[0-9]+$ ]] && chan_set["$ch"]=1
  elif [[ -n "$freq" && "$freq" != "0" ]]; then
    if   [[ "$freq" -ge 2412 && "$freq" -le 2472 ]]; then ch_calc=$(( (freq - 2412)/5 + 1 )); (( ch_calc>=1 && ch_calc<=13 )) && chan_set["$ch_calc"]=1
    elif [[ "$freq" -eq 2484 ]]; then chan_set["14"]=1
    elif [[ "$freq" -ge 5000 && "$freq" -le 5900 ]]; then ch_calc=$(( (freq - 5000)/5 ));   (( ch_calc>=1 && ch_calc<=200 )) && chan_set["$ch_calc"]=1
    elif [[ "$freq" -ge 5925 && "$freq" -le 7125 ]]; then ch_calc=$(( (freq - 5955)/5 + 1 )); (( ch_calc>=1 && ch_calc<=233 )) && chan_set["$ch_calc"]=1
    fi
  fi
done

# DFS filter (default exclude)
is_dfs() { local c="$1"; { [[ "$c" -ge 52 && "$c" -le 64 ]] || [[ "$c" -ge 100 && "$c" -le 144 ]]; }; }
declare -A chan_filtered_set
removed_dfs=0
for c in "${!chan_set[@]}"; do
  if (( include_dfs )); then
    chan_filtered_set["$c"]=1
  else
    if is_dfs "$c"; then removed_dfs=1; continue; fi
    chan_filtered_set["$c"]=1
  fi
done
channel_list=""
if [[ ${#chan_filtered_set[@]} -gt 0 ]]; then
  channel_list=$(printf '%s\n' "${!chan_filtered_set[@]}" | sort -n | paste -sd, -)
fi

# --- helpers to build/compile BPF ---
build_clause() {
  local mac="$1" mode="$2"
  local m=$(echo "$mac" | tr 'A-F' 'a-f')
  if [[ "$mode" == "3" ]]; then
    printf 'wlan addr3 %s' "$m"
  else
    printf '(wlan addr1 %s or wlan addr2 %s or wlan addr3 %s or wlan addr4 %s)' "$m" "$m" "$m" "$m"
  fi
}

build_expr_for_bssids() {
  local mode="$1"; shift
  local arr=( "$@" )
  local out=""
  for mac in "${arr[@]}"; do
    local clause; clause=$(build_clause "$mac" "$mode")
    out=${out:+"$out or "}$clause
  done
  printf '%s' "$out"
}

compile_expr_to_bcf() {
  local expr="$1" out="$2"
  local filterfile="$TMPDIR/filter.expr"
  printf '%s\n' "$expr" > "$filterfile"
  # Use -F to avoid shell tokenization issues
  if tcpdump -s 1024 -y IEEE802_11_RADIO -F "$filterfile" -ddd > "$out" 2>"$TMPDIR/tcpdump.err"; then
    return 0
  else
    return 1
  fi
}

# --- main compile with fallback + chunking ---
bcf_base="${file}.bcf"
bssid_out="${file}.bssids"
chan_out="${file}.channels"
printf '%s\n' "${!bssid_set[@]}" | sort -V > "$bssid_out"
[[ -n "$channel_list" ]] && printf '%s\n' "$channel_list" > "$chan_out"

# Try all BSSIDs at once with requested mode
mapfile -t ALL_BSSIDS < <(printf '%s\n' "${!bssid_set[@]}" | sort -V)

try_mode="$addr_mode"
expr=$(build_expr_for_bssids "$try_mode" "${ALL_BSSIDS[@]}")
if compile_expr_to_bcf "$expr" "$bcf_base"; then
  compiled_parts=( "$bcf_base" )
else
  # Fallback to addr3 if not already
  if [[ "$try_mode" == "all" ]]; then
    try_mode="3"
    expr=$(build_expr_for_bssids "$try_mode" "${ALL_BSSIDS[@]}")
    if compile_expr_to_bcf "$expr" "$bcf_base"; then
      compiled_parts=( "$bcf_base" )
    else
      need_chunk=1
    fi
  else
    need_chunk=1
  fi
fi

# Chunk if still too big
if [[ "${need_chunk:-0}" -eq 1 ]]; then
  echo "Filter too large; splitting into parts..." >&2
  # Start with generous batch size, back off on failure
  local_batch=$(( ${#ALL_BSSIDS[@]} > 64 ? 64 : ${#ALL_BSSIDS[@]} ))
  compiled_parts=()
  part=1
  i=0
  while (( i < ${#ALL_BSSIDS[@]} )); do
    # adaptively find a batch size that compiles
    sz=$local_batch
    success=0
    while (( sz >= 1 )); do
      subset=( "${ALL_BSSIDS[@]:i:sz}" )
      expr=$(build_expr_for_bssids "$try_mode" "${subset[@]}")
      out="${file}.part$(printf '%02d' "$part").bcf"
      if compile_expr_to_bcf "$expr" "$out"; then
        compiled_parts+=( "$out" )
        (( i += sz ))
        (( part++ ))
        success=1
        # try to grow next time a bit (but cap at 128)
        (( local_batch = sz < 128 ? sz*2 : 128 ))
        break
      else
        # shrink batch
        (( sz /= 2 ))
      fi
    done
    if (( ! success )); then
      echo "Failed to compile even a single-BSSID filter. Aborting." >&2
      exit 1
    fi
  done
fi

# --- summary ---
echo
echo "Selected ESSIDs:"
printf '  - %s\n' "${essids[@]}"

echo
echo "Resolved BSSIDs:"
nl -ba "$bssid_out" | sed 's/^/  /'

echo
if (( ${#compiled_parts[@]} == 1 )); then
  echo "Wrote BPF (-ddd) to: ${compiled_parts[0]}"
else
  echo "Wrote ${#compiled_parts[@]} BPF parts:"
  for p in "${compiled_parts[@]}"; do echo "  - $p"; done
  echo "Use one part at a time with hcxdumptool's bpfc option (or rotate between them)."
fi

if [[ -s "$chan_out" ]]; then
  echo "Observed channels written to: $chan_out"
  (( include_dfs )) || { (( removed_dfs )) && echo "  Note: DFS channels excluded. Use -D to include them."; }
  echo "Example:"
  if (( ${#compiled_parts[@]} == 1 )); then
    echo "  hcxdumptool -i <iface> -c $(cat "$chan_out") --bpfc=${compiled_parts[0]}"
  else
    echo "  hcxdumptool -i <iface> -c $(cat "$chan_out") --bpfc=${compiled_parts[0]}   # then rotate parts as needed"
  fi
fi

if (( debug_mode )); then
  echo
  echo "Final mode used for BPF: $try_mode"
fi
