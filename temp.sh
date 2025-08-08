#!/usr/bin/env bash
set -euo pipefail

# bpfdup.sh - Build an IEEE802.11 BPF for hcxdumptool from a capture (pcap/pcapng)
# - Select ESSIDs via fzf (multi-select) or pass -e multiple times
# - Parses SSIDs from wlan_mgt.ssid (ASCII) or wlan.ssid (hex / messy hex)
# - If normal parsing fails, falls back to raw wlan.ssid scanning (old-tool style)
# - Compiles BPF (addr3 or addr1..addr4), falls back & chunks if filter too large
# - Writes:
#     <file>.bcf          - compiled tcpdump -ddd BPF
#     <file>.bssids       - resolved BSSIDs
#     <file>.targets.json - combined JSON (essids, bssids, channels, bands, freqs, flags)
#
# Usage:
#   ./bpfdup.sh -f <capture> [-e <essid>]... [--addr-mode=3|all] [-D] [-d]

# ---- Speed & locale hygiene ---------------------------------------------------
LC_ALL=C
LANG=C
IFS=$' \t\n'

# ---- Options -----------------------------------------------------------------
debug_mode=0
include_dfs=0
addr_mode="3"
file=""
declare -a essids=()

show_help() {
  cat <<EOF
Usage: $0 -f <file> [-e <essid>]... [--addr-mode=3|all] [-D] [-d] [-h]
Options:
  -f <file>        Capture file (pcap/pcapng)
  -e <essid>       ESSID to include (repeatable). If omitted, choose via fzf.
  --addr-mode=MODE   3   - Match only wlan addr3 (default; smaller filter)
                       all - Match wlan addr1..addr4 (bigger, more complete)
  -D               Include DFS channels in channel list (default: exclude)
  -d               Debug mode (set -x)
  -h               Show help
EOF
  exit 0
}

# ---- Args --------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -f) file="${2:-}"; shift 2 ;;
    -e) essids+=("${2:-}"); shift 2 ;;
    -D) include_dfs=1; shift ;;
    -d) debug_mode=1; shift ;;
    --addr-mode=*) addr_mode="${1#*=}"; shift ;;
    -h) show_help ;;
    --) shift; break ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; exit 1 ;;
  esac
done

[[ -n "$file" ]] || { echo "Error: -f <file> is required." >&2; exit 1; }
[[ "$addr_mode" == "3" || "$addr_mode" == "all" ]] || { echo "Error: --addr-mode must be '3' or 'all'." >&2; exit 1; }
[[ -r "$file" ]] || { echo "Error: cannot read capture: $file" >&2; exit 1; }
(( debug_mode )) && set -x

# ---- Deps --------------------------------------------------------------------
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1" >&2; exit 1; }; }
need tshark
need tcpdump
need python3
need xxd        # used by to_hex / hex_to_ascii_best
# fzf is optional until we need interactive selection

TMPDIR="$(mktemp -d -t bpfbuild.XXXXXX)"
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT INT TERM

# ---- Helpers -----------------------------------------------------------------
normalize_hex() { # fast, minimal forking
  local s=$1
  s=${s//0x/}; s=${s//0X/}; s=${s//:/}; s=${s// /}
  # lower only A-F; keep digits
  printf '%s' "$s" | tr 'A-F' 'a-f' | tr -cd '0-9a-f'
}
to_hex() { printf '%s' "$1" | xxd -p -c 256 | tr -d '\n' | tr 'A-F' 'a-f'; }
is_hex_even(){ [[ "$1" =~ ^[0-9a-f]+$ ]] && (( ${#1} % 2 == 0 )); }
strip_nuls(){ tr -d '\000' <<<"$1"; }
ascii_one_line(){ strip_nuls "$1" | tr '\r\t' '  ' | tr -cd '\40-\176' | awk '{printf "%s",$0}'; }
hex_to_ascii_best(){ local h=$1; if is_hex_even "$h"; then xxd -r -p <<<"$h" 2>/dev/null | tr -d '\000' | awk '{printf "%s",$0}'; fi; }
escape_dfilter_str(){ local s=$1; s=${s//\\/\\\\}; s=${s//\"/\\\"}; printf '%s' "$s"; }

# Include main mgmt subtypes we care about (beacon, probe req/resp, assoc/disassoc, etc.)
MGMT_Y='(wlan.fc.type == 0) && (wlan.fc.type_subtype == 0x08 || wlan.fc.type_subtype == 0x04 || wlan.fc.type_subtype == 0x05 || wlan.fc.type_subtype == 0x00 || wlan.fc.type_subtype == 0x01 || wlan.fc.type_subtype == 0x02 || wlan.fc.type_subtype == 0x03)'

resolve_bssids_from_raw_ssid() {
  local cap=$1 want_ascii=$2
  local hw nh; hw=$(to_hex "$want_ascii"); nh=$(normalize_hex "$want_ascii")
  declare -A out=()
  # One tshark, light awk
  tshark -r "$cap" -Y "$MGMT_Y" -T fields -e wlan.bssid -e wlan.ssid -E occurrence=f -E separator=$'\t' 2>/dev/null \
  | awk -F'\t' 'NF && $1 != "" {
      b=tolower($1);
      if (b!="ff:ff:ff:ff:ff:ff" && b!="00:00:00:00:00:00") print b "\t" $2
    }' \
  | while IFS=$'\t' read -r b s; do
      local ns
      ns=$(normalize_hex "${s:-}")
      if [[ -n "$ns" ]]; then
        if [[ "$ns" == "$hw" || "$ns" == "$nh" ]]; then out["$b"]=1; fi
      else
        if [[ -n "${s:-}" && "$s" == "$want_ascii" ]]; then out["$b"]=1; fi
      fi
    done
  ((${#out[@]})) && printf '%s\n' "${!out[@]}" | sort -u || return 1
}

# ---- ESSID/BSSID maps --------------------------------------------------------
declare -A essid_to_bssids=()
declare -A label_to_bssids=()

make_label_ascii_pref() {
  local k=$1 nh dec
  nh=$(normalize_hex "$k")
  if [[ -n "$nh" ]]; then
    if is_hex_even "$nh"; then
      dec="$(hex_to_ascii_best "$nh" || true)"
      if [[ -n "${dec:-}" ]]; then printf '%s' "$(ascii_one_line "$dec")"; return; fi
      printf '%s' "$nh"; return
    fi
    printf '%s' "$nh"; return
  fi
  printf '%s' "$(ascii_one_line "$k")"
}

build_essid_map() {
  # First pass: prefer wlan_mgt.ssid with fallback to wlan.ssid in same row
  mapfile -t raw_pairs < <(
    tshark -r "$file" -Y "$MGMT_Y" \
      -T fields -e wlan.bssid -e wlan_mgt.ssid -e wlan.ssid \
      -E occurrence=f -E separator=$'\t' 2>/dev/null \
    | awk -F'\t' '{
        b=tolower($1); s=$2; if(s=="") s=$3;
        if (b!="" && b!="ff:ff:ff:ff:ff:ff" && b!="00:00:00:00:00:00" && s!="") print b "\t" s
      }' \
    | sort -u
  )

  if ((${#raw_pairs[@]} == 0)); then
    # Raw fallback (older traces)
    mapfile -t raw_pairs < <(
      tshark -r "$file" -Y "$MGMT_Y" -T fields -e wlan.bssid -e wlan.ssid \
        -E occurrence=f -E separator=$'\t' 2>/dev/null \
      | awk -F'\t' 'NF>=2 && $1!="" {
          b=tolower($1);
          if (b!="ff:ff:ff:ff:ff:ff" && b!="00:00:00:00:00:00" && $2!="") print b "\t" $2
        }' \
      | sort -u
    )
  fi

  local line bssid ssid_raw nh dec label
  for line in "${raw_pairs[@]:-}"; do
    bssid=${line%%$'\t'*}; ssid_raw=${line#*$'\t'}
    nh=$(normalize_hex "$ssid_raw")
    if [[ -n "$nh" ]]; then
      if is_hex_even "$nh"; then
        essid_to_bssids["$nh"]+="$bssid"$'\n'
        dec="$(hex_to_ascii_best "$nh" || true)"; [[ -n "${dec:-}" ]] && essid_to_bssids["$dec"]+="$bssid"$'\n'
      else
        essid_to_bssids["$nh"]+="$bssid"$'\n'
      fi
      label="$(make_label_ascii_pref "$nh")"
    else
      essid_to_bssids["$ssid_raw"]+="$bssid"$'\n'
      label="$(make_label_ascii_pref "$ssid_raw")"
    fi
    label_to_bssids["$label"]+="$bssid"$'\n'
  done
}
build_essid_map

# ---- Selection ---------------------------------------------------------------
declare -A bssid_set=()

if [[ ${#essids[@]} -gt 0 ]]; then
  for want in "${essids[@]}"; do
    matched=0
    if [[ -n "${essid_to_bssids[$want]+x}" ]]; then
      while IFS= read -r b; do [[ -n "$b" ]] && bssid_set["$b"]=1; done <<<"${essid_to_bssids[$want]}"
      matched=1
    fi
    if (( !matched )); then
      hw=$(to_hex "$want")
      if [[ -n "${essid_to_bssids[$hw]+x}" ]]; then
        while IFS= read -r b; do [[ -n "$b" ]] && bssid_set["$b"]=1; done <<<"${essid_to_bssids[$hw]}"
        matched=1
      fi
    fi
    if (( !matched )); then
      nw=$(normalize_hex "$want")
      if [[ -n "$nw" && -n "${essid_to_bssids[$nw]+x}" ]]; then
        while IFS= read -r b; do [[ -n "$b" ]] && bssid_set["$b"]=1; done <<<"${essid_to_bssids[$nw]}"
        matched=1
      fi
    fi
    if (( !matched )); then
      mapfile -t fb < <(resolve_bssids_from_raw_ssid "$file" "$want" || true)
      if [[ ${#fb[@]} -gt 0 ]]; then
        for b in "${fb[@]}"; do [[ -n "$b" ]] && bssid_set["$b"]=1; done
        matched=1
      fi
    fi
    (( matched )) || printf 'Warning: ESSID not found (ascii/hex): %s\n' "$want" >&2
  done
else
  if [[ ${#label_to_bssids[@]} -eq 0 ]]; then
    echo "No SSIDs present in capture — falling back to BSSID-only selection." >&2
    mapfile -t only_bssids < <(
      tshark -r "$file" -Y '(wlan.fc.type == 0)' -T fields -e wlan.bssid 2>/dev/null \
      | awk '{
          b=tolower($0);
          if (b!="ff:ff:ff:ff:ff:ff" && b!="00:00:00:00:00:00") print b
        }' \
      | sort -u
    )
    [[ ${#only_bssids[@]} -gt 0 ]] || { echo "No BSSIDs found in capture." >&2; exit 1; }
    need fzf
    mapfile -t picked < <(printf '%s\n' "${only_bssids[@]}" | fzf --multi --prompt="Select BSSIDs: ")
    [[ ${#picked[@]} -gt 0 ]] || { echo "No BSSIDs selected." >&2; exit 1; }
    for b in "${picked[@]}"; do [[ -n "$b" ]] && bssid_set["$b"]=1; done
    essids=("BSSID-ONLY")
  else
    need fzf
    mapfile -t labels < <(printf '%s\n' "${!label_to_bssids[@]}" | sort -u)
    maxlen=0; for L in "${labels[@]}"; do (( ${#L} > maxlen )) && maxlen=${#L}; done
    mapfile -t display_rows < <(
      for L in "${labels[@]}"; do
        # cheaper count than sed|wc
        cnt=$(printf '%s' "${label_to_bssids[$L]}" | grep -c '[0-9a-f]')
        printf "%-*s  (%d BSSID%s)\t%s\n" "$maxlen" "$L" "$cnt" "$([[ $cnt -eq 1 ]] && echo "" || echo "s")" "$L"
      done
    )
    mapfile -t picked_labels < <(
      printf '%s\n' "${display_rows[@]}" \
      | fzf --multi --delimiter=$'\t' --with-nth=1 --prompt="Select ESSIDs: " \
      | cut -f2
    )
    [[ ${#picked_labels[@]} -gt 0 ]] || { echo "No ESSIDs selected." >&2; exit 1; }
    for L in "${picked_labels[@]}"; do
      while IFS= read -r b; do [[ -n "$b" ]] && bssid_set["$b"]=1; done <<<"${label_to_bssids[$L]}"
    done
    essids=("${picked_labels[@]}")
  fi
fi

# Safety: never keep broadcast/null
unset 'bssid_set["ff:ff:ff:ff:ff:ff"]' 'bssid_set["00:00:00:00:00:00"]'
((${#bssid_set[@]})) || { echo "No BSSIDs resolved for selected ESSIDs." >&2; exit 1; }

# ---- Channel/frequency collection -------------------------------------------
declare -A chan_set=() freq_set=() chan_banded_set=() chan_filtered_set=()
removed_dfs=0

band_letter_for_freq(){
  local f=$1
  if   [[ $f -ge 2400  && $f -le 2500 ]];  then printf 'a'
  elif [[ $f -ge 5000  && $f -le 5900 ]];  then printf 'b'
  elif [[ $f -ge 5925  && $f -le 7125 ]];  then printf 'c'
  elif [[ $f -ge 57000 && $f -le 71000 ]]; then printf 'd'
  elif [[ $f -ge 800   && $f -le 1000 ]];  then printf 'e'
  fi
}
channel_from_freq(){
  local f=$1
  if   [[ $f -ge 2412 && $f -le 2472 ]]; then printf '%d' $(( (f - 2412)/5 + 1 ))
  elif [[ $f -eq 2484 ]]; then printf '14'
  elif [[ $f -ge 5000 && $f -le 5900 ]]; then printf '%d' $(( (f - 5000)/5 ))
  elif [[ $f -ge 5925 && $f -le 7125 ]]; then printf '%d' $(( (f - 5955)/5 + 1 ))
  fi
}

collect_from_lines(){
  while IFS=$'\t' read -r f1 f2 f3; do
    local freq=""; [[ -n "${f1:-}" && $f1 != 0 ]] && freq=$f1
    [[ -z "$freq" && -n "${f2:-}" && $f2 != 0 ]] && freq=$f2
    if [[ -n "$freq" ]]; then
      freq_set["$freq"]=1
      local ch; ch=$(channel_from_freq "$freq" || true)
      if [[ -n "$ch" ]]; then
        chan_set["$ch"]=1
        local bletter; bletter=$(band_letter_for_freq "$freq" || true)
        [[ -n "$bletter" ]] && chan_banded_set["${ch}${bletter}"]=1
      fi
    else
      local ch="${f3:-}"
      [[ -n "$ch" && "$ch" =~ ^[0-9]+$ ]] && chan_set["$ch"]=1
    fi
  done
}

# Query PER-BSSID to avoid brittle giant OR filters
mapfile -t SELECTED_BSSIDS < <(printf '%s\n' "${!bssid_set[@]}" | sort -V)

for mac in "${SELECTED_BSSIDS[@]}"; do
  collect_from_lines < <(
    tshark -r "$file" \
      -Y "(wlan.fc.type_subtype == 0x08) && (wlan.bssid == ${mac})" \
      -T fields -e radiotap.channel.freq -e wlan_radio.frequency -e wlan_radio.channel \
      -E occurrence=f -E separator=$'\t' 2>/dev/null
  )
  if (( ${#freq_set[@]} == 0 && ${#chan_set[@]} == 0 )); then
    collect_from_lines < <(
      tshark -r "$file" \
        -Y "(wlan.fc.type == 0) && (wlan.bssid == ${mac})" \
        -T fields -e radiotap.channel.freq -e wlan_radio.frequency -e wlan_radio.channel \
        -E occurrence=f -E separator=$'\t' 2>/dev/null
    )
  fi
done

# DFS filter (applies to the plain channel list)
is_dfs(){ local c=$1; { [[ $c -ge 52 && $c -le 64 ]] || [[ $c -ge 100 && $c -le 144 ]]; }; }
for c in "${!chan_set[@]}"; do
  if (( include_dfs )); then
    chan_filtered_set["$c"]=1
  else
    if is_dfs "$c"; then removed_dfs=1; else chan_filtered_set["$c"]=1; fi
  fi
done

channel_list="" banded_list="" freq_list=""
((${#chan_filtered_set[@]})) && channel_list=$(printf '%s\n' "${!chan_filtered_set[@]}" | sort -n | paste -sd, -)
((${#chan_banded_set[@]}))   && banded_list=$(printf '%s\n' "${!chan_banded_set[@]}" | sort -V | paste -sd, -)
((${#freq_set[@]}))          && freq_list=$(printf '%s\n' "${!freq_set[@]}" | sort -n | paste -sd, -)

# ---- BPF compile -------------------------------------------------------------
build_clause(){
  local mac=$1 mode=$2 m
  m=$(printf '%s' "$mac" | tr 'A-F' 'a-f')
  if [[ "$mode" == "3" ]]; then
    printf 'wlan addr3 %s' "$m"
  else
    printf '(wlan addr1 %s or wlan addr2 %s or wlan addr3 %s or wlan addr4 %s)' "$m" "$m" "$m" "$m"
  fi
}
build_expr_for_bssids(){
  local mode=$1; shift
  local out="" clause
  for mac in "$@"; do
    clause=$(build_clause "$mac" "$mode")
    out=${out:+"$out or "}$clause
  done
  printf '%s' "$out"
}
compile_expr_to_bcf(){
  local expr=$1 out=$2 filterfile="$TMPDIR/filter.expr"
  printf '%s\n' "$expr" > "$filterfile"
  tcpdump -s 1024 -y IEEE802_11_RADIO -F "$filterfile" -ddd > "$out" 2>"$TMPDIR/tcpdump.err"
}

# ---- Outputs -----------------------------------------------------------------
bcf_base="${file}.bcf"
bssid_out="${file}.bssids"
targets_out="${file}.targets.json"

printf '%s\n' "${!bssid_set[@]}" | sort -V > "$bssid_out"

# ---- Compile flow with chunking fallback -------------------------------------
mapfile -t ALL_BSSIDS < <(printf '%s\n' "${!bssid_set[@]}" | sort -V)

try_mode="$addr_mode"
compiled_parts=()

expr=$(build_expr_for_bssids "$try_mode" "${ALL_BSSIDS[@]}")
if compile_expr_to_bcf "$expr" "$bcf_base"; then
  compiled_parts=( "$bcf_base" )
else
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

if (( ${need_chunk:-0} )); then
  echo "Filter too large; splitting into parts..." >&2
  local_batch=$(( ${#ALL_BSSIDS[@]} > 64 ? 64 : ${#ALL_BSSIDS[@]} ))
  part=1 i=0
  while (( i < ${#ALL_BSSIDS[@]} )); do
    sz=$local_batch success=0
    while (( sz >= 1 )); do
      subset=( "${ALL_BSSIDS[@]:i:sz}" )
      expr=$(build_expr_for_bssids "$try_mode" "${subset[@]}")
      out="${file}.part$(printf '%02d' "$part").bcf"
      if compile_expr_to_bcf "$expr" "$out"; then
        compiled_parts+=( "$out" ); (( i += sz )); (( part++ )); success=1
        (( local_batch = sz < 128 ? sz*2 : 128 ))
        break
      else
        (( sz /= 2 ))
      fi
    done
    (( success )) || { echo "Failed to compile even a single-BSSID filter. Aborting." >&2; exit 1; }
  done
fi

# ---- Combined JSON (python) --------------------------------------------------
LISTDIR="$TMPDIR/jsonlists"
mkdir -p "$LISTDIR"

mapfile -t JSON_BSSIDS   < <(printf '%s\n' "${!bssid_set[@]}"        | sort -V)
mapfile -t JSON_CHANNELS < <(printf '%s\n' "${!chan_filtered_set[@]}" | sort -n)
mapfile -t JSON_BANDS    < <(printf '%s\n' "${!chan_banded_set[@]}"   | sort -V)
mapfile -t JSON_FREQS    < <(printf '%s\n' "${!freq_set[@]}"          | sort -n)

printf '%s\n' "${essids[@]:-}"        > "$LISTDIR/essids.lst"
printf '%s\n' "${JSON_BSSIDS[@]:-}"   > "$LISTDIR/bssids.lst"
printf '%s\n' "${JSON_CHANNELS[@]:-}" > "$LISTDIR/channels.lst"
printf '%s\n' "${JSON_BANDS[@]:-}"    > "$LISTDIR/bands.lst"
printf '%s\n' "${JSON_FREQS[@]:-}"    > "$LISTDIR/freqs.lst"

python3 - "$file" "$targets_out" "$include_dfs" "$removed_dfs" "$LISTDIR" <<'PY'
import json, sys, pathlib
cap = sys.argv[1]
out = sys.argv[2]
include_dfs = (sys.argv[3] == "1")
removed_dfs = (sys.argv[4] == "1")
listdir = pathlib.Path(sys.argv[5])

def read_strs(p):
    try:
        return [line.rstrip("\n") for line in open(p, "r", encoding="utf-8") if line.strip()]
    except FileNotFoundError:
        return []

def read_ints(p):
    vals = []
    try:
        for line in open(p, "r", encoding="utf-8"):
            s = line.strip()
            if s:
                try:
                    vals.append(int(s))
                except ValueError:
                    pass
    except FileNotFoundError:
        pass
    return vals

data = {
    "file": pathlib.Path(cap).name,
    "essids": read_strs(listdir / "essids.lst"),
    "bssids": read_strs(listdir / "bssids.lst"),
    "channels": read_ints(listdir / "channels.lst"),
    "bands": read_strs(listdir / "bands.lst"),
    "frequencies": read_ints(listdir / "freqs.lst"),
    "include_dfs": include_dfs,
    "dfs_channels_removed": removed_dfs,
}
with open(out, "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, indent=2)
PY

# ---- Summary -----------------------------------------------------------------
echo
echo "Selected ESSIDs:"
if [[ ${#essids[@]} -gt 0 ]]; then printf '  - %s\n' "${essids[@]}"; else echo "  - (derived from selection)"; fi

echo
echo "Resolved BSSIDs:"
nl -ba "$bssid_out" | sed 's/^/  /'

echo
if (( ${#compiled_parts[@]} == 1 )); then
  echo "Wrote BPF (-ddd) to: ${compiled_parts[0]}"
else
  echo "Wrote ${#compiled_parts[@]} BPF parts:"; for p in "${compiled_parts[@]}"; do echo "  - $p"; done
  echo "Use one part at a time with hcxdumptool's bpfc option (or rotate between them)."
fi

echo
echo "Combined JSON written to: $targets_out"

have_bands=0; have_freqs=0
[[ -n "${banded_list:-}" ]] && have_bands=1
[[ -n "${freq_list:-}"   ]] && have_freqs=1

echo "Example:"
if (( have_bands )); then
  if (( ${#compiled_parts[@]} == 1 )); then
    echo "  hcxdumptool -i <iface> -c $banded_list --bpfc=${compiled_parts[0]}"
  else
    echo "  hcxdumptool -i <iface> -c $banded_list --bpfc=${compiled_parts[0]}   # then rotate parts as needed"
  fi
elif (( have_freqs )); then
  if (( ${#compiled_parts[@]} == 1 )); then
    echo "  hcxdumptool -i <iface> -f $freq_list --bpfc=${compiled_parts[0]}"
  else
    echo "  hcxdumptool -i <iface> -f $freq_list --bpfc=${compiled_parts[0]}   # then rotate parts as needed"
  fi
else
  if (( ${#compiled_parts[@]} == 1 )); then
    echo "  hcxdumptool -i <iface> --bpfc=${compiled_parts[0]}"
  else
    echo "  hcxdumptool -i <iface> --bpfc=${compiled_parts[0]}   # then rotate parts as needed"
  fi
fi

(( debug_mode )) && { echo; echo "Final mode used for BPF: $try_mode"; }
