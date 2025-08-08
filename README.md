# bpfdup

**bpfdup** is a Bash utility for generating **Berkeley Packet Filters** (`.bcf` in tcpdump/libpcap `-ddd` format) from Wi‑Fi capture files, designed for targeting specific ESSIDs/BSSIDs with tools like [hcxdumptool](https://github.com/ZerBea/hcxdumptool).

It parses a capture file (`.pcap` / `.pcapng`), lets you select one or more ESSIDs (via CLI or [fzf](https://github.com/junegunn/fzf) picker), and produces:

- A `.bcf` filter for hcxdumptool
- A `.bssids` file listing the selected APs’ MAC addresses
- A `.channels` file with observed Wi‑Fi channels (DFS optional)

The generated BPF can **target specific APs** for capture/injection, reducing noise and attack footprint.

---

## Features

- **Multi‑ESSID support**
  - Select via `-e ESSID` (repeatable) or interactive `fzf` multi‑select
- **Two address modes**
  - `--addr-mode=3`: Matches only `wlan addr3` (smaller filter, safer for many BSSIDs)
  - `--addr-mode=all`: Matches `wlan addr1..addr4` (more complete, bigger filter)
- **Auto‑fallback & chunking**
  - If filter is too large, automatically retries with `addr3`
  - If still too big, splits into multiple `.bcf` parts
- **Channel detection**
  - Outputs `.channels` file for hcxdumptool’s `-c` option
  - DFS channels excluded by default (toggle with `-D`)
- **Temp file safety**
  - Cleans up automatically on exit

---

## Installation

Clone the repo and make the script executable:

```bash
git clone https://github.com/yourname/bpfdup.git
cd bpfdup
chmod +x bpfdup
```

Make sure it’s on your `$PATH`:

```bash
sudo ln -s "$PWD/bpfdup" /usr/local/bin/bpfdup
```

---

## Dependencies

- **Core tools:** `bash` (POSIX‑compatible), `awk`, `sed`, `grep`, `sort`
- **Packet tools:** `tshark` (Wireshark CLI), `tcpdump`
- **Optional:** `fzf` for interactive ESSID selection

Install on Debian/Kali:

```bash
sudo apt install tshark tcpdump fzf
```

---

## Usage

```bash
bpfdup -f <file> [-e <essid>]... [--addr-mode=3|all] [-D] [-d]
```

### Options

| Option                 | Description                                                                                  |
|------------------------|----------------------------------------------------------------------------------------------|
| `-f <file>`            | Capture file (`.pcap` or `.pcapng`)                                                          |
| `-e <essid>`           | ESSID to include (repeatable). If omitted, `fzf` picker is used                              |
| `--addr-mode=3`        | Match only `wlan addr3` (default; smaller filter)                                            |
| `--addr-mode=all`      | Match `wlan addr1..addr4` (larger filter, more complete)                                     |
| `-D`                   | Include DFS channels in `.channels` output                                                   |
| `-d`                   | Debug mode (`set -x`)                                                                        |
| `-h`                   | Show help                                                                                    |

---

## Output Files

Running:

```bash
bpfdup -f capture.pcapng -e CorpWiFi --addr-mode=all
```

might produce:

| File                        | Contents                                                        |
|-----------------------------|-----------------------------------------------------------------|
| `capture.pcapng.bcf`        | Compiled tcpdump/libpcap BPF program (-ddd format)             |
| `capture.pcapng.bssids`     | Line‑delimited list of selected BSSIDs                         |
| `capture.pcapng.channels`   | Comma‑delimited list of observed channels for those BSSIDs     |

If the filter is too large, output will be split:

```
capture.pcapng.part01.bcf
capture.pcapng.part02.bcf
...
```

---

## Example Workflows

### 1. Target a single ESSID
```bash
bpfdup -f office.pcapng -e CorpWiFi
hcxdumptool -i wlan0mon -c $(cat office.pcapng.channels) --bpfc=office.pcapng.bcf
```

### 2. Select interactively
```bash
bpfdup -f survey.pcapng
```
Use arrow keys + TAB in `fzf` to multi‑select ESSIDs.

### 3. Include DFS channels
```bash
bpfdup -f survey.pcapng -e GuestNet -D
```

### 4. Full address coverage
```bash
bpfdup -f survey.pcapng --addr-mode=all
```

---

## Why addr3 vs addr1..4?

- **`addr3` only:** Minimal filter size, avoids kernel BPF complexity limits, but may miss some non‑beacon frames.
- **`addr1..addr4`:** Matches all 802.11 address fields, catches more frame types, but grows quickly and can hit the “expression too complex” limit. `bpfdup` auto‑falls back to `addr3` and, if needed, auto‑chunks into parts.

---

## Limitations

- BPF cannot filter by frequency directly — `.channels` output is meant for hcxdumptool’s `-c` option.
- If a capture has hundreds of APs, even `addr3` mode may require chunking into multiple `.bcf` files.
- Requires `tshark` to parse captures; won’t work on systems without it.

---

## License

MIT — do whatever you like, but attribution is appreciated.
