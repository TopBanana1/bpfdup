#!/bin/bash

# TODO: make it filter only on relevant channels

# initialise variables
debug_mode=0
file=""
essid=""
hexessid=""
filter=""

# help function
show_help() { 
  echo "Usage: $0 -f <file> -e <essid> [-d] [-h]"
  echo
  echo "Options:"
  echo "  -f <file>    Specify the file name."
  echo "  -e <essid>   Specify the essid."
  echo "  -d           Enable debug mode."
  echo "  -h           Show this help message."
  exit 0
}

# get command line arguments / display help
while getopts "f:e:dh" opt; do
  case $opt in
    f) file="$OPTARG" ;;  # Assign file from -f
    e) essid="$OPTARG" ;; # Assign essid from -e
    d) debug_mode=1 ;;    # Enable debug mode
    h) show_help ;;       # Display help
    *)
      echo "Invalid option. Use -h for help."
      exit 1
      ;;
  esac
done

# Check if required options are provided
if [[ -z "$file" || -z "$essid" ]]; then
    echo "Error: Both -f <file> and -e <essid> are required."
    echo "Usage: $0 -f <file> -e <essid>"
    echo "Use -h for help."
    exit 1
fi

# Debug mode: print debug information if enabled
if [[ $debug_mode -eq 1 ]]; then
    echo "Debug Mode Enabled"
	echo
    set -o xtrace
fi

# use tshark to filter out bssid and essid from the beacon packets in a capture file
echo "Filtering broadcast packets..."
filter=$(tshark -r telstra-01.cap -Y "wlan.fc.type_subtype == 0x08" -T fields -e wlan.bssid -e wlan.ssid)

# convert the essid to hex and remove the null byte at the end
echo "Converting ESSID to HEX..."
hexessid=$(echo "$essid" | xxd -p | sed 's/..$//')

# filter out the APs associated with the target BSSID
echo "Filtering packets containing target ESSID..."
filter=$(echo "$filter" | grep $hexessid)

# convert the list of BSSIDs to BPF format
echo "Converting to BPF plaintext format..."
filter=$(echo "$filter" | awk 'NR > 1 {printf "ether src %s or ", prev} {prev = $1} END {printf "ether src %s\n", prev}')

# compile the filter and output it to a file
echo "Compiling the filter and outputting to file..."
tcpdump -s 1024 -y IEEE802_11_RADIO "$(echo "$filter")" -ddd > ${file%.*}.bcf

# exit message
echo
echo "Done! Filter outputted to ${file%.*}.bcf"
