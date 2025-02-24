#!/bin/bash

# TODO:
# make it so that if the capture file has channels / frequency data for each AP in scope, it adds frequency restrictions to the filter

# do I need all these variables? probably not
debug_mode=0
file=""
essid=""
hexessid=""
filter=""

# I dont want anyone to think im capable/caring enough to write a help function. this was chatgpt.
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

if [[ -z "$file" || -z "$essid" ]]; then
    echo "Error: Both -f <file> and -e <essid> are required."
    echo "Usage: $0 -f <file> -e <essid>"
    echo "Use -h for help."
    exit 1
fi

# this is what Linux mastery looks like
if [[ $debug_mode -eq 1 ]]; then
    echo "Debug Mode Enabled"
	echo
    set -o xtrace
fi

# get the beacon packets from capture file and filter out a list of bssid and essid
echo "Filtering broadcast packets..."
filter=$(tshark -r telstra-01.cap -Y "wlan.fc.type_subtype == 0x08" -T fields -e wlan.bssid -e wlan.ssid)

# so it turns out tshark pulls out hex values so we either unhex all essid and compare to input or we give up and join them in using hex. also xxd adds null byte at the end that we dont want so sed that off
echo "Converting ESSID to HEX..."
hexessid=$(echo "$essid" | xxd -p | sed 's/..$//')

echo "Filtering packets containing target ESSID..."
filter=$(echo "$filter" | grep $hexessid)

# ok so we have to use wlan addr3 because wlan addr3 is the router's bssid which is obviously way different from addr2 which is the router's mac address. I love networking
echo "Converting to BPF plaintext format..."
filter=$(echo "$filter" | awk 'NR > 1 {printf "wlan addr3 %s or ", prev} {prev = $1} END {printf "wlan addr3 %s\n", prev}')

# we dont need the whole packet, 1024 is double of what would be considered more than enough. if your nic is bad make it 512
echo "Compiling the filter and outputting to file..."
tcpdump -s 1024 -y IEEE802_11_RADIO "$(echo "$filter")" -ddd > ${file%.*}.bcf

echo
echo "Done! Filter outputted to ${file%.*}.bcf"
