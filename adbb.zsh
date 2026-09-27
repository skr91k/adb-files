# adbb — start the Mac ⇄ Android file browser and open it in Chrome.
# Add to ~/.zshrc:   source /path/to/adb-files/adbb.zsh
#
#   adbb              start (asks which device if several are attached) and open
#   adbb <n|serial>   use device n from the list, or that serial
#   adbb stop         stop the server

_ADBB_DIR=${${(%):-%x}:A:h}

adbb() {
    local port=8090 url="http://localhost:8090/"
    local script="$_ADBB_DIR/adb_files.py"
    local log="/tmp/adb_files.log" serial_file="/tmp/adb_files.serial"
    local pid=$(lsof -tiTCP:$port -sTCP:LISTEN 2>/dev/null)
    if [ "$1" = "stop" ]; then
        [ -n "$pid" ] && kill $pid && echo "Stopped adb browser (pid $pid)" || echo "adb browser not running"
        return 0
    fi
    local devs=(${(f)"$(adb devices | awk 'NR>1 && $2=="device"{print $1}')"})
    if [ ${#devs} -eq 0 ]; then echo "No device connected (check USB / authorize debugging)"; return 1; fi
    local serial="" i
    if [ -n "$1" ]; then
        if [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le ${#devs} ]; then serial=${devs[$1]}
        elif (( ${devs[(Ie)$1]} )); then serial=$1
        else echo "Unknown device: $1"; return 1; fi
    elif [ ${#devs} -eq 1 ]; then
        serial=${devs[1]}
    else
        local cur=$(cat "$serial_file" 2>/dev/null)
        echo "Multiple devices:"
        for i in {1..${#devs}}; do
            local model=$(adb -s ${devs[$i]} shell getprop ro.product.model </dev/null 2>/dev/null | tr -d '\r')
            echo "  $i) $model  ${devs[$i]}$([ -n "$pid" ] && [ "${devs[$i]}" = "$cur" ] && echo '  (running)')"
        done
        local n; read "n?Pick device [1-${#devs}]: "
        if ! [[ "$n" =~ ^[0-9]+$ ]] || [ "$n" -lt 1 ] || [ "$n" -gt ${#devs} ]; then echo "Cancelled"; return 1; fi
        serial=${devs[$n]}
    fi
    if [ -n "$pid" ] && [ "$(cat "$serial_file" 2>/dev/null)" != "$serial" ]; then
        echo "Switching device: restarting adb browser"
        kill $pid; pid=""
        while lsof -tiTCP:$port -sTCP:LISTEN >/dev/null 2>&1; do sleep 0.2; done
    fi
    if [ -z "$pid" ]; then
        echo "Running: python3 adb_files.py on $serial (log: $log)"
        echo "$serial" > "$serial_file"
        ANDROID_SERIAL=$serial PORT=$port nohup python3 -u "$script" > "$log" 2>&1 &!
        for i in {1..20}; do
            curl -s -o /dev/null "$url" && break
            sleep 0.3
        done
        if ! curl -s -o /dev/null "$url"; then
            echo "Failed to start:"; cat "$log"; return 1
        fi
        grep "^Device" "$log"
    else
        echo "adb browser already running on $serial (pid $pid)"
    fi
    echo "Opening http://localhost:$port/ (Mac | Android) in Chrome"
    open -a "Google Chrome" "http://localhost:$port/"
}
