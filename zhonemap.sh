#!/bin/bash

# ==============================================================================
# Script: ZhoneMap.sh
# Description: Connects to a Zhone router via legacy SSH to extract routing 
#              and ARP tables, then formats the data into a readable CLI report
#              and optionally exports it to a JSON file.
# ==============================================================================

# --- Modern Terminal Colors & Styles ---
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# --- Default Settings ---
ROUTER_USER="admin"
ROUTER_IP="192.168.1.1"

# --- Default Aggressive Legacy SSH Options (Required for older routers) ---
DEFAULT_SSH_OPTS="-c 3des-cbc -oHostKeyAlgorithms=+ssh-rsa -p 22"

VERBOSE_LEVEL=0
MINIMAL_MODE=0
OUTPUT_FILE=""
CUSTOM_SSH=0

# --- Help Menu ---
show_help() {
    echo -e "${CYAN}${BOLD}Zhone Router Enumeration Tool${NC}"
    echo -e "Usage: $0 [OPTIONS]\n"
    echo -e "${BOLD}Options:${NC}"
    echo -e "  -u <user>        Set router SSH username (default: admin)"
    echo -e "  -ip <ip>         Set router IP address (default: 192.168.1.1)"
    echo -e "  -c, --custom-ssh Prompt for custom SSH options"
    echo -e "  -v, --verbose    Level 1 Verbosity: Show injection steps"
    echo -e "  -vv              Level 2 Verbosity: Show live output and SSH debug"
    echo -e "  -m, --minimum    Minimal output mode (no colors/formatting)"
    echo -e "  -o, --output [f] Export results to a JSON file (default: zhonemap.json if no file provided)"
    echo -e "  -h, --help       Display this help message and exit\n"
    exit 0
}

# --- Input Parsing (Flags) ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) show_help ;;
        -u) ROUTER_USER="$2"; shift 2 ;;
        -ip) ROUTER_IP="$2"; shift 2 ;;
        -c|--custom-ssh) CUSTOM_SSH=1; shift ;;
        -v|--verbose) VERBOSE_LEVEL=1; shift ;;
        -vv) VERBOSE_LEVEL=2; shift ;;
        -m|--minimum) MINIMAL_MODE=1; shift ;;
        -o|--output) 
            if [[ -n "$2" && "$2" != -* ]]; then
                OUTPUT_FILE="$2"
                shift 2
            else
                OUTPUT_FILE="zhonemap.json"
                shift 1
            fi
            ;;
        *) shift ;;
    esac
done

# --- Apply Minimal Formatting Overrides ---
if [[ "$MINIMAL_MODE" -eq 1 ]]; then
    # Wipe color and formatting variables
    RED=''; GREEN=''; YELLOW=''; BLUE=''; MAGENTA=''; CYAN=''; WHITE=''; DIM=''; BOLD=''; NC=''
fi

# --- Banner & Prompts ---
if [[ "$MINIMAL_MODE" -eq 0 ]]; then
    echo -e "\n${CYAN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║              ZHONE ROUTER ENUMERATION TOOL               ║${NC}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}\n"
    
    SSH_OPTS="$DEFAULT_SSH_OPTS"
    if [[ "$CUSTOM_SSH" -eq 1 ]]; then
        echo -e "${DIM}Default SSH options: ${DEFAULT_SSH_OPTS}${NC}"
        echo -n -e "🛠️  Enter custom SSH options (press Enter to keep default): "
        read USER_SSH_OPTS
        SSH_OPTS="${USER_SSH_OPTS:-$DEFAULT_SSH_OPTS}"
    fi
    
    echo -n -e "🔑 Enter Router Password for [$ROUTER_USER@$ROUTER_IP]: "
    read -s ROUTER_PASS
    echo -e "\n\n${YELLOW}[⏳] Initializing connection to router CLI...${NC}"
else
    echo -e "Zhone Router Enumeration Tool (Minimal Mode)"
    
    SSH_OPTS="$DEFAULT_SSH_OPTS"
    if [[ "$CUSTOM_SSH" -eq 1 ]]; then
        echo -n "SSH options [$DEFAULT_SSH_OPTS]: "
        read USER_SSH_OPTS
        SSH_OPTS="${USER_SSH_OPTS:-$DEFAULT_SSH_OPTS}"
    fi
    
    echo -n "Password for [$ROUTER_USER@$ROUTER_IP]: "
    read -s ROUTER_PASS
    echo -e "\nInitializing connection..."
fi

# --- Apply SSH Verbosity based on level ---
if [[ $VERBOSE_LEVEL -ge 2 ]]; then
    SSH_OPTS="$SSH_OPTS -v"
fi

# ==============================================================================
# EXPECT SESSION: Automates the SSH login and command execution
# wrapped in a function for cleaner conditional execution.
# ==============================================================================
RUN_EXPECT() {
    expect <<EOF
set timeout 15
match_max 100000

# Level 1+ Verbosity: Print injection steps
proc log_v {msg} {
    if { $VERBOSE_LEVEL >= 1 } {
        if { $MINIMAL_MODE == 1 } {
            send_error "\r\n\[-v\] \$msg\r\n"
        } else {
            send_error "\r\n\033\[1;35m\[-v\] \033\[1;37m\$msg\033\[0m\r\n"
        }
    }
}

log_v "Spawning SSH session: ssh $SSH_OPTS $ROUTER_USER@$ROUTER_IP"
spawn ssh $SSH_OPTS $ROUTER_USER@$ROUTER_IP

# Login and Privilege Escalation Loop
expect {
    -re ".*Are you sure you want to continue connecting.*" {
        log_v "Accepting unknown host key..."
        send "yes\r"
        exp_continue
    }
    -nocase "password:" {
        sleep 0.5
        log_v "Providing password..."
        send "$ROUTER_PASS\r"
        exp_continue
    }
    "Permission denied" {
        exit 2
    }
    ">" {
        log_v "Dropped into standard mode. Injecting 'enable' for privilege escalation..."
        send "enable\r"
        exp_continue
    }
    "#" {
        log_v "Successfully reached privileged mode '#'."
    }
    timeout {
        exit 1
    }
    eof {
        exit 3
    }
}

# Now at the '#' prompt. Send command FIRST, then expect the next prompt.
log_v "Injecting command: show ip"
send "show ip\r"
expect {
    -re "--More--|Press any key to continue" { send " "; exp_continue }
    "(show-ip)#"
}

log_v "Injecting command: route"
send "route\r"
expect {
    -re "--More--|Press any key to continue" { send " "; exp_continue }
    "(show-ip)#"
}

log_v "Injecting command: arp"
send "arp\r"
expect {
    -re "--More--|Press any key to continue" { send " "; exp_continue }
    "(show-ip)#"
}

log_v "Injecting command: exit (returning to root menu)"
send "exit\r"
expect {
    -re "--More--|Press any key to continue" { send " "; exp_continue }
    "#"
}

log_v "Injecting command: show arp (global fallback)"
send "show arp\r"
expect {
    -re "--More--|Press any key to continue" { send " "; exp_continue }
    "#"
}

log_v "Injecting command: show ip arp (global fallback)"
send "show ip arp\r"
expect {
    -re "--More--|Press any key to continue" { send " "; exp_continue }
    "#"
}

log_v "Injecting command: logout (closing session)"
send "logout\r"
expect eof
EOF
}

# Level 2+ Verbosity: Pipe process live to the screen (stderr) while still capturing to RAW_OUTPUT
if [[ $VERBOSE_LEVEL -ge 2 ]]; then
    RAW_OUTPUT=$(RUN_EXPECT | tee /dev/stderr)
    EXIT_CODE=${PIPESTATUS[0]} # Preserve expect's exit code instead of tee's
else
    RAW_OUTPUT=$(RUN_EXPECT)
    EXIT_CODE=$?
fi

# --- Check the exit status from Expect ---
if [ $EXIT_CODE -eq 2 ]; then
    if [[ "$MINIMAL_MODE" -eq 0 ]]; then echo -e "${RED}[!] Authentication Failed: Incorrect Password.${NC}"; else echo "Error: Authentication Failed."; fi
    exit 1
elif [ $EXIT_CODE -eq 3 ]; then
    if [[ "$MINIMAL_MODE" -eq 0 ]]; then
        echo -e "${RED}[!] Connection Dropped: Router abruptly closed the SSH connection.${NC}"
        echo -e "${DIM}    (Check if the password is correct, or if the router only supports Telnet).${NC}"
    else
        echo "Error: Connection Dropped."
    fi
    exit 1
elif [ $EXIT_CODE -eq 1 ]; then
    if [[ "$MINIMAL_MODE" -eq 0 ]]; then echo -e "${RED}[!] Connection Timed Out: Router did not respond in time.${NC}"; else echo "Error: Connection Timed Out."; fi
    exit 1
fi

if [[ "$MINIMAL_MODE" -eq 0 ]]; then
    echo -e "${GREEN}[✔] Data Captured Successfully. Processing outputs...${NC}\n"
else
    echo "Data captured. Processing..."
fi

# ==============================================================================
# DATA PROCESSING & FORMATTING
# ==============================================================================

# STEP 1: Clean the raw output (Remove \r and ANSI color codes)
CLEAN_OUTPUT=$(echo "$RAW_OUTPUT" | tr -d '\r' | sed 's/\x1b\[[0-9;]*m//g')

# ------------------------------------------------------------------------------
# STEP 2: Extract & Explain the Routing Table
# ------------------------------------------------------------------------------
if [[ "$MINIMAL_MODE" -eq 0 ]]; then
    echo -e "${BLUE}╭────────────────────────────────────────────────────────╮${NC}"
    echo -e "${BLUE}│ 🗺️  1. ROUTING TABLE (Network Traffic Pathways)        │${NC}"
    echo -e "${BLUE}╰────────────────────────────────────────────────────────╯${NC}"
else
    echo -e "\n--- 1. ROUTING TABLE ---"
fi

# Find IPs but EXCLUDE any lines containing MAC addresses to isolate the route table
ROUTE_LIST=$(echo "$CLEAN_OUTPUT" | awk '/route/,/exit/' | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -viE '([0-9a-f]{2}[:-]){5}[0-9a-f]{2}')

if [[ -z "$ROUTE_LIST" ]]; then
    if [[ "$MINIMAL_MODE" -eq 0 ]]; then echo -e "  ${RED}No routing data found in the output.${NC}\n"; else echo "  No routing data found."; fi
else
    echo "$ROUTE_LIST" | while read -r line; do
        if [[ "$MINIMAL_MODE" -eq 1 ]]; then
            # Minimal Routing Outputs
            if echo "$line" | grep -q "^0\.0\.0\.0"; then echo "  [Default Gateway] $line"
            elif echo "$line" | grep -q "^127\."; then echo "  [Loopback]        $line"
            elif echo "$line" | grep -E -q "^(224|239)\."; then echo "  [Multicast]       $line"
            elif echo "$line" | grep -q "255\.255\.255\.255"; then echo "  [Broadcast]       $line"
            else echo "  [Local Subnet]    $line"
            fi
        else
            # Fancy Routing Outputs
            if echo "$line" | grep -q "^0\.0\.0\.0"; then
                echo -e "  🌍 ${GREEN}${BOLD}[Default Gateway / WAN]${NC}"
                echo -e "      ${DIM}└─ All external (Internet) traffic is routed through here.${NC}"
                echo -e "      ${WHITE}└─ $line${NC}\n"
            elif echo "$line" | grep -q "^127\."; then
                echo -e "  🔄 ${CYAN}${BOLD}[Loopback Interface]${NC}"
                echo -e "      ${DIM}└─ Used by the router internally to communicate with itself.${NC}"
                echo -e "      ${WHITE}└─ $line${NC}\n"
            elif echo "$line" | grep -E -q "^(224|239)\."; then
                echo -e "  📡 ${MAGENTA}${BOLD}[Multicast Route]${NC}"
                echo -e "      ${DIM}└─ Used for streaming services and device discovery protocols.${NC}"
                echo -e "      ${WHITE}└─ $line${NC}\n"
            elif echo "$line" | grep -q "255\.255\.255\.255"; then
                echo -e "  📢 ${YELLOW}${BOLD}[Broadcast Route]${NC}"
                echo -e "      ${DIM}└─ Used to broadcast messages to EVERY device on the network.${NC}"
                echo -e "      ${WHITE}└─ $line${NC}\n"
            else
                echo -e "  💻 ${BLUE}${BOLD}[Local Subnet Route]${NC}"
                echo -e "      ${DIM}└─ Internal traffic destined for devices connected to the router.${NC}"
                echo -e "      ${WHITE}└─ $line${NC}\n"
            fi
        fi
    done
fi

# ------------------------------------------------------------------------------
# STEP 3: Extract & Explain the ARP Table (Connected Devices)
# ------------------------------------------------------------------------------
if [[ "$MINIMAL_MODE" -eq 0 ]]; then
    echo -e "${BLUE}╭────────────────────────────────────────────────────────╮${NC}"
    echo -e "${BLUE}│ 📱 2. CONNECTED DEVICES (ARP Cache)                    │${NC}"
    echo -e "${BLUE}╰────────────────────────────────────────────────────────╯${NC}"
else
    echo -e "\n--- 2. CONNECTED DEVICES ---"
fi

# Extract lines containing MAC addresses, trim leading spaces, and remove duplicates
ARP_LIST=$(echo "$CLEAN_OUTPUT" | grep -iE '([0-9a-f]{2}[:-]){5}[0-9a-f]{2}' | sed 's/^[ \t]*//' | sort -u)

if [[ -z "$ARP_LIST" ]]; then
    if [[ "$MINIMAL_MODE" -eq 0 ]]; then
        echo -e "  ${RED}No connected devices found (ARP table is empty or command failed).${NC}"
        echo -e "\n  ${DIM}[DEBUG] Router's raw response to ARP commands:${NC}"
        echo "$CLEAN_OUTPUT" | grep -iA 3 "arp" | grep -vE "(show|exit)" | head -n 6 | sed 's/^/    /'
        echo ""
    else
        echo "  No connected devices found."
    fi
else
    DEVICE_COUNT=$(echo "$ARP_LIST" | wc -l | tr -d ' ')
    if [[ "$MINIMAL_MODE" -eq 0 ]]; then
        echo -e "  ${GREEN}[*] Discovered ${BOLD}$DEVICE_COUNT${NC}${GREEN} active device(s) on the network.${NC}\n"
    else
        echo "  Discovered $DEVICE_COUNT active device(s):"
    fi
    
    echo "$ARP_LIST" | while read -r line; do
        # Extract specific pieces of data
        IP_ADDR=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)
        MAC_ADDR=$(echo "$line" | grep -iE -o '([0-9a-f]{2}[:-]){5}[0-9a-f]{2}')
        IFACE=$(echo "$line" | awk '{print $NF}') # Usually the last column
        
        if [[ "$MINIMAL_MODE" -eq 1 ]]; then
            # Minimal ARP row
            NOTES="Client"
            if [[ "$IP_ADDR" == "$ROUTER_IP" ]]; then NOTES="Router"
            elif echo "$MAC_ADDR" | grep -iq "ff:ff:ff:ff:ff:ff"; then NOTES="Broadcast"
            fi
            echo "  IP: $(printf '%-15s' "$IP_ADDR") | MAC: $(printf '%-17s' "$MAC_ADDR") | IF: $(printf '%-6s' "$IFACE") | $NOTES"
        else
            # Fancy ARP row
            NOTES="${DIM}Standard Client Device${NC}"
            if [[ "$IP_ADDR" == "$ROUTER_IP" ]]; then 
                NOTES="${YELLOW}${BOLD}⭐ Router (Gateway)${NC}"
            elif echo "$MAC_ADDR" | grep -iq "ff:ff:ff:ff:ff:ff"; then
                NOTES="${MAGENTA}Broadcast MAC${NC}"
            fi
            echo -e "  🖥️  IP: ${GREEN}$(printf '%-15s' "$IP_ADDR")${NC} │ MAC: ${CYAN}$(printf '%-17s' "$MAC_ADDR")${NC} │ IF: ${WHITE}$(printf '%-6s' "$IFACE")${NC} │ $NOTES"
        fi
    done
    if [[ "$MINIMAL_MODE" -eq 0 ]]; then echo ""; fi
fi

# ------------------------------------------------------------------------------
# STEP 4: Global Network & Security Context
# ------------------------------------------------------------------------------
if [[ "$MINIMAL_MODE" -eq 0 ]]; then
    echo -e "${BLUE}╭────────────────────────────────────────────────────────╮${NC}"
    echo -e "${BLUE}│ 🛡️  3. GLOBAL NETWORK & SESSION INFO                   │${NC}"
    echo -e "${BLUE}╰────────────────────────────────────────────────────────╯${NC}"
    echo -e "  ${DIM}Fetching external IP profile...${NC}"
else
    echo -e "\n--- 3. GLOBAL NETWORK & SESSION INFO ---"
fi

PUBLIC_IP=$(curl -s --connect-timeout 5 https://api.ipify.org || curl -s --connect-timeout 5 https://icanhazip.com || curl -s --connect-timeout 5 https://ifconfig.me)
RAW_PUBLIC_IP="$PUBLIC_IP" # Save raw IP before applying any color formatting

if [[ "$MINIMAL_MODE" -eq 1 ]]; then
    # Minimal Summary
    [[ -z "$PUBLIC_IP" ]] && PUBLIC_IP="[Failed]"

    echo "  • Public IP       : $PUBLIC_IP"
    echo "  • Local Router IP : $ROUTER_IP"
    echo "  • Authenticated As: $ROUTER_USER"
    echo ""
else
    # Fancy Summary
    if [[ -z "$PUBLIC_IP" ]]; then
        PUBLIC_IP="${RED}[Failed to reach external IP APIs]${NC}"
    else
        PUBLIC_IP="${GREEN}${BOLD}$PUBLIC_IP${NC}"
    fi

    echo -e "  • Public IP Address : $PUBLIC_IP"
    echo -e "  • Local Router IP   : ${WHITE}$ROUTER_IP${NC}"
    echo -e "  • Authenticated As  : ${WHITE}$ROUTER_USER${NC}"
    echo -e "\n${CYAN}${BOLD}════════════════════════════════════════════════════════════${NC}\n"
fi

# ==============================================================================
# STEP 5: Export to JSON (If requested via -o/--output)
# ==============================================================================
if [[ -n "$OUTPUT_FILE" ]]; then
    # Calculate Array Sizes for the JSON Payload
    ROUTE_COUNT=0
    [[ -n "$ROUTE_LIST" ]] && ROUTE_COUNT=$(echo "$ROUTE_LIST" | wc -l | tr -d ' ')
    
    ARP_COUNT=0
    [[ -n "$ARP_LIST" ]] && ARP_COUNT=$(echo "$ARP_LIST" | wc -l | tr -d ' ')

    # Manually building JSON to avoid requiring 'jq' dependency on the target system
    {
        echo "{"
        echo "  \"session_info\": {"
        echo "    \"public_ip\": \"${RAW_PUBLIC_IP:-Failed}\","
        echo "    \"local_router_ip\": \"$ROUTER_IP\","
        echo "    \"authenticated_as\": \"$ROUTER_USER\""
        echo "  },"
        echo "  \"total_route_entries\": $ROUTE_COUNT,"
        echo "  \"total_arp_entries\": $ARP_COUNT,"

        echo "  \"routing_table\": ["
        FIRST_ROUTE=1
        if [[ -n "$ROUTE_LIST" ]]; then
            while read -r r_line; do
                [[ -z "$r_line" ]] && continue
                if [[ $FIRST_ROUTE -eq 1 ]]; then FIRST_ROUTE=0; else echo ","; fi
                
                # Determine route type similarly to CLI output logic
                if echo "$r_line" | grep -q "^0\.0\.0\.0"; then ROUTE_TYPE="Default Gateway"
                elif echo "$r_line" | grep -q "^127\."; then ROUTE_TYPE="Loopback"
                elif echo "$r_line" | grep -E -q "^(224|239)\."; then ROUTE_TYPE="Multicast"
                elif echo "$r_line" | grep -q "255\.255\.255\.255"; then ROUTE_TYPE="Broadcast"
                else ROUTE_TYPE="Local Subnet"
                fi
                
                # Extract ALL columns using bash array reading
                # Sequence matches: Destination Gateway Subnet_Mask Flag Metric IfName
                read -r DEST_IP GATEWAY SUBNET_MASK FLAGS METRIC IFACE <<< "$r_line"
                
                echo "    {"
                echo "      \"destination\": \"$DEST_IP\","
                echo "      \"gateway\": \"$GATEWAY\","
                echo "      \"subnet_mask\": \"$SUBNET_MASK\","
                echo "      \"flags\": \"$FLAGS\","
                echo "      \"metric\": \"$METRIC\","
                echo "      \"interface\": \"$IFACE\","
                echo "      \"type\": \"$ROUTE_TYPE\""
                echo -n "    }"
            done <<< "$ROUTE_LIST"
        fi
        echo "" # Newline after the last route
        echo "  ],"

        echo "  \"arp_table\": ["
        FIRST_ARP=1
        if [[ -n "$ARP_LIST" ]]; then
            while read -r a_line; do
                [[ -z "$a_line" ]] && continue
                if [[ $FIRST_ARP -eq 1 ]]; then FIRST_ARP=0; else echo ","; fi
                
                # Re-extract values specifically for JSON
                IP_ADDR=$(echo "$a_line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)
                MAC_ADDR=$(echo "$a_line" | grep -iE -o '([0-9a-f]{2}[:-]){5}[0-9a-f]{2}')
                IFACE=$(echo "$a_line" | awk '{print $NF}')
                
                echo "    {"
                echo "      \"ip\": \"$IP_ADDR\","
                echo "      \"mac\": \"$MAC_ADDR\","
                echo "      \"interface\": \"$IFACE\""
                echo -n "    }"
            done <<< "$ARP_LIST"
        fi
        echo "" # Newline after the last ARP object
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    if [[ "$MINIMAL_MODE" -eq 0 ]]; then
        echo -e "${GREEN}[✔] Results successfully exported to JSON: ${BOLD}$OUTPUT_FILE${NC}\n"
    else
        echo "Results exported to JSON: $OUTPUT_FILE"
    fi
fi