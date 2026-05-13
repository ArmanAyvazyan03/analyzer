#!/bin/bash

LOG_FILE=$1
FILTER_TYPE=$2
FILTER_VALUE=$3

REQUEST_THRESHOLD=10
FAILED_THRESHOLD=3

if [ -z "$LOG_FILE" ]; then
    echo "Usage:"
    echo "./analyzer.sh access.log"
    echo "./analyzer.sh access.log ip 192.168.1.10"
    echo "./analyzer.sh access.log path admin"
    echo "./analyzer.sh access.log status 404"
    exit 1
fi

if [ ! -f "$LOG_FILE" ]; then
    echo "Error: Log file not found!"
    exit 1
fi

echo
echo "WEB LOG THREAT ANALYZER"
echo

if [ "$FILTER_TYPE" == "ip" ]; then
    echo "[FILTER MODE - IP]"
    echo

    grep "$FILTER_VALUE" "$LOG_FILE"

    echo
    echo "FILTER COMPLETE"
    exit 0
fi

if [ "$FILTER_TYPE" == "path" ]; then
    echo "[FILTER MODE - PATH]"
    echo

    grep "$FILTER_VALUE" "$LOG_FILE"

    echo
    echo "FILTER COMPLETE"
    exit 0
fi

if [ "$FILTER_TYPE" == "status" ]; then
    echo "[FILTER MODE - STATUS]"
    echo

    awk -v code="$FILTER_VALUE" '$9 == code' "$LOG_FILE"

    echo
    echo "FILTER COMPLETE"
    exit 0
fi

echo "[1] Parsed Log Fields"
echo

awk '{
    print "IP:", $1,
    "| Timestamp:", $4,
    "| Method:", $6,
    "| Path:", $7,
    "| Status:", $9,
    "| Size:", $10
}' "$LOG_FILE"

echo
echo "[2] Suspicious Paths"
echo

grep -E '(/admin|/wp-admin|/\.env|backup|/login|/phpmyadmin|/\.git|config|passwd)' "$LOG_FILE"

echo
echo "[3] Failed Requests (401,403,404)"
echo

awk '$9 ~ /401|403|404/' "$LOG_FILE"

echo
echo "[4] Top IP Addresses"
echo

awk '{print $1}' "$LOG_FILE" | \
sort | uniq -c | sort -nr

echo
echo "[5] Possible Brute Force Attempts"
echo

awk '$9 == 401 {print $1}' "$LOG_FILE" | \
sort | uniq -c | \
awk -v limit="$FAILED_THRESHOLD" '$1 >= limit'

echo
echo "[6] Possible Scanning Activity (404 Flood)"
echo

awk '$9 == 404 {print $1}' "$LOG_FILE" | \
sort | uniq -c | \
awk -v limit="$FAILED_THRESHOLD" '$1 >= limit'

echo
echo "[7] High Request Rate Detection"
echo

awk '{print $1}' "$LOG_FILE" | \
sort | uniq -c | \
awk -v limit="$REQUEST_THRESHOLD" '$1 >= limit'

echo
echo "[8] Malformed Log Lines"
echo

grep -vE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$LOG_FILE"

echo
echo "[9] Suspicious IP Summary"
echo

for ip in $(awk '{print $1}' "$LOG_FILE" | grep -E '^[0-9]+\.' | sort | uniq)
do
    FAILS=$(awk -v ip="$ip" '$1 == ip && $9 ~ /401|403|404/' "$LOG_FILE" | wc -l)

    SUSPICIOUS=$(grep "$ip" "$LOG_FILE" | \
    grep -E '(/admin|/wp-admin|/\.env|backup|/login|/phpmyadmin|/\.git|config|passwd)' | wc -l)

    REQUESTS=$(grep "$ip" "$LOG_FILE" | wc -l)

    if [ "$FAILS" -ge 2 ] || [ "$SUSPICIOUS" -ge 1 ] || [ "$REQUESTS" -ge "$REQUEST_THRESHOLD" ]; then

        START_TIME=$(grep "$ip" "$LOG_FILE" | head -1 | awk '{print $4}')
        END_TIME=$(grep "$ip" "$LOG_FILE" | tail -1 | awk '{print $4}')

        echo
        echo "ALERT: Suspicious IP Detected"
        echo "IP Address: $ip"
        echo "Time Range: $START_TIME -> $END_TIME"
        echo "Total Requests: $REQUESTS"
        echo "Failed Requests: $FAILS"
        echo "Sensitive Path Requests: $SUSPICIOUS"

        echo
        echo "Reasons Flagged:"

        if [ "$FAILS" -ge 2 ]; then
            echo "- Multiple failed requests"
        fi

        if [ "$SUSPICIOUS" -ge 1 ]; then
            echo "- Access to sensitive paths"
        fi

        if [ "$REQUESTS" -ge "$REQUEST_THRESHOLD" ]; then
            echo "- High request volume"
        fi

        echo
        echo "Related Requests:"
        grep "$ip" "$LOG_FILE"

        echo
    fi
done

echo "ANALYSIS COMPLETE"
