# Automated Incident Response with Splunk

A follow-up SOC project: closing the loop from detection to automated action. Earlier projects ([SSH detection](../README.md), [DVWA web attacks](../project5-dvwa/README.md)) stopped at "alert fires." This one wires a real response script to an existing alert, so a detected SSH brute-force attack results in an automatic firewall block — with a safelist to guarantee the automation can never lock out legitimate or internal traffic.

## Objective

Take the existing **SSH Brute Force - Burst Detection** alert and add a "Run a script" trigger action that:
1. Reads the offending source IP directly out of Splunk's own alert results.
2. Checks it against a safelist (loopback, internal subnets, Docker bridge range).
3. Blocks it with `iptables` if it's not safelisted — or logs that it was skipped if it is.

## Design decision: the safelist is mandatory, not optional

Every attack generated in this lab so far has come from an address that looks like an "attacker" in the logs but is actually the lab machine itself — `127.0.0.1` for the SSH tests, `172.17.0.1` (Docker's bridge gateway) for the DVWA tests. An automated response that blocks on IP alone, with no exceptions, would have blocked the lab's own SSH access or broken the DVWA container's networking the first time it ran. The safelist is what makes "automatically block on detection" safe to turn on at all.

```
127.0.0.1
10.0.2.0/24
10.0.3.0/24
172.17.0.0/16
```

## 1. The response script

`/opt/splunk/bin/scripts/block_ip.sh` — invoked by Splunk's "Run a script" alert action, which passes the triggered search's results as a gzipped CSV file (the 8th positional argument), not as plain arguments. The script:

- Reads the results file and extracts every `src_ip` value.
- For each IP, checks it against `/opt/soc-response/safelist.txt` (supports exact IPs and CIDR ranges).
- Safelisted → logs `SKIPPED: <ip> is safelisted` and does nothing further.
- Not safelisted → adds an `iptables -I INPUT -s <ip> -j DROP` rule (skipping if already present) and logs `BLOCKED: <ip>`.
- All actions are logged to `/opt/soc-response/response.log` with UTC timestamps.

```bash
#!/bin/bash
RESULTS_FILE="$8"
SAFELIST="/opt/soc-response/safelist.txt"
LOG="/opt/soc-response/response.log"

if [ -z "$RESULTS_FILE" ] || [ ! -f "$RESULTS_FILE" ]; then
    echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') ERROR: results file not found: $RESULTS_FILE" >> "$LOG"
    exit 1
fi

IPS=$(zcat "$RESULTS_FILE" | python3 -c "
import csv, sys
reader = csv.DictReader(sys.stdin)
for row in reader:
    ip = row.get('src_ip', '').strip()
    if ip:
        print(ip)
")

for IP in $IPS; do
    SAFE=0
    while IFS= read -r entry; do
        [ -z "$entry" ] && continue
        if [[ "$entry" == *"/"* ]]; then
            python3 -c "
import ipaddress, sys
sys.exit(0 if ipaddress.ip_address('$IP') in ipaddress.ip_network('$entry') else 1)
" && { SAFE=1; break; }
        elif [ "$IP" == "$entry" ]; then
            SAFE=1; break
        fi
    done < "$SAFELIST"

    if [ "$SAFE" -eq 1 ]; then
        echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') SKIPPED: $IP is safelisted" >> "$LOG"
        continue
    fi

    if sudo /usr/sbin/iptables -C INPUT -s "$IP" -j DROP 2>/dev/null; then
        echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') ALREADY BLOCKED: $IP" >> "$LOG"
    else
        sudo /usr/sbin/iptables -I INPUT -s "$IP" -j DROP
        echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') BLOCKED: $IP" >> "$LOG"
    fi
done
```

## 2. Permissions setup

Two separate privilege issues had to be solved, since the script runs as the `splunk` OS user, not as a human with a login shell:

**Passwordless sudo for the exact iptables commands, nothing broader:**
```
# /etc/sudoers.d/splunk-iptables
splunk ALL=(root) NOPASSWD: /usr/sbin/iptables -C INPUT -s * -j DROP
splunk ALL=(root) NOPASSWD: /usr/sbin/iptables -I INPUT -s * -j DROP
```

**Write access to the log file for the `splunk` user:**
```bash
sudo chown splunk:splunk /opt/soc-response/response.log
```
(The script, the safelist, and the containing directory remain root-owned — only the log file itself needed to be writable by `splunk`.)

## 3. Wiring the alert

On the existing **SSH Brute Force - Burst Detection** alert: **Edit → Trigger Actions → Add Actions → Run a script**, filename `block_ip.sh` (Splunk resolves this automatically from `$SPLUNK_HOME/bin/scripts/`).

![Alert trigger action configuration](screenshots/01-alert-trigger-action-config.png)

## 4. Testing

### Isolated script test (safelist + blocking logic, before wiring to Splunk)

```bash
sudo /opt/soc-response/block_ip.sh 127.0.0.1      # → SKIPPED (safelisted)
sudo /opt/soc-response/block_ip.sh 203.0.113.5    # → BLOCKED (reserved documentation address, never a real host)
```
Confirmed both the safelist check and the actual `iptables` rule addition worked correctly before touching Splunk at all.

### Simulated Splunk invocation (correct results-file argument passing)

```bash
printf "_time,src_ip,failed_attempts\n2026-11-06T10:00:00,203.0.113.5,10\n" > /tmp/test_results/results.csv
gzip /tmp/test_results/results.csv
sudo -u splunk /opt/splunk/bin/scripts/block_ip.sh a b c d e f g /tmp/test_results/results.csv.gz
```
Confirmed the script correctly reads `src_ip` out of a gzipped CSV passed as the 8th argument — the actual format Splunk's "Run a script" action uses, not a plain IP string.

### Live end-to-end test (real attack, real alert, real script, zero manual steps)

```bash
hydra -l attacker -P ~/wordlist.txt ssh://localhost
```
10 failed SSH logins in under a second. Confirmed caught by the detection search (`failed_attempts=9` from `127.0.0.1` in one 10-second window), which triggered the alert automatically on its next scheduled run:

![Alert triggered automatically](screenshots/02-alert-triggered.png)

The response log shows the result:
```
2026-11-06 10:30:01 UTC SKIPPED: 127.0.0.1 is safelisted
```
One second after the alert fired at 10:30:00 — with no manual script invocation anywhere in this run. `iptables -L INPUT -n` confirmed no block was applied; the lab's own SSH access was never at risk.

## Full evidence trail

```
response.log:
2026-11-06 10:10:57 UTC SKIPPED: 127.0.0.1 is explicitly safelisted   (isolated test)
2026-11-06 10:11:08 UTC BLOCKED: 203.0.113.5                          (isolated test)
2026-11-06 10:19:12 UTC ALREADY BLOCKED: 203.0.113.5                  (idempotency check)
2026-11-06 10:22:42 UTC BLOCKED: 203.0.113.5                          (simulated-invocation test)
2026-11-06 10:30:01 UTC SKIPPED: 127.0.0.1 is safelisted              (live, fully automated run)
```

## Lessons Learned

- Splunk's "Run a script" alert action does not pass field values as plain command-line arguments. It passes several positional arguments to the script, one of which (the 8th) is the path to a gzipped CSV of the search results. A script written to expect `$1` as a raw IP will not work when actually invoked by Splunk — it must parse the results file.
- A script invoked by an alert action runs as the Splunk service account directly; it does not inherit any `sudo` session a human operator might have. Privileged actions inside the script need their own narrowly-scoped `sudoers` entries.
- Scope `sudoers` NOPASSWD rules to the exact command and arguments needed (`iptables -I INPUT -s * -j DROP`), not to running an entire script as root — the script itself still runs as the unprivileged service account; only the specific privileged commands it calls are elevated.
- File ownership matters independently at every layer a script touches — the script file, the directory it lives in, and any file it writes to can each have different required owners, and a working manual test as one user doesn't guarantee it works when invoked as another.
- A safelist is not a "nice to have" for this kind of automation — it is the control that makes it safe to enable at all, since lab (and real) attack traffic can easily originate from addresses that are actually part of your own infrastructure (loopback, container bridges, internal subnets).
- Editing an existing scheduled alert in this Splunk version can silently reset its Time Range back to an invalid "Custom time" value — this bug recurred on three separate alerts across this project and the previous one, and is worth checking first whenever a scheduled alert unexpectedly shows "no fired events."

## Tools

Splunk Enterprise (Run a script alert action), Bash, Python 3 (`ipaddress`, `csv` modules), iptables, THC-Hydra
