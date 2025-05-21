#!/usr/bin/env python3

"""
A FortiGate configuration audit script.
It reads a FortiGate configuration file and checks for compliance
with many recommended settings derived from the CIS FortiGate Benchmark.

Output:
  - Terminal progress and coloured PASS/FAIL messages.
  - An HTML report with a summary, a Passed Checks section, detailed failed checks
    separated into “Missing Recommended Settings” and “Insecure Settings Found” sections and
    an explanation for findings that display "None".

Author: Alfie
Website: www.the-infosec.com
GitHub: https://github.com/Xalfie
Tool Link: https://the-infosec.com/2025/03/14/fortigate-configuration-files-audit-tool-fcfat-enhancing-firewall-security-with-automated-analysis/
"""
import subprocess
import sys
import ctypes
import os
import re
import time
from colorama import init, Fore, Style
from tqdm import tqdm

print("check for updates and new features at https://github.com/XalfiE/Fortigate-Configuration-Files-Audit-Tool")

# Detect if running inside a Virtual Machine
def detect_virtual_machine():
    try:
        output = subprocess.check_output("wmic bios get serialnumber", shell=True).decode()
        if any(vm in output for vm in VM_SIGNATURES):
            print("❌ Virtual Machine detected! Exiting...")
            sys.exit()
    except:
        pass  # Ignore errors in case the system does not support WMIC

# Detect Debuggers (x64dbg, IDA Pro, etc.)
def detect_debugger():
    is_debugger_present = ctypes.windll.kernel32.IsDebuggerPresent()
    if is_debugger_present:
        print("⚠ Debugger detected! Exiting...")
        sys.exit()

# Run security checks at startup
detect_virtual_machine()  # Anti-VM Check
detect_debugger()  # Anti-Debugging Check

VM_SIGNATURES = ["VMware", "VirtualBox", "QEMU", "Xen", "Parallels", "Hyper-V"]

def detect_virtual_machine():
    """Detect if running inside a virtual machine and self-destruct if detected."""
    try:
        output = subprocess.check_output("wmic bios get serialnumber", shell=True).decode()
        if any(vm in output for vm in VM_SIGNATURES):
            print("❌ Virtual Machine detected! Exiting...")
            os.remove(sys.argv[0])  # Self-destruct
            sys.exit()
    except:
        print("⚠ Unable to check for VM. Assuming safe environment.")

# Run check at startup
detect_virtual_machine()

# Initialize colorama for terminal colouring.
init(autoreset=True)

# Define our expected variables (these mirror the variables in the audit file)
variables = {
    'TIMEZONE': '12',
    'MIN_LENGTH': '12',  # Changed to 12 (Refer to company Policy)
    'MAX_AGE': '90',     # 90 days (Refer to company Policy)
    'MIN_LOWERCASE': '1',
    'MIN_UPPERCASE': '1',
    'MIN_NON_ALPHANUM': '1',
    'MIN_NUMBER': '1',
    'EXPIRE_PASSWORDS': 'enable',
    'ADMIN_LOCKOUT_DURATION': '900',
    'ADMIN_LOCKOUT_THRESHOLD': '3',
    'ADMIN_TIMEOUT': '5',
    'HA_GATEWAY': '192.168.0.1',
    'HA_INTERFACE': 'port6',
    'HA_MONITOR_PORT_1': 'port8',
    'HA_MONITOR_PORT_2': 'port9',
    'WAN_PORT': 'port1',
    'APPLIES_TO': 'admin-password ipsec-preshared-key'
}

##############################
# Custom check functions
##############################

def check_wan_mgmt(config_text):
    """
    Look for the configuration block for the WAN interface (using variables['WAN_PORT'])
    and ensure that the “allowaccess” setting does not include insecure protocols (http or telnet).
    Returns (passed, findings).
    """
    pattern = (r'config\s+system\s+interface.*?edit\s+"?' +
               re.escape(variables['WAN_PORT']) +
               r'"?.*?set\s+allowaccess\s+(.+?)(?=\n)')
    matches = re.findall(pattern, config_text, re.MULTILINE | re.DOTALL)
    passed = True
    findings = []
    if matches:
        for allowaccess in matches:
            if re.search(r'\b(http|telnet)\b', allowaccess, re.IGNORECASE):
                passed = False
                findings.append("Insecure allowaccess found: set allowaccess " + allowaccess.strip())
    else:
        passed = False
        findings.append("No WAN interface configuration found for " + variables['WAN_PORT'])
    return passed, findings

def check_password_policy(config_text):
    """
    Extract the password policy block and check for the expected settings.
    Note: For "minimum-length" and "expire-day" the description has been appended
    with "(Refer to company Policy)".
    """
    pattern = r'config\s+system\s+password-policy(.*?)end'
    block_match = re.search(pattern, config_text, re.DOTALL | re.IGNORECASE)
    findings = []
    passed = True
    if block_match:
        block = block_match.group(1)
        expected_settings = {
            'minimum-length': variables['MIN_LENGTH'],
            'min-lower-case-letter': variables['MIN_LOWERCASE'],
            'min-upper-case-letter': variables['MIN_UPPERCASE'],
            'min-non-alphanumeric': variables['MIN_NON_ALPHANUM'],
            'min-number': variables['MIN_NUMBER'],
            'expire-status': variables['EXPIRE_PASSWORDS'],
            'expire-day': variables['MAX_AGE'],
            'reuse-password': 'disable',
            'status': 'enable',
            'apply-to': variables['APPLIES_TO']
        }
        for setting, exp_value in expected_settings.items():
            regex = r'set\s+' + re.escape(setting) + r'\s+(\S+)'
            match = re.search(regex, block, re.IGNORECASE)
            if match:
                actual = match.group(1).strip()
                if actual.lower() != exp_value.lower():
                    passed = False
                    findings.append(f"{setting}: expected '{exp_value}' but found '{actual}'")
            else:
                passed = False
                findings.append(f"{setting} not found in password-policy")
    else:
        passed = False
        findings.append("Password policy block not found")
    return passed, findings

def check_admin_lockout(config_text):
    """
    Check that the admin lockout threshold and duration are correctly set.
    """
    findings = []
    passed = True
    threshold_match = re.search(r'set\s+admin-lockout-threshold\s+(\d+)', config_text, re.IGNORECASE)
    if threshold_match:
        if threshold_match.group(1) != variables['ADMIN_LOCKOUT_THRESHOLD']:
            passed = False
            findings.append(f"admin-lockout-threshold expected '{variables['ADMIN_LOCKOUT_THRESHOLD']}' but found '{threshold_match.group(1)}'")
    else:
        passed = False
        findings.append("admin-lockout-threshold not found")
    duration_match = re.search(r'set\s+admin-lockout-duration\s+(\d+)', config_text, re.IGNORECASE)
    if duration_match:
        if duration_match.group(1) != variables['ADMIN_LOCKOUT_DURATION']:
            passed = False
            findings.append(f"admin-lockout-duration expected '{variables['ADMIN_LOCKOUT_DURATION']}' but found '{duration_match.group(1)}'")
    else:
        passed = False
        findings.append("admin-lockout-duration not found")
    return passed, findings

def check_ha_mgmt(config_text):
    """
    Check that the HA management block (ha-mgmt-interfaces) contains the expected interface and gateway.
    """
    pattern = r'config\s+ha-mgmt-interfaces(.*?)end'
    match = re.search(pattern, config_text, re.DOTALL | re.IGNORECASE)
    findings = []
    passed = True
    if match:
        block = match.group(1)
        int_match = re.search(r'set\s+interface\s+"?' + re.escape(variables['HA_INTERFACE']) + r'"?', block, re.IGNORECASE)
        gw_match = re.search(r'set\s+gateway\s+(\S+)', block, re.IGNORECASE)
        if not int_match:
            passed = False
            findings.append(f"HA management interface '{variables['HA_INTERFACE']}' not found")
        if not gw_match or gw_match.group(1) != variables['HA_GATEWAY']:
            passed = False
            found_gw = gw_match.group(1) if gw_match else "None"
            findings.append(f"HA gateway expected '{variables['HA_GATEWAY']}' but found '{found_gw}'")
    else:
        passed = False
        findings.append("HA management interfaces block not found")
    return passed, findings

def check_log_encrypt(config_text):
    """
    Check that log transmission to FortiAnalyzer is encrypted:
      - set reliable enable
      - set enc-algorithm high
    """
    findings = []
    passed = True
    if not re.search(r'set\s+reliable\s+enable', config_text, re.IGNORECASE):
        passed = False
        findings.append("Log transmission not set to reliable enable")
    if not re.search(r'set\s+enc-algorithm\s+high', config_text, re.IGNORECASE):
        passed = False
        findings.append("Encryption algorithm not set to high")
    return passed, findings

def check_default_accounts(config_text):
    """
    Check for default or generic administrative accounts.
    
    This function scans the FortiGate configuration for the "config system admin" block
    and looks for any account names that contain common generic keywords such as:
      - "admin"
      - "test"
      - "demo"
      - "guest"
      - "default"
      - "administrator"
      
    These accounts are widely known and are common targets for attackers.
    It is recommended that generic accounts be removed or renamed.
    
    Returns (passed, findings) where findings lists any flagged account names.
    """
    pattern = r'config\s+system\s+admin(.*?)end'
    findings = []
    passed = True
    match = re.search(pattern, config_text, re.DOTALL | re.IGNORECASE)
    # Define a list of generic keywords
    generic_keywords = ["admin", "test", "demo", "guest", "default", "administrator"]
    if match:
        block = match.group(1)
        accounts = re.findall(r'edit\s+"?(\S+)"?', block, re.IGNORECASE)
        flagged_accounts = []
        for account in accounts:
            # Check if the account name contains any generic keyword
            for keyword in generic_keywords:
                if keyword in account.lower():
                    flagged_accounts.append(account)
                    break  # No need to check further keywords for this account
        if flagged_accounts:
            passed = False
            findings.append("Default/generic admin accounts found: " + ", ".join(flagged_accounts))
    else:
        findings.append("No admin configuration block found.")
    return passed, findings

##############################
# Generic check runner
##############################

def run_check(check, config_text):
    """
    For a check dictionary that has a 'regex' (or a list of them) and an optional 'expected' value,
    run the search and return (passed, list_of_matches).
    """
    if isinstance(check['regex'], list):
        results = []
        for rx in check['regex']:
            matches = re.findall(rx, config_text, re.MULTILINE | re.DOTALL)
            results.append(matches)
        passed = all(len(r) > 0 for r in results)
        found = []
        for r in results:
            found.extend(r)
        if check.get('expected'):
            # if expected is ">=2", check number of matches
            if check['expected'] == ">=2":
                passed = (sum(len(r) for r in results) >= 2)
        return passed, found
    else:
        matches = re.findall(check['regex'], config_text, re.MULTILINE)
        if check.get('expected'):
            if check['expected'] == ">=2":
                passed = (len(matches) >= 2)
            else:
                passed = any(check['expected'] in m for m in matches)
        else:
            passed = bool(matches)
        return passed, matches

##############################
# Define check list (each is a dict)
##############################

checks = [
    {
        "id": "CHK_INTRAZONE",
        "section": "Missing recommended setting",
        "description": "Ensure intra-zone traffic is not always allowed",
        "rationale": "This setting prevents unauthorized traffic between networks in the same zone.",
        "regex": r'set\s+intrazone\s+deny',
        "expected": None
    },
    {
        "id": "CHK_WAN_MGMT",
        "section": "Insecure setting found",
        "description": "Disable management related services on WAN port",
        "rationale": "Enabling management services on the WAN exposes the device to risk.",
        "custom_check": check_wan_mgmt
    },
    {
        "id": "CHK_PRE_BANNER",
        "section": "Missing recommended setting",
        "description": "Ensure 'Pre-Login Banner' is set",
        "rationale": "A pre-login banner warns unauthorized users that activity is monitored.",
        "regex": r'set\s+pre-login-banner\s+enable',
        "expected": None
    },
    {
        "id": "CHK_POST_BANNER",
        "section": "Missing recommended setting",
        "description": "Ensure 'Post-Login Banner' is set",
        "rationale": "A post-login banner notifies users and can limit unauthorized use.",
        "regex": r'set\s+post-login-banner\s+enable',
        "expected": None
    },
    {
        "id": "CHK_TLS",
        "section": "Missing recommended setting",
        "description": "Ensure management GUI listens on secure TLS version",
        "rationale": "Using TLS 1.3 reduces man-in-the-middle attack risk.",
        "regex": r'set\s+admin-https-ssl-versions\s+tlsv1-3',
        "expected": None
    },
    {
        "id": "CHK_CPU_LOG",
        "section": "Missing recommended setting",
        "description": "Ensure single CPU core overloaded event is logged",
        "rationale": "This helps catch performance issues that might be missed by overall CPU usage metrics.",
        "regex": r'set\s+log-single-cpu-high\s+enable',
        "expected": None
    },
    {
        "id": "CHK_TIMEZONE",
        "section": "Missing recommended setting",
        "description": "Ensure timezone is properly configured",
        "rationale": "Accurate time is critical for logging, scheduling, and certificate validation.",
        "regex": r'set\s+timezone\s+(\d+)',
        "expected": variables['TIMEZONE']
    },
    {
        "id": "CHK_NTP",
        "section": "Missing recommended setting",
        "description": "Ensure correct system time is configured through NTP",
        "rationale": "NTP synchronization is essential for accurate timestamps in logs and certificates.",
        "regex": r'set\s+server\s+(?:\"?[0-9.]+\"?)',
        "expected": ">=2"
    },
    {
        "id": "CHK_HOSTNAME",
        "section": "Missing recommended setting",
        "description": "Ensure hostname is set",
        "rationale": "A unique hostname is important for device identification and asset management.",
        "regex": r'set\s+hostname\s+(.+)',
        "expected": None
    },
    {
        "id": "CHK_PWD_POLICY",
        "section": "Missing recommended setting",
        "description": "Ensure 'Password Policy' is enabled (Refer to company Policy) for minimum-length and expire-day",
        "rationale": "Strong password policies reduce the risk of unauthorized access.",
        "custom_check": check_password_policy
    },
    {
        "id": "CHK_ADMIN_LOCKOUT",
        "section": "Missing recommended setting",
        "description": "Ensure administrator password retries and lockout time are configured",
        "rationale": "This setting limits brute-force attack attempts.",
        "custom_check": check_admin_lockout
    },
    {
        "id": "CHK_DEFAULT_ACCOUNTS",
        "section": "Insecure setting found",
        "description": "Ensure that default or generic administrative accounts (e.g. admin, test, demo, guest, default, administrator) are not present",
        "rationale": "Generic accounts are widely known targets for attackers. Remove or rename these accounts to minimize risk.",
        "custom_check": check_default_accounts
    },
    {
        "id": "CHK_IDLE_TIMEOUT",
        "section": "Missing recommended setting",
        "description": "Ensure idle timeout time is configured",
        "rationale": "An idle timeout prevents unauthorized use of a logged-in session.",
        "regex": r'set\s+admintimeout\s+(\d+)',
        "expected": variables['ADMIN_TIMEOUT']
    },
    {
        "id": "CHK_HA_MONITOR",
        "section": "Missing recommended setting",
        "description": "Ensure 'Monitor Interfaces' for High Availability devices is enabled",
        "rationale": "Interface monitoring is required to trigger failover when a link fails.",
        "regex": r'set\s+monitor\s+"?' + re.escape(variables['HA_MONITOR_PORT_1']) +
                 r'"?\s+"?' + re.escape(variables['HA_MONITOR_PORT_2']) + r'"?',
        "expected": None
    },
    {
        "id": "CHK_HA_MGMT",
        "section": "Missing recommended setting",
        "description": "Ensure HA Reserved Management Interface is configured",
        "rationale": "A reserved management interface ensures you can access secondary devices in an HA cluster.",
        "custom_check": check_ha_mgmt
    },
    {
        "id": "CHK_SERVICE_ALL",
        "section": "Insecure setting found",
        "description": "Ensure that policies do not use 'ALL' as Service",
        "rationale": "Using 'ALL' may allow unauthorized protocols and increase risk.",
        "regex": r'set\s+service\s+.*ALL',
        "expected": None
    },
    {
        "id": "CHK_LOG_TRAFFIC",
        "section": "Missing recommended setting",
        "description": "Ensure logging is enabled on all firewall policies",
        "rationale": "Logging is essential for forensic analysis and incident response.",
        "regex": r'set\s+logtraffic\s+(\w+)',
        "expected": "all"
    },
    {
        "id": "CHK_IPS_SENSOR",
        "section": "Insecure setting found",
        "description": "Apply IPS Security Profile to Policies (Manual Review Required)",
        "rationale": "An IPS profile helps detect and block known threats.",
        "regex": r'set\s+ips-sensor',
        "expected": None
    },
    {
        "id": "CHK_SANDBOX",
        "section": "Missing recommended setting",
        "description": "Ensure inline scanning with FortiGuard AI-Based Sandbox Service is enabled",
        "rationale": "Inline scanning prevents malware from bypassing signature detection.",
        "regex": r'set\s+sandbox-inline-scan\s+enable',
        "expected": None
    },
    {
        "id": "CHK_DNS_FILTER_LOG",
        "section": "Missing recommended setting",
        "description": "Ensure DNS Filter logs all DNS queries and responses",
        "rationale": "Logging DNS queries aids in the detection of malicious activity.",
        "regex": r'set\s+log-all-domain\s+enable',
        "expected": None
    },
    {
        "id": "CHK_DNS_FILTER_PROFILE",
        "section": "Insecure setting found",
        "description": "Apply DNS Filter Security Profile to Policies (Manual Review Required)",
        "rationale": "A DNS filter profile helps block access to malicious domains.",
        "regex": r'set\s+dnsfilter-profile',
        "expected": None
    },
    {
        "id": "CHK_APPCTRL_HIGH_RISK",
        "section": "Insecure setting found",
        "description": "Block high risk categories on Application Control (Manual Review Required)",
        "rationale": "Blocking high risk applications (e.g. P2P, Proxy) reduces exposure to malware.",
        "regex": r'set\s+category\s+2\s+6',
        "expected": None
    },
    {
        "id": "CHK_APPCTRL_LOG",
        "section": "Missing recommended setting",
        "description": "Ensure all Application Control related traffic is logged",
        "rationale": "Logging application traffic is critical for incident detection.",
        "regex": r'set\s+unknown-application-log\s+enable',
        "expected": None
    },
    {
        "id": "CHK_APPCTRL_POLICY",
        "section": "Insecure setting found",
        "description": "Apply Application Control Security Profile to Policies (Manual Review Required)",
        "rationale": "Application control profiles should be applied to monitor and restrict application traffic.",
        "regex": r'set\s+application-list',
        "expected": None
    },
    {
        "id": "CHK_QUARANTINE",
        "section": "Missing recommended setting",
        "description": "Enable Compromised Host Quarantine",
        "rationale": "Quarantining compromised hosts helps limit lateral movement.",
        "regex": r'edit\s+"Compromised Host Quarantine".*set\s+status\s+enable',
        "expected": None
    },
    {
        "id": "CHK_LOG_ENCRYPT",
        "section": "Missing recommended setting",
        "description": "Encrypt Log Transmission to FortiAnalyzer / FortiManager",
        "rationale": "Encrypting logs prevents interception and tampering.",
        "custom_check": check_log_encrypt
    }
]

##############################
# Main processing
##############################

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(Fore.YELLOW + "Usage: fcfat.exe <config_file>")
        sys.exit(1)

    config_filename = sys.argv[1]
    if not os.path.isfile(config_filename):
        print(Fore.RED + f"Error: File '{config_filename}' not found.")
        sys.exit(1)

    with open(config_filename, "r") as f:
        config_text = f.read()

    total_checks = len(checks)
    passed_checks = 0
    failed_checks = 0
    results = []  # Each result is a dict with id, section, description, rationale, passed, findings

    print(Fore.CYAN + f"Starting audit on configuration file: {config_filename}\n")
    for check in tqdm(checks, desc="Auditing Checks", ncols=100):
        time.sleep(0.1)  # simulate work for progress display
        if "custom_check" in check:
            passed, findings = check["custom_check"](config_text)
        else:
            passed, findings = run_check(check, config_text)
        result = {
            "id": check["id"],
            "section": check["section"],
            "description": check["description"],
            "rationale": check["rationale"],
            "passed": passed,
            "findings": findings if findings else ["None"]
        }
        results.append(result)
        if passed:
            passed_checks += 1
            print(Fore.GREEN + f"[PASS] {check['id']}: {check['description']}")
        else:
            failed_checks += 1
            print(Fore.RED + f"[FAIL] {check['id']}: {check['description']}")
    percentage = (passed_checks / total_checks) * 100

    ##############################
    # Generate HTML report
    ##############################
    # Name the report file similar to the input file
    base_name = os.path.splitext(os.path.basename(config_filename))[0]
    report_filename = base_name + "_audit_report.html"

    html_report = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>FortiGate Audit Report - {config_filename}</title>
<style>
    body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f7f7f7; }}
    h1 {{ color: #2E8B57; }}
    h2 {{ color: #4682B4; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
    th, td {{ border: 1px solid #dddddd; text-align: left; padding: 8px; }}
    tr:nth-child(even) {{ background-color: #ffffff; }}
    .missing {{ background-color: #FFECB3; }} /* light orange for missing recommended settings */
    .insecure {{ background-color: #FFCDD2; }} /* light red for insecure settings found */
    .passed {{ background-color: #C8E6C9; }} /* light green for passed checks */
    .summary {{ background-color: #E0F7FA; padding: 10px; border: 1px solid #00838F; }}
    .footer {{ margin-top: 20px; font-size: 0.9em; text-align: center; }}
    .explanation {{ background-color: #F0F4C3; padding: 10px; border: 1px solid #9E9D24; margin-bottom: 20px; }}
</style>
</head>
<body>
<h1>FortiGate Audit Report</h1>
<h3>Configuration File: {config_filename}</h3>
<div class="summary">
    <h2>Summary</h2>
    <p>Total Checks Performed: {total_checks}<br>
       Checks Passed: {passed_checks}<br>
       Checks Failed: {failed_checks}<br>
       Percentage Pass: {percentage:.2f}%</p>
</div>
<hr>
<h2>Passed Checks</h2>
<table>
<tr><th>ID</th><th>Description</th><th>Rationale</th></tr>
"""
    # Add rows for passed checks
    for res in results:
        if res["passed"]:
            html_report += f"<tr class='passed'><td>{res['id']}</td><td>{res['description']}</td><td>{res['rationale']}</td></tr>\n"

    html_report += """
</table>
<h2>Missing Recommended Settings</h2>
<table>
<tr><th>ID</th><th>Description</th><th>Rationale</th><th>Findings</th></tr>
"""
    # Add rows for missing recommended settings that failed
    for res in results:
        if res["section"] == "Missing recommended setting" and not res["passed"]:
            findings_str = "<br>".join(res["findings"])
            html_report += f"<tr class='missing'><td>{res['id']}</td><td>{res['description']}</td><td>{res['rationale']}</td><td>{findings_str}</td></tr>\n"
    html_report += """
</table>
<h2>Insecure Settings Found</h2>
<table>
<tr><th>ID</th><th>Description</th><th>Rationale</th><th>Findings</th></tr>
"""
    # Add rows for insecure settings that failed
    for res in results:
        if res["section"] == "Insecure setting found" and not res["passed"]:
            findings_str = "<br>".join(res["findings"])
            html_report += f"<tr class='insecure'><td>{res['id']}</td><td>{res['description']}</td><td>{res['rationale']}</td><td>{findings_str}</td></tr>\n"
    html_report += """
</table>
<div class="explanation">
    <h2>Explanation</h2>
    <p>If a checks Findings column displays None, this means that the check failed but no additional configuration details were captured by the audit script. This might be because the check only verifies the presence or absence of a setting, without providing further details. In such cases, manual review of the configuration is recommended for more context.</p>
</div>
<hr>
<footer class="footer">
    <p>Alfie / <a href="http://www.the-infosec.com" target="_blank">www.the-infosec.com</a> / 
    <a href="https://github.com/Xalfie" target="_blank">https://github.com/Xalfie</a></p>
</footer>
</body>
</html>
"""
    with open(report_filename, "w") as f:
        f.write(html_report)

    print("\n" + Fore.CYAN + f"Audit complete. Report generated: {report_filename}")
    print(Fore.CYAN + f"Summary: {total_checks} checks performed, {passed_checks} passed, {failed_checks} failed, {percentage:.2f}% pass.\n")
