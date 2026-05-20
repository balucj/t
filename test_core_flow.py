import os
import json
from dotenv import load_dotenv
from mcp_sentinel_server import read_vulnerability_csv, detect_os, run_vulnerability_scan

load_dotenv(override=True)

TARGET_HOST = os.getenv("TARGET_HOST")
TARGET_USER = os.getenv("TARGET_USER")
TARGET_PASSWORD = os.getenv("TARGET_PASSWORD")
TARGET_PORT = int(os.getenv("TARGET_PORT", 22))
TARGET_KEY_PATH = os.getenv("TARGET_KEY_PATH")

def test_flow():
    print(f"--- Testing CSV Reading ---")
    csv_res = read_vulnerability_csv("vul_csv/sec-1123.csv")
    csv_data = json.loads(csv_res)
    if "error" in csv_data:
        print(f"Error reading CSV: {csv_data['error']}")
        return
    vulns = csv_data.get("vulnerabilities", [])
    print(f"Found {len(vulns)} vulnerabilities.")

    print(f"--- Testing OS Detection on {TARGET_HOST} ---")
    os_res = detect_os(
        host=TARGET_HOST,
        user=TARGET_USER,
        password=TARGET_PASSWORD,
        port=TARGET_PORT,
        key_path=TARGET_KEY_PATH
    )
    os_data = json.loads(os_res)
    if "error" in os_data:
        print(f"Error detecting OS: {os_data['error']}")
        return
    print(f"OS Family: {os_data.get('os_family')}, Pkg Manager: {os_data.get('pkg_manager')}")

    if vulns:
        pkg = vulns[0].get("package")
        print(f"--- Testing Scan for Package: {pkg} ---")
        scan_res = run_vulnerability_scan(
            host=TARGET_HOST,
            user=TARGET_USER,
            password=TARGET_PASSWORD,
            port=TARGET_PORT,
            key_path=TARGET_KEY_PATH,
            package=pkg,
            pkg_manager=os_data.get('pkg_manager')
        )
        scan_data = json.loads(scan_res)
        if "error" in scan_data:
            print(f"Error scanning package: {scan_data['error']}")
            return
        print(f"Scan Status: {scan_data.get('status')}, Is Installed: {scan_data.get('is_installed')}")

if __name__ == "__main__":
    test_flow()
