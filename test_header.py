from headerScanner import scan_headers

target_url = "http://testphp.vulnweb.com"

print("[+] Checking security headers...")
missing = scan_headers(target_url)

if missing:
    print("\nMissing Security Headers:")
    for h in missing:
        print(" -", h)
else:
    print("All required security headers are present")
