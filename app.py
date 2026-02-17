from crawler import crawl
from sqlScanner import scan_sql_injection
from xssScanner import scan_xss
from headerScanner import scan_headers

def main():
    print("   WebSpidey Vulnerability Scanner  ")
    print("\n")

    target_url = input("Enter target URL: ").strip()

    # crawling
    print("\n[+] Crawling target website...")
    urls = crawl(target_url)
    print(f"[+] Total URLs discovered: {len(urls)}\n")

    # sql injection
    print("[+] Running SQL Injection scan...")
    sqli_results = scan_sql_injection(urls)

    # xss
    print("[+] Running XSS scan...")
    xss_results = scan_xss(urls)

    # headers
    print("[+] Checking Security Headers...")
    header_results = scan_headers(target_url)

    # report
    print("\nFINAL SCAN REPORT\n")

    # SQL Injection
    print("[SQL Injection]")
    if sqli_results:
        print("Status: VULNERABLE")
        for url in sqli_results:
            print(" -", url)
    else:
        print("Status: NOT DETECTED")

    print("\n")

    # XSS
    print("[Cross-Site Scripting (XSS)]")
    if xss_results:
        print("Status: VULNERABLE")
        for url in xss_results:
            print(" -", url)
    else:
        print("Status: NOT DETECTED")

    print("\n")

    # Headers
    print("[Security Headers]")
    if header_results:
        print("Missing Headers")
        for header in header_results:
            print(" -", header)
    else:
        print("All Required Headers Present")

    print("\n")

if __name__ == "__main__":
    main()
