from crawler import crawl
from sqlScanner import scan_sql_injection
from xssScanner import scan_xss

def main():
    print("\n")
    print("   WebSpidey Vulnerability Scanner  ")
    print("\n")

    target_url = input("Enter target URL: ").strip()

    print("\n[+] Crawling target website...")
    urls = crawl(target_url)

    print(f"[+] Total URLs discovered: {len(urls)}\n")

    # SQL Injection 
    print("[+] Running SQL Injection scan...")
    sqli_results = scan_sql_injection(urls)

    # XSS 
    print("[+] Running XSS scan...")
    xss_results = scan_xss(urls)

    # REPORT 
    print("\nSCAN REPORT\n")

    # SQL Injection Report
    print("[SQL Injection]")
    if sqli_results:
        print("Status: VULNERABLE ❌")
        for url in sqli_results:
            print(" -", url)
    else:
        print("Status: NOT DETECTED ✅")

    print("\n\n")

    # XSS Report
    print("[Cross-Site Scripting (XSS)]")
    if xss_results:
        print("Status: VULNERABLE ❌")
        for url in xss_results:
            print(" -", url)
    else:
        print("Status: NOT DETECTED ✅")

    print("\n")

if __name__ == "__main__":
    main()
