from crawler import crawl
from sqlScanner import scan_sql_injection

def main():
    print("=== WebSpidey Vulnerability Scanner ===\n")

    target_url = input("Enter target URL: ")

    print("\n[1] Crawling the website...")
    urls = crawl(target_url)

    print(f"Found {len(urls)} URLs\n")

    print("[2] Scanning for SQL Injection vulnerabilities...")
    sqli_results = scan_sql_injection(urls)

    print("\n=== Scan Report ===")

    if sqli_results:
        print("\n[SQL Injection]")
        print("Status: VULNERABLE ")
        for url in sqli_results:
            print(" -", url)
    else:
        print("\n[SQL Injection]")
        print("Status: NOT DETECTED ")

if __name__ == "__main__":
    main()
