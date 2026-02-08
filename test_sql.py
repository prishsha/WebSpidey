from crawler import crawl
from sqlScanner import scan_sql_injection

target_url = "http://testphp.vulnweb.com"

print("[+] Crawling...")
urls = crawl(target_url)

print("[+] Testing SQL Injection...")
results = scan_sql_injection(urls)

print("\nVulnerable URLs:")
if results:
    for r in results:
        print(" -", r)
else:
    print("No SQL Injection detected")
