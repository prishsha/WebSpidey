from crawler import crawl
from xssScanner import scan_xss

target_url = "http://testphp.vulnweb.com"

print("[+] Crawling...")
urls = crawl(target_url)

print("[+] Testing XSS...")
results = scan_xss(urls)

print("\nVulnerable URLs:")
if results:
    for r in results:
        print(" -", r)
else:
    print("No XSS detected")
