import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

MAX_URLS = 10  # demo limit

def crawl(start_url):
    found_links = []

    print("\n[+] Starting crawl on:", start_url)
    print(f"[+] Crawl limit set to {MAX_URLS} URLs (demo mode)")

    try:
        response = requests.get(start_url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        base_domain = urlparse(start_url).netloc

        for tag in soup.find_all("a"):
            if len(found_links) >= MAX_URLS:
                #print("[+] Reached crawl limit. Stopping discovery.")
                break

            href = tag.get("href")
            if not href:
                continue

            # Skip non-web links
            if href.startswith(("mailto:", "javascript:", "#")):
                continue

            full_url = urljoin(start_url, href)
            parsed = urlparse(full_url)

            # Only allow http/https
            if parsed.scheme not in ["http", "https"]:
                continue

            # Stay within same domain
            if parsed.netloc != base_domain:
                continue

            if full_url not in found_links:
                found_links.append(full_url)
                print("[+] Found URL:", full_url)

    except Exception as e:
        print("[-] Crawling error:", e)

    print(f"[+] Total URLs collected: {len(found_links)}\n")
    return found_links