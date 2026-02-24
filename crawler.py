import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def crawl(start_url):
    found_links = []

    print("\n[+] Starting crawl on:", start_url)

    try:
        response = requests.get(start_url)
        soup = BeautifulSoup(response.text, "html.parser")

        tags = soup.find_all("a")

        for tag in tags:
            href = tag.get("href")

            if href:
                full_url = urljoin(start_url, href)

                if full_url not in found_links:
                    found_links.append(full_url)
                    print("[+] Found URL:", full_url)

    except Exception as e:
        print("[-] Crawling error:", e)

    if not found_links:
        print("[-] No links found on page.")

    return found_links