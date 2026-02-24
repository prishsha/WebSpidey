import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def crawl(start_url):
    found_links = []

    try:
        r = requests.get(start_url)
        soup = BeautifulSoup(r.text, "html.parser")

        tags = soup.find_all("a")

        for t in tags:
            href = t.get("href")

            if href:
                # convert relative → absolute URL
                full_url = urljoin(start_url, href)

                if full_url not in found_links:
                    found_links.append(full_url)

    except Exception as e:
        print("Error while crawling:", e)

    return found_links