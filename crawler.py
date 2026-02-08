import requests
from bs4 import BeautifulSoup

def crawl(url):
    links = []

    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        for a in soup.find_all("a"):
            href = a.get("href")
            if href and href.startswith("http"):
                links.append(href)

    except Exception as e:
        print("Crawler error:", e)

    return links
