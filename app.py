from flask import Flask, render_template, request

from crawler import crawl
from sqlScanner import scan_sql_injection
from xssScanner import scan_xss
from headerScanner import scan_headers

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    discovered_urls = []

    if request.method == "POST":
        target_url = request.form.get("url")

        # Run crawler
        discovered_urls = crawl(target_url)

        # Run scanners
        sqli = scan_sql_injection(discovered_urls)
        xss = scan_xss(discovered_urls)
        headers = scan_headers(target_url)

        results = {
            "sqli": sqli,
            "xss": xss,
            "headers": headers
        }

    return render_template("index.html", results=results, urls=discovered_urls)

if __name__ == "__main__":
    app.run(debug=True, port=5000)