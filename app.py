from flask import Flask, render_template, request, session

from crawler import crawl
from scanners.sqlScanner import scan_sql_injection
from scanners.xssScanner import scan_xss
from scanners.headerScanner import scan_headers
from scanners.redirectScanner import scan_open_redirect
from scanners.directoryScanner import scan_directories
from scanners.exposureScanner import scan_sensitive_data

from services.risk import classify_owasp_risk, generate_security_suggestions
from services.pdf_generator import generate_pdf

app = Flask(__name__)
app.secret_key = 'webspidey_secret_key'


@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    discovered_urls = []

    if request.method == "POST":
        target_url = request.form.get("url")

        # 🔍 Crawl
        discovered_urls = crawl(target_url)

        # 🔍 Core scanners
        sqli = scan_sql_injection(discovered_urls)
        xss = scan_xss(discovered_urls)
        headers = scan_headers(target_url)

        # 🔥 New scanners
        open_redirect = scan_open_redirect(discovered_urls)
        directories = scan_directories(target_url)
        sensitive_data = scan_sensitive_data(discovered_urls)

        # 🧠 Risk score (update function to accept new params)
        owasp_risk = classify_owasp_risk(
            sqli,
            xss,
            headers,
            discovered_urls,
            open_redirect,
            directories,
            sensitive_data
        )

        # 📊 Results object
        results = {
            "sqli": sqli,
            "xss": xss,
            "headers": headers,
            "open_redirect": open_redirect,
            "directories": directories,
            "sensitive_data": sensitive_data,
            "owasp_risk": owasp_risk
        }

        # 💡 Suggestions
        results["suggestions"] = generate_security_suggestions(results, discovered_urls)

        # 💾 Store in session
        session['results'] = results
        session['urls'] = discovered_urls
        session['target_url'] = target_url

    return render_template("index.html", results=results, urls=discovered_urls)


@app.route('/download_pdf')
def download_pdf():
    return generate_pdf(
        session.get('results'),
        session.get('urls', []),
        session.get('target_url', '')
    )


if __name__ == "__main__":
    app.run(debug=True)