from flask import Flask, render_template, request, session

from crawler import crawl
from sqlScanner import scan_sql_injection
from xssScanner import scan_xss
from headerScanner import scan_headers

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

        discovered_urls = crawl(target_url)
        sqli = scan_sql_injection(discovered_urls)
        xss = scan_xss(discovered_urls)
        headers = scan_headers(target_url)

        owasp_risk = classify_owasp_risk(sqli, xss, headers, discovered_urls)

        results = {
            "sqli": sqli,
            "xss": xss,
            "headers": headers,
            "owasp_risk": owasp_risk
        }

        results["suggestions"] = generate_security_suggestions(results, discovered_urls)

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