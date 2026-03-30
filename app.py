from flask import Flask, render_template, request, session, make_response
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

from crawler import crawl
from sqlScanner import scan_sql_injection
from xssScanner import scan_xss
from headerScanner import scan_headers

app = Flask(__name__)
app.secret_key = 'webspidey_secret_key'  # For session storage


def classify_owasp_risk(sqli_vulns, xss_vulns, missing_headers, discovered_urls):
    """Compute an OWASP-style risk score from 1 to 10.

    - SQLi and XSS findings are high-impact.
    - Missing security headers increase risk.
    - Larger attack surface slightly increases risk.
    """
    score = 1

    # Critical flaws (SQLi/XSS) have strong weight
    score += min(len(sqli_vulns) * 3, 7)
    score += min(len(xss_vulns) * 3, 7)

    # Header hygiene
    score += min(len(missing_headers) * 2, 4)

    # Surface area modifier
    if len(discovered_urls) > 20:
        score += 1
    if len(discovered_urls) > 50:
        score += 1

    score = min(10, max(1, score))

    if score <= 3:
        level = "Low"
    elif score <= 6:
        level = "Medium"
    elif score <= 8:
        level = "High"
    else:
        level = "Critical"

    return {
        "score": score,
        "level": level,
        "details": {
            "sql_injection_count": len(sqli_vulns),
            "xss_count": len(xss_vulns),
            "missing_headers_count": len(missing_headers)
        }
    }


def generate_security_suggestions(results, discovered_urls):
    """Generate tailored security suggestions based on scan results."""
    suggestions = []
    owasp_risk = results.get('owasp_risk', {})
    risk_level = owasp_risk.get('level', 'Low')

    # General suggestions based on risk level
    if risk_level == "Critical":
        suggestions.append("🚨 CRITICAL RISK: Immediate action required. Consider taking the site offline until vulnerabilities are patched.")
    elif risk_level == "High":
        suggestions.append("⚠️ HIGH RISK: Prioritize fixing vulnerabilities within the next 24-48 hours.")
    elif risk_level == "Medium":
        suggestions.append("🟡 MEDIUM RISK: Address issues within the next week.")
    else:
        suggestions.append("🟢 LOW RISK: Monitor regularly and apply best practices.")

    # Specific suggestions for SQL Injection
    sqli = results.get('sqli', [])
    if sqli:
        suggestions.append("🔒 SQL Injection Vulnerabilities Detected:")
        suggestions.append("  • Use prepared statements and parameterized queries")
        suggestions.append("  • Implement input validation and sanitization")
        suggestions.append("  • Use ORM libraries that handle SQL escaping")
        suggestions.append("  • Enable database query logging and monitoring")
        suggestions.append("  • Consider using Web Application Firewall (WAF)")

    # Specific suggestions for XSS
    xss = results.get('xss', [])
    if xss:
        suggestions.append("🛡️ XSS Vulnerabilities Detected:")
        suggestions.append("  • Sanitize all user inputs before displaying")
        suggestions.append("  • Use Content Security Policy (CSP) headers")
        suggestions.append("  • Implement output encoding (HTML, JavaScript, etc.)")
        suggestions.append("  • Use secure frameworks that auto-escape content")
        suggestions.append("  • Validate and filter user input on both client and server side")

    # Specific suggestions for missing headers
    headers = results.get('headers', [])
    if headers:
        suggestions.append("📋 Missing Security Headers:")
        for header in headers:
            if header == "Content-Security-Policy":
                suggestions.append("  • Add CSP header to prevent XSS and data injection")
            elif header == "X-Frame-Options":
                suggestions.append("  • Add X-Frame-Options to prevent clickjacking")
            elif header == "X-XSS-Protection":
                suggestions.append("  • Add X-XSS-Protection header (though CSP is preferred)")
        suggestions.append("  • Consider using security headers middleware")

    # General best practices
    suggestions.append("🏆 General Security Best Practices:")
    suggestions.append("  • Keep all software and dependencies updated")
    suggestions.append("  • Implement regular security audits and penetration testing")
    suggestions.append("  • Use HTTPS everywhere")
    suggestions.append("  • Implement proper authentication and authorization")
    suggestions.append("  • Enable logging and monitoring for suspicious activities")
    suggestions.append("  • Use secure coding practices and code reviews")

    # Surface area considerations
    if len(discovered_urls) > 50:
        suggestions.append("🌐 Large Attack Surface Detected:")
        suggestions.append("  • Consider reducing the number of exposed endpoints")
        suggestions.append("  • Implement rate limiting and DDoS protection")
        suggestions.append("  • Use API gateways for better control")

    return suggestions


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

        owasp_risk = classify_owasp_risk(sqli, xss, headers, discovered_urls)

        # Generate security suggestions
        suggestions = generate_security_suggestions({
            "sqli": sqli,
            "xss": xss,
            "headers": headers,
            "owasp_risk": owasp_risk
        }, discovered_urls)

        results = {
            "sqli": sqli,
            "xss": xss,
            "headers": headers,
            "owasp_risk": owasp_risk,
            "suggestions": suggestions
        }

        # Store in session for PDF download
        session['results'] = results
        session['urls'] = discovered_urls
        session['target_url'] = target_url

    return render_template("index.html", results=results, urls=discovered_urls)

@app.route('/download_pdf')
def download_pdf():
    results = session.get('results')
    urls = session.get('urls', [])
    target_url = session.get('target_url', '')

    if not results:
        return "No results to download", 400

    # Generate PDF
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("WebSpidey Vulnerability Scan Report", styles['Title']))
    story.append(Spacer(1, 12))

    story.append(Paragraph(f"Target URL: {target_url}", styles['Normal']))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Discovered URLs:", styles['Heading2']))
    for url in urls:
        story.append(Paragraph(url, styles['Normal']))
    story.append(Spacer(1, 12))

    story.append(Paragraph("OWASP Risk Score", styles['Heading2']))
    risk = results.get('owasp_risk', {})
    story.append(Paragraph(f"Score: {risk.get('score', 'N/A')} / 10", styles['Normal']))
    story.append(Paragraph(f"Level: {risk.get('level', 'N/A')}", styles['Normal']))
    details = risk.get('details', {})
    story.append(Paragraph(f"SQL Injection Count: {details.get('sql_injection_count', 0)}", styles['Normal']))
    story.append(Paragraph(f"XSS Count: {details.get('xss_count', 0)}", styles['Normal']))
    story.append(Paragraph(f"Missing Headers Count: {details.get('missing_headers_count', 0)}", styles['Normal']))
    story.append(Spacer(1, 12))

    # SQL Injection
    story.append(Paragraph("SQL Injection", styles['Heading2']))
    sqli = results.get('sqli', [])
    if sqli:
        story.append(Paragraph("Vulnerable URLs:", styles['Normal']))
        for url in sqli:
            story.append(Paragraph(url, styles['Normal']))
    else:
        story.append(Paragraph("Not Detected", styles['Normal']))
    story.append(Spacer(1, 12))

    # XSS
    story.append(Paragraph("XSS", styles['Heading2']))
    xss = results.get('xss', [])
    if xss:
        story.append(Paragraph("Vulnerable URLs:", styles['Normal']))
        for url in xss:
            story.append(Paragraph(url, styles['Normal']))
    else:
        story.append(Paragraph("Not Detected", styles['Normal']))
    story.append(Spacer(1, 12))

    # Headers
    story.append(Paragraph("Security Headers", styles['Heading2']))
    headers = results.get('headers', [])
    if headers:
        story.append(Paragraph("Missing Headers:", styles['Normal']))
        for h in headers:
            story.append(Paragraph(h, styles['Normal']))
    else:
        story.append(Paragraph("All Required Headers Present", styles['Normal']))
    story.append(Spacer(1, 12))

    # Security Suggestions
    story.append(Paragraph("Security Recommendations", styles['Heading2']))
    suggestions = results.get('suggestions', [])
    for suggestion in suggestions:
        story.append(Paragraph(suggestion, styles['Normal']))
    story.append(Spacer(1, 12))

    doc.build(story)
    buffer.seek(0)

    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=scan_report.pdf'
    return response

if __name__ == "__main__":
    app.run(debug=True, port=5000)