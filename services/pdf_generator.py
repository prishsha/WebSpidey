from io import BytesIO
from flask import make_response
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet


def generate_pdf(results, urls, target_url):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # 🧾 Title
    story.append(Paragraph("WebSpidey Vulnerability Scan Report", styles['Title']))
    story.append(Spacer(1, 12))

    # 🌐 Target
    story.append(Paragraph(f"<b>Target URL:</b> {target_url}", styles['Normal']))
    story.append(Spacer(1, 12))

    # 📊 Risk Score
    risk = results.get('owasp_risk', {})
    story.append(Paragraph("<b>OWASP Risk Score</b>", styles['Heading2']))
    story.append(Paragraph(f"Score: {risk.get('score', 'N/A')} / 10", styles['Normal']))
    story.append(Paragraph(f"Level: {risk.get('level', 'N/A')}", styles['Normal']))
    story.append(Spacer(1, 12))

    # 🔍 Breakdown (EXPLAINABILITY 🔥)
    details = risk.get('details', {})
    story.append(Paragraph("<b>Risk Breakdown</b>", styles['Heading3']))
    story.append(Paragraph(f"SQL Injection: {details.get('sql_injection_count', 0)}", styles['Normal']))
    story.append(Paragraph(f"XSS: {details.get('xss_count', 0)}", styles['Normal']))
    story.append(Paragraph(f"Open Redirect: {details.get('open_redirect_count', 0)}", styles['Normal']))
    story.append(Paragraph(f"Sensitive Data Exposure: {details.get('sensitive_data_count', 0)}", styles['Normal']))
    story.append(Paragraph(f"Missing Headers: {details.get('missing_headers_count', 0)}", styles['Normal']))
    story.append(Paragraph(f"Directory Exposure: {details.get('directory_exposure_count', 0)}", styles['Normal']))
    story.append(Spacer(1, 12))

    # 🔴 SQL Injection
    story.append(Paragraph("<b>SQL Injection</b>", styles['Heading3']))
    if results.get('sqli'):
        for url in results['sqli']:
            story.append(Paragraph(url, styles['Normal']))
    else:
        story.append(Paragraph("Not Detected", styles['Normal']))
    story.append(Spacer(1, 10))

    # 🔴 XSS
    story.append(Paragraph("<b>XSS</b>", styles['Heading3']))
    if results.get('xss'):
        for url in results['xss']:
            story.append(Paragraph(url, styles['Normal']))
    else:
        story.append(Paragraph("Not Detected", styles['Normal']))
    story.append(Spacer(1, 10))

    # 🟠 Open Redirect
    story.append(Paragraph("<b>Open Redirect</b>", styles['Heading3']))
    if results.get('open_redirect'):
        for url in results['open_redirect']:
            story.append(Paragraph(url, styles['Normal']))
    else:
        story.append(Paragraph("Not Detected", styles['Normal']))
    story.append(Spacer(1, 10))

    # 🟠 Sensitive Data
    story.append(Paragraph("<b>Sensitive Data Exposure</b>", styles['Heading3']))
    if results.get('sensitive_data'):
        for item in results['sensitive_data']:
            story.append(Paragraph(f"{item['url']} ({item['type']})", styles['Normal']))
    else:
        story.append(Paragraph("Not Detected", styles['Normal']))
    story.append(Spacer(1, 10))

    # 🟡 Headers
    story.append(Paragraph("<b>Missing Security Headers</b>", styles['Heading3']))
    if results.get('headers'):
        for h in results['headers']:
            story.append(Paragraph(h, styles['Normal']))
    else:
        story.append(Paragraph("All Present", styles['Normal']))
    story.append(Spacer(1, 10))

    # 🟡 Directories
    story.append(Paragraph("<b>Exposed Directories</b>", styles['Heading3']))
    if results.get('directories'):
        for d in results['directories']:
            story.append(Paragraph(d, styles['Normal']))
    else:
        story.append(Paragraph("Not Detected", styles['Normal']))
    story.append(Spacer(1, 12))

    # 💡 Suggestions
    story.append(Paragraph("<b>Security Recommendations</b>", styles['Heading2']))
    for suggestion in results.get('suggestions', []):
        story.append(Paragraph(suggestion, styles['Normal']))

    doc.build(story)
    buffer.seek(0)

    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=scan_report.pdf'

    return response