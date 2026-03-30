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

    story.append(Paragraph("WebSpidey Vulnerability Scan Report", styles['Title']))
    story.append(Spacer(1, 12))

    story.append(Paragraph(f"Target URL: {target_url}", styles['Normal']))

    story.append(Paragraph("OWASP Risk Score", styles['Heading2']))
    risk = results.get('owasp_risk', {})
    story.append(Paragraph(f"Score: {risk.get('score')} / 10", styles['Normal']))

    story.append(Spacer(1, 12))

    for suggestion in results.get('suggestions', []):
        story.append(Paragraph(suggestion, styles['Normal']))

    doc.build(story)
    buffer.seek(0)

    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=scan_report.pdf'

    return response