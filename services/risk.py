def classify_owasp_risk(sqli_vulns, xss_vulns, missing_headers, discovered_urls):
    score = 1

    score += min(len(sqli_vulns) * 3, 7)
    score += min(len(xss_vulns) * 3, 7)
    score += min(len(missing_headers) * 2, 4)

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
    suggestions = []
    risk_level = results.get('owasp_risk', {}).get('level', 'Low')

    if risk_level == "Critical":
        suggestions.append("🚨 CRITICAL RISK: Immediate action required.")
    elif risk_level == "High":
        suggestions.append("⚠️ HIGH RISK: Fix within 24-48 hours.")
    elif risk_level == "Medium":
        suggestions.append("🟡 MEDIUM RISK: Fix within a week.")
    else:
        suggestions.append("🟢 LOW RISK: Maintain best practices.")

    if results.get('sqli'):
        suggestions.append("Use prepared statements for SQL.")

    if results.get('xss'):
        suggestions.append("Sanitize inputs and use CSP.")

    if results.get('headers'):
        suggestions.append("Add missing security headers.")

    suggestions.append("Use HTTPS, logging, and regular audits.")

    return suggestions