def classify_owasp_risk(
    sqli_vulns,
    xss_vulns,
    missing_headers,
    discovered_urls,
    open_redirect,
    directories,
    sensitive_data
):
    """
    Compute an OWASP-style risk score (1–10)
    based on multiple vulnerability categories.
    """

    score = 1

    # 🔴 High impact vulnerabilities
    score += min(len(sqli_vulns) * 3, 7)
    score += min(len(xss_vulns) * 3, 7)

    # 🟠 Medium impact
    score += min(len(open_redirect) * 2, 4)
    score += min(len(sensitive_data) * 2, 4)

    # 🟡 Lower impact
    score += min(len(missing_headers) * 2, 4)
    score += min(len(directories) * 1, 3)

    # 🌐 Attack surface factor
    if len(discovered_urls) > 20:
        score += 1
    if len(discovered_urls) > 50:
        score += 1

    # Normalize score
    score = min(10, max(1, score))

    # Risk level classification
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
            "missing_headers_count": len(missing_headers),
            "open_redirect_count": len(open_redirect),
            "directory_exposure_count": len(directories),
            "sensitive_data_count": len(sensitive_data),
            "total_urls_scanned": len(discovered_urls)
        }
    }


def generate_security_suggestions(results, discovered_urls):
    """
    Generate contextual and professional security recommendations
    based on detected vulnerabilities.
    """

    suggestions = []
    risk_level = results.get('owasp_risk', {}).get('level', 'Low')

    # 🔥 Priority-based intro
    if risk_level == "Critical":
        suggestions.append("🚨 Critical risk level detected. Immediate remediation is strongly recommended.")
    elif risk_level == "High":
        suggestions.append("⚠️ High risk level. Address major vulnerabilities as a priority.")
    elif risk_level == "Medium":
        suggestions.append("🟡 Medium risk. Improvements should be made to strengthen security posture.")
    else:
        suggestions.append("🟢 Low risk. Maintain current practices and monitor regularly.")

    # 🔴 SQL Injection
    if results.get('sqli'):
        suggestions.append("🔒 SQL Injection vulnerabilities detected:")
        suggestions.append("  • Use parameterized queries or prepared statements")
        suggestions.append("  • Avoid dynamic query construction")
        suggestions.append("  • Validate and sanitize all inputs")

    # 🔴 XSS
    if results.get('xss'):
        suggestions.append("🛡️ Cross-Site Scripting (XSS) vulnerabilities detected:")
        suggestions.append("  • Sanitize and encode user inputs")
        suggestions.append("  • Implement Content Security Policy (CSP)")
        suggestions.append("  • Avoid injecting raw HTML into pages")

    # 🟠 Open Redirect
    if results.get('open_redirect'):
        suggestions.append("🔀 Open Redirect vulnerabilities found:")
        suggestions.append("  • Validate and restrict redirect URLs")
        suggestions.append("  • Avoid using user-controlled redirect parameters")

    # 🟠 Sensitive Data Exposure
    if results.get('sensitive_data'):
        suggestions.append("📡 Sensitive data exposure detected:")
        suggestions.append("  • Avoid exposing API keys, tokens, or emails in responses")
        suggestions.append("  • Use environment variables for secrets")
        suggestions.append("  • Mask or encrypt sensitive information")

    # 🟡 Headers
    if results.get('headers'):
        suggestions.append("📋 Missing security headers:")
        suggestions.append("  • Add Content-Security-Policy")
        suggestions.append("  • Add X-Frame-Options")
        suggestions.append("  • Add Strict-Transport-Security")

    # 🟡 Directory Exposure
    if results.get('directories'):
        suggestions.append("📁 Exposed directories detected:")
        suggestions.append("  • Restrict access to sensitive endpoints")
        suggestions.append("  • Disable directory listing on servers")
        suggestions.append("  • Protect admin/debug paths")

    # 🌐 Large attack surface
    if len(discovered_urls) > 50:
        suggestions.append("🌐 Large number of endpoints detected:")
        suggestions.append("  • Reduce unnecessary exposed routes")
        suggestions.append("  • Implement rate limiting and access control")

    # 🏆 General best practices
    suggestions.append("🏆 General Security Best Practices:")
    suggestions.append("  • Use HTTPS across all endpoints")
    suggestions.append("  • Keep dependencies updated")
    suggestions.append("  • Implement logging and monitoring")
    suggestions.append("  • Perform regular security testing")

    return suggestions