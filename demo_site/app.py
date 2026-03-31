from flask import Flask, request, redirect

app = Flask(__name__)

# =========================
# 🏠 HOME
# =========================
@app.route("/")
def home():
    return """
    <h2>🕷️ WebSpidey Demo Application</h2>
    <p>This demo app intentionally contains vulnerabilities for testing.</p>

    <h3>Test Modules</h3>
    <ul>
        <li><a href="/login">Login (SQL Injection)</a></li>
        <li><a href="/search">Search (XSS)</a></li>
        <li><a href="/redirect?next=https://example.com">Open Redirect</a></li>
        <li><a href="/admin">Admin Panel (Directory Exposure)</a></li>
        <li><a href="/api/data">API Endpoint (Sensitive Data Exposure)</a></li>
    </ul>
    """

# =========================
# 🔴 SQL INJECTION
# =========================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

        # simulate SQL error
        if "'" in username or "'" in password:
            return """
            <h3>Database Error</h3>
            <p>SQL syntax error near '' OR '1'='1'</p>
            """

        return f"""
        <h3>Query Executed</h3>
        <p>{query}</p>
        """

    return """
    <h2>Login Page</h2>
    <form method="POST">
        Username: <input name="username"><br><br>
        Password: <input name="password"><br><br>
        <button type="submit">Login</button>
    </form>
    """

# =========================
# 🔴 XSS
# =========================
@app.route("/search")
def search():
    term = request.args.get("q", "")

    return f"""
    <h2>Search Page</h2>

    <form>
        <input name="q" placeholder="Search something">
        <button type="submit">Search</button>
    </form>

    <h3>Results for: {term}</h3>
    <p style='color:red;'>⚠️ Input reflected directly (XSS possible)</p>
    """

# =========================
# 🟠 OPEN REDIRECT
# =========================
@app.route("/redirect")
def open_redirect():
    target = request.args.get("next", "/")

    # vulnerable: no validation
    return redirect(target)

# =========================
# 🟡 DIRECTORY EXPOSURE
# =========================
@app.route("/admin")
def admin_panel():
    return """
    <h2>Admin Dashboard</h2>
    <p>⚠️ This page should be restricted but is publicly accessible.</p>
    """

@app.route("/backup")
def backup():
    return """
    <h2>Backup Files</h2>
    <p>⚠️ Exposed backup data</p>
    """

# =========================
# 🟠 SENSITIVE DATA EXPOSURE
# =========================
@app.route("/api/data")
def api_data():
    return """
    {
        "user": "admin",
        "email": "admin@example.com",
        "api_key": "12345SECRETKEY",
        "token": "abcdef123456"
    }
    """

# =========================
# 🚀 RUN
# =========================
if __name__ == "__main__":
    app.run(port=9000, debug=True)