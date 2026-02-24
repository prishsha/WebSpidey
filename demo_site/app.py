from flask import Flask, request

app = Flask(__name__)

@app.route("/")
def home():
    return """
    <h2>Demo Application - Iteration 2</h2>
    <p>Now includes SQL Injection + XSS vulnerability</p>

    <a href="/login">Login (SQLi)</a><br><br>
    <a href="/search">Search (XSS)</a>
    """

# SQL INJECTION VULNERABILITY 

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

        # simulate SQL error when injection happens
        if "'" in username or "'" in password:
            return """
            <h3>Database Error:</h3>
            <p>You have an error in your SQL syntax near '' OR '1'='1'</p>
            """

        return f"""
        <h3>Executed Query:</h3>
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

# XSS VULNERABILITY 

@app.route("/search")
def search():
    term = request.args.get("q", "")

    # intentionally reflecting user input without sanitization
    return f"""
    <h2>Search Page</h2>

    <form>
        <input name="q" placeholder="Search something">
        <button type="submit">Search</button>
    </form>

    <h3>Results for: {term}</h3>
    <p style='color:red;'>Input reflected directly → XSS possible.</p>
    """

if __name__ == "__main__":
    app.run(port=9000, debug=True)