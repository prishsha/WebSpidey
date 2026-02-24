from flask import Flask, request

app = Flask(__name__)

@app.route("/")
def home():
    return """
    <h2>Demo Application</h2>
    <p>Testing SQL Injection Detection</p>
    <a href="/login">Login</a>
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

if __name__ == "__main__":
    app.run(port=9000, debug=True)