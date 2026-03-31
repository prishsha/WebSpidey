console.log("Chatbot script loaded");

window.showLoading = function() {
    console.log("Loading...");
};

document.addEventListener("DOMContentLoaded", function () {

    const chatbotBtn = document.getElementById('chatbot-btn');
    const modal = document.getElementById('chatbot-modal');
    const closeBtn = document.querySelector('.close');
    const chatMessages = document.getElementById('chat-messages');
    const input = document.getElementById('chat-input');

    const results = JSON.parse(
        document.getElementById('results-data')?.innerText || "{}"
    );

    if (!chatbotBtn || !modal || !closeBtn) {
        console.error("Modal elements not found");
        return;
    }

    // Open modal
    chatbotBtn.addEventListener("click", () => {
        console.log("Opening chatbot modal");
        modal.style.display = "block";
    });

    // Close modal
    closeBtn.addEventListener("click", () => {
        modal.style.display = "none";
    });

    //Click outside
    window.addEventListener("click", (e) => {
        if (e.target === modal) modal.style.display = "none";
    });

    // Enter key
    if (input) {
        input.addEventListener("keypress", function (e) {
            if (e.key === "Enter") sendMessage();
        });
    }

    // Send message function
    window.sendMessage = function () {
        const text = input.value.trim();
        if (!text) return;

        addMessage(text, "user-message");
        input.value = "";

        const reply = generateResponse(text.toLowerCase());
        addMessage(reply, "bot-message");
    };

    function addMessage(text, className) {
        const msg = document.createElement('div');
        msg.className = 'message ' + className;
        msg.innerText = text;
        chatMessages.appendChild(msg);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    function generateResponse(query) {
        const r = results?.owasp_risk;
        const sqli = results?.sqli || [];
        const xss = results?.xss || [];
        const redirect = results?.open_redirect || [];
        const dirs = results?.directories || [];
        const data = results?.sensitive_data || [];
        const headers = results?.headers || [];
        const suggestions = results?.suggestions || [];

        if (query.includes("risk") || query.includes("score")) {
            if (!r) return "Run a scan first.";
            return `Security score: ${r.score}/10 (${r.level})`;
        }

        if (query.includes("sql")) {
            return sqli.length ? `SQL Injection found (${sqli.length})` : "No SQLi issues.";
        }

        if (query.includes("xss")) {
            return xss.length ? `XSS found (${xss.length})` : "No XSS issues.";
        }

        if (query.includes("redirect")) {
            return redirect.length ? `Open Redirect found (${redirect.length})` : "No redirect issues.";
        }

        if (query.includes("directory")) {
            return dirs.length ? `Directories exposed (${dirs.length})` : "No directory issues.";
        }

        if (query.includes("data")) {
            return data.length ? `Sensitive data exposed` : "No data leaks.";
        }

        if (query.includes("header")) {
            return headers.length ? `Missing headers: ${headers.join(", ")}` : "All headers present.";
        }

        if (query.includes("fix") || query.includes("improve")) {
            return suggestions.slice(0, 5).join("\n");
        }

        return "Ask about vulnerabilities, risk score, or fixes.";
    }

});