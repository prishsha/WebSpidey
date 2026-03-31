const chatbotBtn = document.getElementById('chatbot-btn');
const modal = document.getElementById('chatbot-modal');
const closeBtn = document.querySelector('.close');
const chatMessages = document.getElementById('chat-messages');
const input = document.getElementById('chat-input');

const results = JSON.parse(
    document.getElementById('results-data')?.innerText || "{}"
);

// Modal controls
chatbotBtn.onclick = () => modal.style.display = "block";
closeBtn.onclick = () => modal.style.display = "none";

window.onclick = (e) => {
    if (e.target === modal) modal.style.display = "none";
};

// Enter key
input.addEventListener("keypress", function (e) {
    if (e.key === "Enter") sendMessage();
});

function sendMessage() {
    const text = input.value.trim();
    if (!text) return;

    addMessage(text, "user-message");
    input.value = "";

    const reply = generateResponse(text.toLowerCase());
    addMessage(reply, "bot-message");
}

function addMessage(text, className) {
    const msg = document.createElement('div');
    msg.className = 'message ' + className;
    msg.innerText = text;
    chatMessages.appendChild(msg);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// 🧠 IMPROVED CHATBOT
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
        return `Security score: ${r.score}/10 (${r.level}).\n\n` +
               `Top contributors:\n` +
               `• SQLi: ${r.details.sql_injection_count}\n` +
               `• XSS: ${r.details.xss_count}\n` +
               `• Redirect: ${r.details.open_redirect_count}`;
    }

    if (query.includes("redirect")) {
        return redirect.length
            ? `Open Redirect found on ${redirect.length} endpoint(s). Validate redirect URLs.`
            : "No open redirect issues detected.";
    }

    if (query.includes("directory") || query.includes("admin")) {
        return dirs.length
            ? `Exposed directories detected (${dirs.length}). Restrict access immediately.`
            : "No exposed directories found.";
    }

    if (query.includes("data") || query.includes("api") || query.includes("leak")) {
        return data.length
            ? `Sensitive data exposure detected. Avoid exposing API keys, tokens, or emails.`
            : "No sensitive data exposure detected.";
    }

    if (query.includes("sql")) {
        return sqli.length
            ? `SQL Injection detected. Use prepared statements.`
            : "No SQL Injection issues found.";
    }

    if (query.includes("xss")) {
        return xss.length
            ? `XSS detected. Sanitize inputs and use CSP.`
            : "No XSS issues found.";
    }

    if (query.includes("header")) {
        return headers.length
            ? `Missing headers: ${headers.join(", ")}`
            : "All security headers are present.";
    }

    if (query.includes("fix") || query.includes("improve")) {
        return suggestions.slice(0, 5).join("\n");
    }

    return "Ask about risk score, SQLi, XSS, redirects, directories, or data exposure.";
}