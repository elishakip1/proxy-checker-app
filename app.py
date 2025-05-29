<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Proxy Checker</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #f0f2f5;
        }
        .container {
            margin-top: 50px;
            max-width: 800px;
        }
        .textarea-box {
            height: 200px;
        }
        .copy-btn {
            float: right;
            font-size: 12px;
        }
        .used-badge {
            float: right;
            color: #dc3545;
            font-weight: bold;
        }
        .proxy-masked {
            font-family: monospace;
        }
        /* Disabled styles */
        a.disabled {
            pointer-events: none;
            color: #6c757d !important;
            border-color: #6c757d !important;
            opacity: 0.7;
        }
        .copy-btn.disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
    </style>
</head>
<body>
    <div class="container bg-white p-4 rounded shadow-sm">
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h2 class="mb-0">Proxy Checker(V2.1)</h2>
            <a href="#" class="btn btn-outline-secondary btn-sm disabled">⚡Upgrade</a>
        </div>

        {% if message %}
        <div class="alert alert-info">{{ message }}</div>
        {% endif %}

        <div class="accordion" id="proxyAccordion">
            <div class="accordion-item">
                <h2 class="accordion-header" id="formHeading">
                    <button class="accordion-button {% if results %}collapsed{% endif %}" type="button" data-bs-toggle="collapse" data-bs-target="#proxyForm" aria-expanded="{{ 'false' if results else 'true' }}" aria-controls="proxyForm">
                        Paste or Upload Proxies
                    </button>
                </h2>
                <div id="proxyForm" class="accordion-collapse collapse {% if not results %}show{% endif %}" aria-labelledby="formHeading" data-bs-parent="#proxyAccordion">
                    <div class="accordion-body">
                        <form method="POST" enctype="multipart/form-data">
                            <div class="mb-3">
                                <label for="proxyfile" class="form-label">Upload Proxy File</label>
                                <input type="file" class="form-control" name="proxyfile" onchange="checkFileLines(this)">
                            </div>
                            <div class="mb-3">
                                <label for="proxytext" class="form-label">Or Paste Proxies</label>
                                <textarea name="proxytext" id="proxytext" class="form-control textarea-box" placeholder="Paste proxies here (one per line, max 50 lines)..." oninput="limitProxyLines(this)"></textarea>
                            </div>
                            <button type="submit" id="submitBtn" class="btn btn-primary w-100">Check Proxies</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>

        {% if results %}
        <hr>
        <h5 class="mt-4">✅ Good Proxies (Fraud Score 0)</h5>
        <ul class="list-group mt-2">
            {% for item in results %}
            <li class="list-group-item d-flex justify-content-between align-items-center">
                <span class="proxy-masked" id="proxy-{{ loop.index }}" data-full-proxy="{{ item.proxy }}">
                    {{ item.proxy.split(':')[0] }}:{{ item.proxy.split(':')[1] }}:********
                </span>
                {% if item.used %}
                <span class="used-badge">USED</span>
                {% else %}
                <button class="btn btn-sm btn-outline-secondary copy-btn" 
                        onclick="copyToClipboard('proxy-{{ loop.index }}', this); trackUsedProxy('{{ item.proxy }}')">
                    Copy
                </button>
                {% endif %}
            </li>
            {% endfor %}
        </ul>
        <p class="mt-3 text-muted text-end">You will be redirected to the homepage in 5 minutes...</p>
        {% endif %}
    </div>

    <script>
        let trackedProxies = new Set();
        const MAX_LINES = 50;

        function limitProxyLines(textarea) {
            const lines = textarea.value.split('\n');
            if (lines.length > MAX_LINES) {
                textarea.value = lines.slice(0, MAX_LINES).join('\n');
                alert(`You can only enter a maximum of ${MAX_LINES} proxies at a time.`);
            }
        }

        function checkFileLines(input) {
            const file = input.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = function(e) {
                    const lines = e.target.result.split('\n');
                    if (lines.length > MAX_LINES) {
                        alert(`The uploaded file contains more than ${MAX_LINES} lines. Only the first ${MAX_LINES} lines will be processed.`);
                        // Optionally disable submit button or trim the file content before submission
                        // For now, we'll let the backend handle the trimming
                    }
                };
                reader.readAsText(file);
            }
        }

        function copyToClipboard(elementId, clickedButton) {
            const element = document.getElementById(elementId);
            const fullProxy = element.getAttribute('data-full-proxy');
            
            // Immediately disable clicked button
            clickedButton.disabled = true;
            clickedButton.classList.add('disabled');

            navigator.clipboard.writeText(fullProxy).then(() => {
                if (!element.parentElement.querySelector('.text-success')) {
                    const copiedMsg = document.createElement("span");
                    copiedMsg.className = "text-success ms-2 small";
                    copiedMsg.innerText = "✔ Copied!";
                    copiedMsg.style.fontWeight = "bold";
                    element.parentElement.appendChild(copiedMsg);
                }
            });

            // Disable all other buttons
            const allButtons = document.querySelectorAll('.copy-btn');
            allButtons.forEach(button => {
                if (button !== clickedButton) {
                    button.disabled = true;
                    button.classList.add('disabled');
                }
            });

            // Re-enable after 60 seconds
            setTimeout(() => {
                allButtons.forEach(button => {
                    button.disabled = false;
                    button.classList.remove('disabled');
                });
            }, 60000);
        }

        function trackUsedProxy(proxy) {
            if (trackedProxies.has(proxy)) return;
            trackedProxies.add(proxy);
            
            fetch('/track-used', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({proxy: proxy})
            }).catch(error => console.error('Error tracking used proxy:', error));
        }

        {% if results %}
        setTimeout(function() {
            window.location.href = "/";
        }, 300000);
        {% endif %}
    </script>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
