from flask import Flask
import base64

app = Flask(__name__)

@app.get("/")
def home():
    # Encode the message as base64
    message = "nech:ashes"
    encoded = base64.b64encode(message.encode()).decode()
    return encoded

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
