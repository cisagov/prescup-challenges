from flask import Flask, render_template_string, request
import subprocess
import os

app = Flask(__name__)

# Simple HTML template with a form and placeholder for result
TEMPLATE = '''
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Submission Page</title>
</head>
<body>
  <h1>Submission Page</h1>
  <form method="post">
    <button type="submit">Check DMARC</button>
  </form>
  {% if result %}
    <p><strong>{{ result }}</strong></p>
  {% endif %}
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        try:
            output = subprocess.check_output(
                ['dig', '+short', 'TXT', '_dmarc.example.com', '@dns'],
                text=True,
                stderr=subprocess.DEVNULL
            )
            txt = output.replace('"', '').replace('\n', ' ')
            if 'p=reject' in txt:
                token = os.environ.get("token3", "TOKEN3_NOT_SET")
                result = f"Congrats! Token: {token}"
            else:
                result = 'Try Again'
        except FileNotFoundError:
            result = 'Error: dig not installed on server'
        except subprocess.CalledProcessError:
            result = 'try again'
    return render_template_string(TEMPLATE, result=result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)