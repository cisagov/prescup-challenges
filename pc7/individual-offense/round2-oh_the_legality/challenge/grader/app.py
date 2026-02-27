from flask import Flask, request, render_template_string
import hashlib
import os

app = Flask(__name__)

# Target SHA-256 hash
TARGET_HASH = "C93325B895B6554BBB8734CAC6808C6F3CE09727F69551AD57163F26181E4684"

# Simple HTML upload form
HTML_FORM = '''
<!DOCTYPE html>
<html>
<head><title>Upload File</title></head>
<body>
    <h2>Upload File for Hash Check</h2>
    <form method="POST" action="/submit" enctype="multipart/form-data">
        <input type="file" name="file">
        <input type="submit" value="Upload">
    </form>
</body>
</html>
'''

@app.route('/', methods=['GET'])
def index():
    return render_template_string(HTML_FORM)

@app.route('/submit', methods=['POST'])
def submit():
    if 'file' not in request.files:
        return 'No file part in the request.', 400

    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return 'No selected file.', 400

    file_bytes = uploaded_file.read()
    hash_obj = hashlib.sha256(file_bytes).hexdigest().upper()

    if hash_obj == TARGET_HASH:
        secret_flag = os.environ.get('token3', 'FLAG_NOT_SET')
        return f'Hash matched. Secret: {secret_flag}'
    else:
        print("Hash accepted: " + hash_obj)
        return 'Hash did not match: ' + hash_obj, 403

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
