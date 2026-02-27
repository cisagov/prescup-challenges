from flask import Flask, render_template, request, redirect, url_for, Response, abort
import os

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'txt', 'py', 'pcap'}  # Allow py: subtle trap

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

# @app.route("/robots.txt", methods=['GET'])
# def robots_txt():
#     robots = """User-agent: *
# Disallow: /admin
# Disallow: /admin/process
# """
#     return Response(robots, mimetype="text/plain")

@app.route("/admin")
def admin():
    abort(400)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        f = request.files['file']
        if f and allowed_file(f.filename):
            filename = f.filename
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            f.save(save_path)
            return redirect(url_for('success', name=filename))
    return render_template('upload.html')

@app.route('/uploads/<name>')
def uploaded_file(name):
    return open(os.path.join(UPLOAD_FOLDER, name)).read()

@app.route('/success/<name>')
def success(name):
    return render_template('success.html', name=name)

@app.route('/admin/process', methods=['POST'])
def process_uploaded_payload():
    secret_key = request.form.get('key')
    filename = request.form.get('file')
    if secret_key != "process_secret_984":  # hidden key required
        return "Unauthorized", 403

    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.isfile(file_path):
        return "File not found", 404

    with open(file_path, 'r') as f:
        code = f.read()

    try:
        exec(code, {'__builtins__': __builtins__, '__name__': '__main__'})
        return "Payload executed successfully"
    except Exception as e:
        return f"Error executing payload: {e}", 500


if __name__ == '__main__':
    app.run(host='0.0.0.0',port=80)
