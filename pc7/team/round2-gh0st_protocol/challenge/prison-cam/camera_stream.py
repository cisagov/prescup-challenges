from flask import Flask, Response, render_template_string
import cv2

app = Flask(__name__)
vid = cv2.VideoCapture(0)  # Use 0 for local webcam, or replace with video file path

HTML = """
<html><body>
<h2>Prison Camera Feed</h2>
<img src="{{ url_for('video_feed') }}">
</body></html>
"""

def gen_frames():
    while True:
        success, frame = vid.read()
        if not success:
            break
        ret, buffer = cv2.imencode('.jpg', frame)
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + buffer.tobytes() + b'\r\n')

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/video_feed')
def video_feed():
    return Response(gen_frames(),
                    mimetype='multipart/x-mixed-replace; boundary=frame')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)