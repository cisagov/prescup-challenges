from flask import Flask, request, send_file
import subprocess
import os
import tempfile

app = Flask(__name__)

CA_CERT = '/home/user/certs/CA.pem'
CA_KEY = '/home/user/certs/CA.key'
PASS_PHRASE = 'tartans'  

@app.route('/generate-certificate', methods=['POST'])
def generate_certificate():
    if 'csr' not in request.files:
        return 'No CSR file provided', 400

    csr_file = request.files['csr']

    with tempfile.TemporaryDirectory() as temp_dir:
        csr_path = os.path.join(temp_dir, 'request.csr')
        crt_path = os.path.join(temp_dir, 'certificate.crt')

        csr_file.save(csr_path)

        try:
            command = [
                'openssl', 'x509', '-req', '-in', csr_path,
                '-CA', CA_CERT, '-CAkey', CA_KEY, '-CAcreateserial',
                '-out', crt_path, '-days', '1000', '-sha256', 
                '-passin', f'pass:{PASS_PHRASE}'  
            ]

            subprocess.run(command, check=True)

        except subprocess.CalledProcessError as e:
            return f'Error generating certificate: {e}', 500

        return send_file(crt_path, as_attachment=True, download_name='certificate.crt')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
