from flask import Flask, render_template_string, request, redirect, url_for
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64
import json
import time

app = Flask(__name__)

html_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>🔮 SecureTextPro</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet" />
<style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
    body {
        margin: 0;
        padding: 2rem;
        font-family: 'Share Tech Mono', monospace;
        background-color: #0a0a0a;
        color: #d8a0ff;
        overflow-x: hidden;
        position: relative;
        min-height: 100vh;
    }
    h1 {
        color: #bd00ff;
        text-shadow:
          0 0 5px #bd00ff,
          0 0 10px #bd00ff,
          0 0 20px #bd00ff,
          0 0 40px #9b00ff;
        margin-bottom: 1rem;
    }
    .container {
        max-width: 900px;
        margin: auto;
        background: rgba(25, 0, 50, 0.85);
        border-radius: 8px;
        padding: 2rem;
        box-shadow:
          0 0 15px #a000ff,
          inset 0 0 40px #7e00cc;
    }
    textarea, select, input[type="file"] {
        width: 100%;
        padding: 10px;
        margin-top: 10px;
        background: #120027;
        color: #d8a0ff;
        border: 1.5px solid #d8a0ff;
        border-radius: 4px;
        font-size: 1rem;
        resize: vertical;
        box-shadow:
          0 0 5px #bd00ff;
        transition: box-shadow 0.3s;
    }
    textarea:focus, select:focus, input[type="file"]:focus {
        outline: none;
        box-shadow:
          0 0 12px #ff00ff;
    }
    button {
        margin: 10px 0 20px 0;
        padding: 12px 20px;
        background: #9b00ff;
        border: none;
        color: #fff;
        font-weight: 700;
        font-size: 1.1rem;
        cursor: pointer;
        border-radius: 6px;
        box-shadow:
          0 0 10px #9b00ff;
        transition: background-color 0.3s ease;
    }
    button:hover {
        background-color: #bd00ff;
        box-shadow:
          0 0 20px #bd00ff;
    }
    label {
        font-weight: 600;
        font-size: 1rem;
        color: #d8a0ff;
        margin-top: 15px;
        display: block;
    }
    .toggle-theme {
        float: right;
        background: transparent;
        border: 2px solid #bd00ff;
        color: #bd00ff;
        padding: 6px 12px;
        font-weight: 600;
        border-radius: 6px;
        cursor: pointer;
        margin-bottom: 1rem;
        box-shadow:
          0 0 8px #bd00ff;
        transition: all 0.3s ease;
    }
    .toggle-theme:hover {
        background-color: #bd00ff;
        color: #0a0a0a;
        box-shadow:
          0 0 25px #ff33ff;
    }
    .analytics {
        background: #1a0030;
        padding: 15px;
        margin-top: 20px;
        border: 1.5px dashed #bd00ff;
        border-radius: 8px;
        font-size: 0.95rem;
        color: #e5ccff;
        box-shadow:
          inset 0 0 15px #a100ff;
    }
    textarea[readonly] {
        background: #2a004f;
        color: #f0d7ff;
        font-weight: 600;
        cursor: default;
        user-select: all;
        box-shadow:
          inset 0 0 8px #bd00ff;
    }
    .result-section {
        margin-top: 2rem;
    }

    /* Matrix Violet Rain */
    canvas#matrix {
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        pointer-events: none;
        z-index: 0;
        background: black;
        opacity: 0.3;
        mix-blend-mode: screen;
    }
</style>
</head>
<body>
<canvas id="matrix"></canvas>
<div class="container" style="position: relative; z-index: 10;">
    <h1>🔐 SecureTextPro 🔒</h1>
    <button class="toggle-theme" onclick="toggleTheme()">Toggle Theme</button>

    <form action="/encrypt" method="POST" enctype="multipart/form-data">
        <label for="text">Plain Text Input (or upload file):</label>
        <textarea id="text" name="text" rows="4" placeholder="Type text here..."></textarea>
        <input type="file" name="file" id="file" accept=".txt,.json,.csv,.log,.xml,.html" />
        <label for="algorithm">Choose Encryption Algorithm🔒:</label>
        <select name="algorithm" id="algorithm" required>
            <option value="AES">AES🛡️</option>
            <option value="DES">DES🛡️</option>
            <option value="RSA">RSA🛡️</option>
        </select>
        <button type="submit">🔐Encrypt</button>
    </form>

    <form action="/decrypt" method="POST">
        <label for="ciphertext">Encrypted Text:</label>
        <textarea name="ciphertext" id="ciphertext" rows="4" placeholder="Paste encrypted data here..." required></textarea>

        <label for="private_key" id="privateKeyLabel" style="display:none;">RSA Private Key (required for RSA):</label>
        <textarea name="private_key" id="private_key" rows="6" placeholder="Paste your private key here for RSA decryption..." style="display:none;"></textarea>

        <label for="decrypt_algorithm">Choose Decryption Algorithm:</label>
        <select name="algorithm" id="decrypt_algorithm" required onchange="togglePrivateKeyInput()">
            <option value="AES">AES🛡️</option>
            <option value="DES">DES🛡️</option>
            <option value="RSA">RSA🛡️</option>
        </select>
        <button type="submit">🔓Decrypt</button>
    </form>

    {% if result %}
    <div class="result-section">
        <h2>Result:</h2>
        <textarea readonly rows="6">{{ result }}</textarea>
        <button onclick="copyToClipboard(`{{ result | safe }}`)">Copy</button>
    </div>
    {% endif %}

    {% if private_key %}
    <div class="result-section">
        <h2>Your RSA Private Key (Keep it safe!):</h2>
        <textarea readonly rows="10">{{ private_key }}</textarea>
        <button onclick="copyToClipboard(`{{ private_key | safe }}`)">Copy Private Key</button>
    </div>
    {% endif %}

    {% if analytics %}
    <div class="analytics">
        <h3>Encryption Analytics</h3>
        <p>Original Size: {{ analytics.original_size }} bytes</p>
        <p>Encrypted Size: {{ analytics.encrypted_size }} bytes</p>
        <p>Entropy (mock): {{ analytics.entropy }} bits</p>
        <p>Time Taken: {{ analytics.time }} ms</p>
    </div>
    {% endif %}
</div>

<script>
    function copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            alert('Copied!');
        }).catch(() => {
            alert('Failed to copy.');
        });
    }

    function toggleTheme() {
        document.body.classList.toggle('light-mode');
    }

    function togglePrivateKeyInput() {
        const algo = document.getElementById('decrypt_algorithm').value;
        const keyLabel = document.getElementById('privateKeyLabel');
        const keyTextarea = document.getElementById('private_key');
        if (algo === 'RSA') {
            keyLabel.style.display = 'block';
            keyTextarea.style.display = 'block';
            keyTextarea.setAttribute('required', 'required');
        } else {
            keyLabel.style.display = 'none';
            keyTextarea.style.display = 'none';
            keyTextarea.removeAttribute('required');
        }
    }

  
    togglePrivateKeyInput();


    const canvas = document.getElementById('matrix');
    const ctx = canvas.getContext('2d');

    let width = window.innerWidth;
    let height = window.innerHeight;
    canvas.width = width;
    canvas.height = height;

    const letters = 'アァカサタナハマヤャラワガザダバパイィキシチニヒミリヰギジヂビピウゥクスツヌフムユュルグズヅブプエェケセテネヘメレヱゲゼデベペオォコソトノホモヨョロヲゴゾドボポヴ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    const fontSize = 16;
    const columns = Math.floor(width / fontSize);

    const drops = new Array(columns).fill(1);

    function draw() {
        ctx.fillStyle = 'rgba(10, 0, 26, 0.15)'; // translucent dark purple-black background for fading
        ctx.fillRect(0, 0, width, height);

        ctx.fillStyle = '#bd00ff'; // neon violet
        ctx.font = fontSize + 'px "Share Tech Mono", monospace';

        for (let i = 0; i < drops.length; i++) {
            const text = letters.charAt(Math.floor(Math.random() * letters.length));
            ctx.fillText(text, i * fontSize, drops[i] * fontSize);

            if (drops[i] * fontSize > height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i]++;
        }
    }

    setInterval(draw, 50);

    window.addEventListener('resize', () => {
        width = window.innerWidth;
        height = window.innerHeight;
        canvas.width = width;
        canvas.height = height;
    });
</script>
</body>
</html>
'''


def encrypt_aes(data):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    b64data = base64.b64encode(json.dumps({
        'nonce': base64.b64encode(nonce).decode(),
        'tag': base64.b64encode(tag).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'key': base64.b64encode(key).decode()
    }).encode()).decode()
    return b64data, key

def decrypt_aes(b64data):
    try:
        decoded = json.loads(base64.b64decode(b64data).decode())
        nonce = base64.b64decode(decoded['nonce'])
        tag = base64.b64decode(decoded['tag'])
        ciphertext = base64.b64decode(decoded['ciphertext'])
        key = base64.b64decode(decoded['key'])
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data.decode()
    except Exception as e:
        return f"Error during AES decryption: {str(e)}"

def encrypt_des(data):
    key = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    b64data = base64.b64encode(json.dumps({
        'nonce': base64.b64encode(nonce).decode(),
        'tag': base64.b64encode(tag).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'key': base64.b64encode(key).decode()
    }).encode()).decode()
    return b64data, key

def decrypt_des(b64data):
    try:
        decoded = json.loads(base64.b64decode(b64data).decode())
        nonce = base64.b64decode(decoded['nonce'])
        tag = base64.b64decode(decoded['tag'])
        ciphertext = base64.b64decode(decoded['ciphertext'])
        key = base64.b64decode(decoded['key'])
        cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data.decode()
    except Exception as e:
        return f"Error during DES decryption: {str(e)}"

def encrypt_rsa(data):
    key = RSA.generate(2048)
    public_key = key.publickey()
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(data.encode())
    b64cipher = base64.b64encode(ciphertext).decode()
    private_key_pem = key.export_key().decode()
    return b64cipher, private_key_pem

def decrypt_rsa(b64cipher, private_key_pem):
    try:
        private_key = RSA.import_key(private_key_pem)
        cipher = PKCS1_OAEP.new(private_key)
        ciphertext = base64.b64decode(b64cipher)
        data = cipher.decrypt(ciphertext)
        return data.decode()
    except Exception as e:
        return f"Error during RSA decryption: {str(e)}"

def calculate_entropy(data):
    import math
    if not data:
        return 0
    prob = [float(data.count(c)) / len(data) for c in set(data)]
    entropy = - sum([p * math.log2(p) for p in prob])
    return round(entropy, 2)

@app.route('/', methods=['GET'])
def index():
    return render_template_string(html_template)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    text = request.form.get('text', '')
    file = request.files.get('file')
    algorithm = request.form.get('algorithm')

    if file and file.filename:
        text = file.read().decode('utf-8', errors='ignore')

    start_time = time.time()
    result = None
    private_key = None
    key_data = None

    if not text.strip():
        result = "Please provide some input text or file."
        return render_template_string(html_template, result=result)

    if algorithm == 'AES':
        encrypted, key = encrypt_aes(text)
        result = encrypted
        key_data = base64.b64encode(key).decode()
    elif algorithm == 'DES':
        encrypted, key = encrypt_des(text)
        result = encrypted
        key_data = base64.b64encode(key).decode()
    elif algorithm == 'RSA':
        encrypted, private_key = encrypt_rsa(text)
        result = encrypted
    else:
        result = "Unsupported algorithm."

    end_time = time.time()
    time_taken_ms = round((end_time - start_time) * 1000, 2)
    analytics = {
        'original_size': len(text.encode()),
        'encrypted_size': len(result.encode()),
        'entropy': calculate_entropy(text),
        'time': time_taken_ms
    }
    return render_template_string(html_template, result=result, private_key=private_key, analytics=analytics)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    ciphertext = request.form.get('ciphertext', '')
    algorithm = request.form.get('algorithm')
    private_key = request.form.get('private_key', '')

    if not ciphertext.strip():
        result = "Please provide encrypted text."
        return render_template_string(html_template, result=result)

    start_time = time.time()
    result = None

    if algorithm == 'AES':
        result = decrypt_aes(ciphertext)
    elif algorithm == 'DES':
        result = decrypt_des(ciphertext)
    elif algorithm == 'RSA':
        if not private_key.strip():
            result = "Private key is required for RSA decryption."
        else:
            result = decrypt_rsa(ciphertext, private_key)
    else:
        result = "Unsupported algorithm."

    end_time = time.time()
    time_taken_ms = round((end_time - start_time) * 1000, 2)
    analytics = {
        'original_size': len(ciphertext.encode()),
        'encrypted_size': len(ciphertext.encode()),  # same input
        'entropy': calculate_entropy(ciphertext),
        'time': time_taken_ms
    }
    return render_template_string(html_template, result=result, analytics=analytics)

if __name__ == "__main__":
    app.run(debug=True)
