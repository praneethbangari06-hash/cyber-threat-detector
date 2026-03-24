import os
import magic
import zipfile
import requests
import time
import hashlib
import numpy as np
from PIL import Image
from PIL.ExifTags import TAGS
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "cyber_security_secret_key"
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

# VirusTotal API Key
VT_API_KEY = os.environ.get("VT_API_KEY", "e9fd0a09f087ee4f1fcf449cc6542f6b896647db99ef061aec053cd274540e13")

# Ensure upload directory exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- CORE FUNCTIONS ---

def detect_file_type(file_path):
    """Detect real file type using magic numbers (MIME types)."""
    try:
        # Check first few bytes for magic numbers as a fallback
        with open(file_path, 'rb') as f:
            header = f.read(10)
            if header.startswith(b'\x89PNG'): return 'image/png'
            if header.startswith(b'\xFF\xD8\xFF'): return 'image/jpeg'
            if header.startswith(b'%PDF'): return 'application/pdf'
            if header.startswith(b'PK\x03\x04'): return 'application/zip'
            if header.startswith(b'MZ'): return 'application/x-dosexec'
            if header.startswith(b'Rar!'): return 'application/x-rar'

        # Use the magic library for more comprehensive detection
        mime = magic.Magic(mime=True)
        file_type = mime.from_file(file_path)
        return file_type
    except Exception as e:
        print(f"Error detecting file type: {e}")
        return "unknown/unknown"

def fake_detection(filename, detected_mime, file_path):
    """Detect fake files, double extensions, and suspicious patterns."""
    reasons = []
    
    # 1. Double extension check
    parts = filename.split('.')
    if len(parts) > 2:
        reasons.append("Double extension detected (e.g., file.jpg.exe)")

    # 2. Extension vs MIME check
    extension = filename.split('.')[-1].lower()
    mime_map = {
        'png': 'image/png',
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'pdf': 'application/pdf',
        'zip': 'application/zip',
        'exe': 'application/x-dosexec',
        'rar': 'application/x-rar',
        'txt': 'text/plain'
    }
    
    expected_mime = mime_map.get(extension)
    if expected_mime and expected_mime != detected_mime:
        reasons.append(f"File extension (.{extension}) does not match actual detected type ({detected_mime})")

    # 3. Dangerous extensions
    dangerous_exts = ['exe', 'bat', 'cmd', 'js', 'vbs', 'ps1', 'scr']
    if extension in dangerous_exts:
        reasons.append(f"Dangerous executable extension detected: .{extension}")

    # 4. Hidden files
    if filename.startswith('.'):
        reasons.append("Hidden file detected (starts with '.')")

    # 5. Very small files
    file_size = os.path.getsize(file_path)
    if file_size < 1024:
        reasons.append("File is very small (less than 1KB), which can be suspicious for certain file types")

    return reasons

def scan_zip(file_path):
    """Extract and scan ZIP contents for executables."""
    reasons = []
    try:
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            for file_info in zip_ref.infolist():
                if file_info.filename.endswith(('.exe', '.bat', '.cmd', '.vbs', '.js')):
                    reasons.append(f"Malicious file found inside ZIP: {file_info.filename}")
    except zipfile.BadZipFile:
        reasons.append("Corrupted or invalid ZIP file")
    except Exception as e:
        reasons.append(f"Error scanning ZIP: {str(e)}")
    
    return reasons

def get_file_hash(file_path):
    """Generate SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_hash_virustotal(file_hash):
    """Check if file hash exists in VirusTotal database."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print(f"Error checking hash: {e}")
        return None

def upload_file_virustotal(file_path):
    """Upload file to VirusTotal and return analysis ID."""
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VT_API_KEY}
    try:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            response = requests.post(url, headers=headers, files=files)
            if response.status_code == 200:
                return response.json().get("data", {}).get("id")
        return None
    except Exception as e:
        print(f"Error uploading file: {e}")
        return None

def get_analysis_result(analysis_id):
    """Fetch scan report using analysis ID."""
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        # Wait a bit for analysis to complete
        time.sleep(10)
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print(f"Error getting analysis: {e}")
        return None

def parse_vt_results(vt_data):
    """Extract malicious/suspicious counts and return status."""
    if not vt_data:
        return "⚠️ Scan unavailable"
    
    # Check if it's from /files or /analyses endpoint
    stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats")
    if not stats:
        # Try from /analyses endpoint structure
        stats = vt_data.get("data", {}).get("attributes", {}).get("stats")
        
    if stats:
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        
        if malicious > 0:
            return "❌ Virus Detected"
        elif suspicious > 0:
            return "⚠️ Suspicious File"
        else:
            return "✅ No Virus Detected (Safe)"
    
    return "⚠️ Scan unavailable"

def scan_file_virustotal(file_path):
    """
    Hybrid detection approach:
    1. Check hash (Fast)
    2. Upload if unknown (Accurate)
    3. Fetch result
    """
    if not VT_API_KEY:
        return {"status": "⚠️ Scan unavailable", "error": "No API Key provided"}

    try:
        # STEP 1: HASH-BASED CHECK
        file_hash = get_file_hash(file_path)
        print(f"Checking hash: {file_hash}")
        hash_data = check_hash_virustotal(file_hash)
        
        if hash_data:
            print("Hash found in database.")
            status = parse_vt_results(hash_data)
            return {"status": status}

        # STEP 2: FILE UPLOAD (IF NOT FOUND)
        print("Hash not found. Uploading file...")
        analysis_id = upload_file_virustotal(file_path)
        
        if analysis_id:
            # STEP 3: FETCH SCAN RESULT
            print(f"Scanning in progress (ID: {analysis_id})...")
            analysis_data = get_analysis_result(analysis_id)
            status = parse_vt_results(analysis_data)
            return {"status": status}
        
        return {"status": "⚠️ Scan unavailable", "error": "Upload failed"}

    except Exception as e:
        return {"status": "⚠️ Scan unavailable", "error": str(e)}

def check_url(url_to_check):
    """Detect suspicious URLs using heuristic rules."""
    reasons = []
    url_lower = url_to_check.lower()
    
    # 1. Keywords
    suspicious_keywords = ['login', 'verify', 'update', 'secure', 'bank', 'account', 'signin', 'wp-admin']
    for kw in suspicious_keywords:
        if kw in url_lower:
            reasons.append(f"URL contains suspicious keyword: '{kw}'")
            break

    # 2. @ symbol
    if '@' in url_to_check:
        reasons.append("URL contains '@' symbol, often used for phishing/redirection")

    # 3. Multiple dots
    if url_to_check.count('.') > 3:
        reasons.append("URL contains excessive number of dots")

    # 4. Fake domains (basic check)
    fake_domains = ['amaz0n', 'paypa1', 'faceb00k', 'goog1e', 'm1crosoft']
    for fd in fake_domains:
        if fd in url_lower:
            reasons.append(f"URL looks like a fake/typosquatted domain: '{fd}'")
            break

    return reasons

def detect_ai_image_advanced(file_path):
    """
    Advanced AI Image Detection using a hybrid heuristic approach:
    - Metadata analysis
    - Resolution patterns
    - Pixel statistics
    - Symmetry and Lighting consistency
    - Edge/Texture and Noise analysis
    """
    print("AI DETECTION RUNNING")
    try:
        score = 0
        ai_reasons = []
        
        # Load image
        img = Image.open(file_path)
        width, height = img.size
        img_array = np.array(img.convert('RGB'))
        
        # 1. METADATA CHECK
        exif = img._getexif()
        if not exif:
            score += 50
            ai_reasons.append("No camera metadata found (High AI Signal)")
        
        # 2. RESOLUTION PATTERN CHECK
        if width % 64 == 0 and height % 64 == 0:
            score += 30
            ai_reasons.append("Resolution matches AI generation pattern (multiples of 64)")
            
        # 3. PIXEL VARIATION / FACE SMOOTHNESS CHECK
        std_dev = np.std(img_array)
        if std_dev < 40:
            score += 20
            ai_reasons.append("Overly smooth textures detected (AI-like)")
            
        # 4. COLOR / BRIGHTNESS CHECK
        mean_val = np.mean(img_array)
        if mean_val > 180:
            score += 10
            ai_reasons.append("Artificial lighting / High brightness consistency")
            
        # 5. EDGE / TEXTURE CHECK (BLUR CHECK)
        edge_diff = np.mean(np.abs(np.diff(img_array, axis=0)))
        if edge_diff < 10:
            score += 15
            ai_reasons.append("Low edge variation (Unnatural smooth texture)")

        # 6. SYMMETRY CHECK (AI often generates too symmetric features)
        # Check basic horizontal symmetry
        img_flipped = np.fliplr(img_array)
        symmetry_diff = np.mean(np.abs(img_array - img_flipped))
        if symmetry_diff < 40: # Low difference means high symmetry
            score += 10
            ai_reasons.append("High structural symmetry detected (AI-like)")

        # 7. NOISE PATTERN CHECK
        # Real images have sensor noise; AI images are often "too clean"
        noise_var = np.var(img_array)
        if noise_var < 500:
            score += 15
            ai_reasons.append("Lack of natural sensor noise (image is too digitally clean)")
            
        # Final Decision logic
        if score >= 70:
            result = "❌ AI Generated Image"
        elif score >= 40:
            result = "⚠️ Possibly AI Generated"
        elif score >= 20:
            result = "🔍 Low-level AI Signals"
        else:
            result = "✅ Likely Real Image"
            
        return result, min(score, 100), ai_reasons
        
    except Exception as e:
        print(f"AI Advanced Detection Error: {e}")
        return "⚠️ AI detection failed", 0, ["Analysis engine encountered an error"]

def decision_engine(file_reasons, zip_reasons, vt_result, url_reasons):
    """Combine all results and give one final output."""
    all_reasons = file_reasons + zip_reasons + url_reasons
    
    vt_status = vt_result.get("status", "")
    is_malicious_vt = "❌ Virus Detected" in vt_status
    is_suspicious_vt = "⚠️ Suspicious File" in vt_status

    if vt_status:
        all_reasons.append(f"VirusTotal Result: {vt_status}")

    # Priority Decision logic
    if zip_reasons or is_malicious_vt:
        status = "Dangerous"
        risk_level = "HIGH"
        risk_color = "danger"
        action = "Delete immediately"
    elif file_reasons or url_reasons or is_suspicious_vt:
        status = "Suspicious"
        risk_level = "MEDIUM"
        risk_color = "warning"
        action = "Be cautious"
    else:
        status = "Safe"
        risk_level = "LOW"
        risk_color = "success"
        action = "Safe to open"

    return {
        "status": status,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "action": action,
        "reasons": all_reasons
    }

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'GET':
        return redirect(url_for('index'))
    
    url_input = request.form.get('url', '').strip()
    file = request.files.get('file')
    
    if not file and not url_input:
        flash("Please provide a file or a URL to scan.")
        return redirect(url_for('index'))

    results = {
        "filename": "N/A",
        "file_type": "N/A",
        "vt_status": "Not scanned",
        "url_status": "Not scanned",
        "ai_result": "Not applicable",
        "ai_confidence": 0,
        "ai_reasons": [],
        "final_decision": {}
    }

    file_reasons = []
    zip_reasons = []
    vt_result = {}
    url_reasons = []

    # Handle File Scan
    if file and file.filename:
        try:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            results["filename"] = filename
            
            # 1. Detect File Type
            detected_mime = detect_file_type(file_path)
            results["file_type"] = detected_mime
            
            # 2. Fake & Suspicious Detection
            file_reasons = fake_detection(filename, detected_mime, file_path)
            
            # 3. ZIP Scan
            if detected_mime == 'application/zip' or filename.lower().endswith('.zip'):
                zip_reasons = scan_zip(file_path)
                
            # 4. VirusTotal Scan
            vt_result = scan_file_virustotal(file_path)
            results["vt_status"] = vt_result.get("status", "Error")

            # 5. Advanced AI Image Detection (Heuristic)
            if detected_mime in ['image/png', 'image/jpeg', 'image/jpg']:
                ai_label, ai_score, ai_reasons_list = detect_ai_image_advanced(file_path)
                results["ai_result"] = ai_label
                results["ai_confidence"] = ai_score
                results["ai_reasons"] = ai_reasons_list
                
                # Add AI findings to main reasons if suspicious/dangerous
                if ai_score >= 30:
                    file_reasons.append(f"AI Detection: {ai_label} ({ai_score}%)")
            
        except Exception as e:
            file_reasons.append(f"Error processing file: {str(e)}")
            results["filename"] = file.filename
            results["file_type"] = "Error"

    # Handle URL Scan
    if url_input:
        url_reasons = check_url(url_input)
        results["url_status"] = "⚠️ Suspicious Link" if url_reasons else "✅ Safe Link"

    # 5. Final Decision
    results["final_decision"] = decision_engine(file_reasons, zip_reasons, vt_result, url_reasons)

    return render_template('result.html', results=results)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
