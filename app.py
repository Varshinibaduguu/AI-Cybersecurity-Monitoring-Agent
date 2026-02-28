from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import pymongo
from datetime import datetime
import json
from models.anomaly_model import AnomalyDetector
from models.phishing_model import PhishingDetector
from models.file_analyzer import FileThreatAnalyzer
import tempfile
import shutil

app = Flask(__name__)
CORS(app)

# Configuration
port = int(os.environ.get("PORT", 5000))
mongo_uri = os.environ.get("MONGO_URI")

# Initialize MongoDB client with proper error handling
client = None
db = None
threat_logs = []

if mongo_uri:
    try:
        # Configure MongoDB client with proper settings for Atlas
        client = pymongo.MongoClient(
            mongo_uri,
            serverSelectionTimeoutMS=5000,  # 5 second timeout
            connectTimeoutMS=10000,           # 10 second timeout
            socketTimeoutMS=20000,           # 20 second timeout
            retryWrites=True,
            w="majority"
        )
        
        # Test the connection
        client.admin.command('ping')
        
        # Extract database name from URI or use default
        if '/' in mongo_uri.split('mongodb')[-1]:
            db_name = mongo_uri.split('/')[-1].split('?')[0]
        else:
            db_name = 'cybersecurity'
        
        db = client[db_name]
        threat_logs = db.threat_logs
        
        print(f"✅ Connected to MongoDB Atlas successfully (Database: {db_name})")
        
    except pymongo.errors.ServerSelectionTimeoutError:
        print("❌ MongoDB Atlas connection timeout - using in-memory storage")
        threat_logs = []
    except pymongo.errors.ConnectionFailure as e:
        print(f"❌ MongoDB Atlas connection failed: {e}")
        print("🔄 Falling back to in-memory storage for development")
        threat_logs = []
    except pymongo.errors.ConfigurationError as e:
        print(f"❌ MongoDB Atlas configuration error: {e}")
        print("🔄 Please check your MONGO_URI environment variable")
        threat_logs = []
    except Exception as e:
        print(f"❌ Unexpected MongoDB error: {e}")
        print("🔄 Using in-memory storage as fallback")
        threat_logs = []
else:
    print("⚠️  MONGO_URI environment variable not set")
    print("🔄 Using in-memory storage for development")
    print("💡 To use MongoDB Atlas, set MONGO_URI environment variable:")
    print("   export MONGO_URI='mongodb+srv://<username>:<password>@cluster.mongodb.net/<dbname>'")
    threat_logs = []

# Initialize ML models
anomaly_detector = AnomalyDetector()
phishing_detector = PhishingDetector()
file_analyzer = FileThreatAnalyzer()

# Configure upload settings
UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx',
    'zip', 'rar', 'exe', 'dll', 'bat', 'cmd', 'sh', 'php', 'jsp', 'asp',
    'js', 'html', 'css', 'json', 'xml', 'csv', 'log', 'sql', 'py', 'rb'
}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

@app.route('/')
def dashboard():
    """Render the main dashboard"""
    return render_template('dashboard.html')

@app.route('/api/analyze_login', methods=['POST'])
def analyze_login():
    """Analyze login attempts for anomalies"""
    try:
        data = request.get_json()
        
        # Extract features
        user_id = data.get('user_id', '')
        login_time = data.get('login_time', '')
        failed_attempts = int(data.get('failed_attempts', 0))
        country = data.get('country', '')
        ip_address = data.get('ip_address', '')
        
        # Detect anomaly
        result = anomaly_detector.detect_anomaly({
            'user_id': user_id,
            'login_time': login_time,
            'failed_attempts': failed_attempts,
            'country': country,
            'ip_address': ip_address
        })
        
        # Log to database
        log_entry = {
            'user': user_id,
            'threat_type': result['threat_type'],
            'risk_score': result['risk_score'],
            'severity': result['severity'],
            'timestamp': datetime.now(),
            'details': {
                'failed_attempts': failed_attempts,
                'country': country,
                'ip_address': ip_address
            }
        }
        
        if isinstance(threat_logs, list):
            threat_logs.append(log_entry)
        else:
            threat_logs.insert_one(log_entry)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze_email', methods=['POST'])
def analyze_email():
    """Analyze email content for phishing"""
    try:
        data = request.get_json()
        email_content = data.get('email_content', '')
        
        # Detect phishing
        result = phishing_detector.detect_phishing(email_content)
        
        # Log to database
        log_entry = {
            'user': data.get('user_id', 'unknown'),
            'threat_type': result['threat_type'],
            'risk_score': result['risk_score'],
            'severity': result['severity'],
            'timestamp': datetime.now(),
            'details': {
                'email_length': len(email_content),
                'analysis_type': 'email'
            }
        }
        
        if isinstance(threat_logs, list):
            threat_logs.append(log_entry)
        else:
            threat_logs.insert_one(log_entry)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard_data', methods=['GET'])
def get_dashboard_data():
    """Get aggregated data for dashboard"""
    try:
        if isinstance(threat_logs, list):
            # Use in-memory data
            logs = threat_logs
        else:
            # Use MongoDB data
            logs = list(threat_logs.find({}, {'_id': 0}))
        
        # Calculate metrics
        total_threats = len(logs)
        high_risk = len([log for log in logs if log.get('severity') == 'High'])
        medium_risk = len([log for log in logs if log.get('severity') == 'Medium'])
        
        # Threat type distribution
        threat_types = {}
        for log in logs:
            threat_type = log.get('threat_type', 'Unknown')
            threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
        
        # Recent threats
        recent_threats = sorted(logs, key=lambda x: x.get('timestamp', datetime.min), reverse=True)[:10]
        
        return jsonify({
            'total_threats': total_threats,
            'high_risk': high_risk,
            'medium_risk': medium_risk,
            'system_status': 'Active',
            'threat_types': threat_types,
            'recent_threats': recent_threats,
            'all_logs': logs
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/threat_logs', methods=['GET'])
def get_threat_logs():
    """Get all threat logs"""
    try:
        if isinstance(threat_logs, list):
            logs = threat_logs
        else:
            logs = list(threat_logs.find({}, {'_id': 0}))
        
        return jsonify({'logs': logs})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/analyze_files', methods=['POST'])
def analyze_files():
    """Analyze uploaded files for security threats"""
    temp_files = []
    
    try:
        # Check if files were uploaded
        if 'files' not in request.files:
            return jsonify({'error': 'No files provided', 'status': 'error'}), 400
        
        files = request.files.getlist('files')
        user_id = request.form.get('user_id', 'unknown')
        
        if not files or files[0].filename == '':
            return jsonify({'error': 'No files selected', 'status': 'error'}), 400
        
        # Process each file
        files_to_analyze = []
        processed_files = []
        
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                
                # Save file temporarily
                file.save(temp_path)
                temp_files.append(temp_path)
                files_to_analyze.append((temp_path, filename))
                processed_files.append(filename)
        
        if not files_to_analyze:
            return jsonify({
                'error': 'No valid files to analyze. Allowed extensions: ' + ', '.join(ALLOWED_EXTENSIONS),
                'status': 'error'
            }), 400
        
        # Analyze all files
        analysis_results = file_analyzer.analyze_multiple_files(files_to_analyze)
        
        # Log results to database for each high-risk file
        for file_result in analysis_results['file_results']:
            if file_result['status'] == 'complete':
                log_entry = {
                    'user': user_id,
                    'threat_type': file_result['threat_type'],
                    'risk_score': file_result['risk_score'],
                    'severity': file_result['severity'],
                    'timestamp': datetime.now(),
                    'details': {
                        'filename': file_result['filename'],
                        'file_size': file_result.get('file_size', 0),
                        'file_extension': file_result.get('file_extension', ''),
                        'threat_indicators': file_result.get('threat_indicators', []),
                        'analysis_type': 'file'
                    }
                }
                
                if isinstance(threat_logs, list):
                    threat_logs.append(log_entry)
                else:
                    threat_logs.insert_one(log_entry)
        
        # Clean up temporary files
        for temp_file in temp_files:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except:
                pass
        
        return jsonify({
            'status': 'success',
            'message': f"Successfully analyzed {analysis_results['analyzed_files']} files",
            'overall_analysis': {
                'total_files': analysis_results['total_files'],
                'risk_score': analysis_results['overall_risk_score'],
                'severity': analysis_results['overall_severity'],
                'high_risk_files': analysis_results['high_risk_files'],
                'medium_risk_files': analysis_results['medium_risk_files']
            },
            'file_results': analysis_results['file_results']
        })
        
    except Exception as e:
        # Clean up temporary files on error
        for temp_file in temp_files:
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except:
                pass
        
        return jsonify({
            'status': 'error',
            'error': f"File analysis failed: {str(e)}"
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port, debug=False)
