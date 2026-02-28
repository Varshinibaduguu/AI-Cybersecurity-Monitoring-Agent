from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import pymongo
from datetime import datetime, timedelta
import json
import random
import tempfile
from models.file_analyzer import FileThreatAnalyzer
from models.network_monitor import NetworkMonitor, network_monitor
from models.alert_manager import AlertManager, alert_manager
from models.report_generator import ReportGenerator, init_report_generator

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

# Simple rule-based threat detection (without ML)
class SimpleThreatDetector:
    def detect_login_anomaly(self, login_data):
        """Simple rule-based login anomaly detection"""
        failed_attempts = int(login_data.get('failed_attempts', 0))
        login_time = login_data.get('login_time', '')
        country = login_data.get('country', '')
        
        risk_score = 0
        threat_type = "Normal Activity"
        
        # Risk calculation rules
        if failed_attempts > 5:
            risk_score += 40
            threat_type = "Brute Force Attack"
        elif failed_attempts > 2:
            risk_score += 20
            threat_type = "Suspicious Login"
        
        # Check for unusual login time
        if login_time:
            try:
                hour = int(login_time.split(':')[0])
                if hour >= 22 or hour <= 6:
                    risk_score += 20
                    if threat_type == "Normal Activity":
                        threat_type = "Suspicious Login"
            except:
                pass
        
        # Check for suspicious country
        suspicious_countries = ["Nigeria", "Russia", "China", "North Korea"]
        if country in suspicious_countries:
            risk_score += 30
            if threat_type == "Normal Activity":
                threat_type = "Suspicious Login"
        
        # Determine severity
        if risk_score <= 30:
            severity = "Low"
        elif risk_score <= 70:
            severity = "Medium"
        else:
            severity = "High"
        
        return {
            'threat_type': threat_type,
            'risk_score': min(risk_score, 100),
            'severity': severity,
            'is_anomaly': risk_score > 30,
            'confidence': 0.75
        }
    
    def detect_phishing(self, email_content):
        """Simple rule-based phishing detection"""
        if not email_content or len(email_content.strip()) < 10:
            return {
                'threat_type': 'Safe',
                'risk_score': 0,
                'severity': 'Low',
                'is_phishing': False,
                'confidence': 0.95
            }
        
        risk_score = 0
        email_lower = email_content.lower()
        
        # Suspicious keywords
        suspicious_keywords = [
            'urgent', 'immediate', 'suspended', 'verify', 'confirm',
            'click here', 'account', 'password', 'security', 'alert',
            'congratulations', 'winner', 'prize', 'claim', 'limited',
            'offer', 'discount', 'free', 'risk', 'threat', 'compromised'
        ]
        
        keyword_count = sum(1 for keyword in suspicious_keywords if keyword in email_lower)
        risk_score += min(keyword_count * 5, 30)
        
        # URL detection
        if 'http://' in email_lower or 'https://' in email_lower:
            url_count = email_lower.count('http')
            risk_score += min(url_count * 5, 20)
        
        # Urgency indicators
        urgency_words = ['urgent', 'immediately', 'asap', 'right now', 'quickly']
        urgency_count = sum(1 for word in urgency_words if word in email_lower)
        risk_score += urgency_count * 8
        
        # Capitalization abuse
        words = email_content.split()
        all_caps_words = sum(1 for word in words if word.isupper() and len(word) > 3)
        if len(words) > 0:
            all_caps_ratio = all_caps_words / len(words)
            if all_caps_ratio > 0.3:
                risk_score += 10
        
        # Determine if phishing
        is_phishing = risk_score > 25
        
        if is_phishing:
            threat_type = "Phishing Attack"
            risk_score += 20  # Base score for phishing
        else:
            threat_type = "Safe"
        
        # Determine severity
        if risk_score <= 30:
            severity = "Low"
        elif risk_score <= 70:
            severity = "Medium"
        else:
            severity = "High"
        
        return {
            'threat_type': threat_type,
            'risk_score': min(risk_score, 100),
            'severity': severity,
            'is_phishing': is_phishing,
            'confidence': 0.70,
            'features': {
                'suspicious_keywords': keyword_count,
                'url_count': email_lower.count('http'),
                'urgency_score': urgency_count,
                'all_caps_ratio': all_caps_ratio if len(words) > 0 else 0
            }
        }

# Initialize threat detector and file analyzer
detector = SimpleThreatDetector()
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

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
        result = detector.detect_login_anomaly({
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
        
        # Trigger alert for high-risk login threats
        if result['risk_score'] >= 40:
            alert_manager.trigger_alert(log_entry)
        
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
        result = detector.detect_phishing(email_content)
        
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
        
        # Trigger alert for high-risk email threats
        if result['risk_score'] >= 40:
            alert_manager.trigger_alert(log_entry)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
        
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                
                # Save file temporarily
                file.save(temp_path)
                temp_files.append(temp_path)
                files_to_analyze.append((temp_path, filename))
        
        if not files_to_analyze:
            return jsonify({
                'error': 'No valid files to analyze',
                'status': 'error'
            }), 400
        
        # Analyze all files
        analysis_results = file_analyzer.analyze_multiple_files(files_to_analyze)
        
        # Log results to database for each file
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
                
                # Trigger alert for high-risk file threats
                if file_result['risk_score'] >= 40:
                    alert_manager.trigger_alert(log_entry)
        
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
        
        # If no data, generate sample data
        if len(logs) == 0:
            logs = generate_sample_logs()
        
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
        
        if len(logs) == 0:
            logs = generate_sample_logs()
        
        return jsonify({'logs': logs})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def generate_sample_logs():
    """Generate sample threat logs for demonstration"""
    sample_logs = []
    
    # Sample users and data
    users = ["john_doe", "jane_smith", "bob_wilson", "alice_brown"]
    threat_types = ["Brute Force Attack", "Suspicious Login", "Phishing Attack", "Normal Activity"]
    severities = ["Low", "Medium", "High"]
    
    for i in range(20):
        user = random.choice(users)
        threat_type = random.choice(threat_types)
        severity = random.choice(severities)
        
        # Generate risk score based on severity
        if severity == "High":
            risk_score = random.randint(71, 100)
        elif severity == "Medium":
            risk_score = random.randint(31, 70)
        else:
            risk_score = random.randint(0, 30)
        
        # Random timestamp within last 48 hours
        timestamp = datetime.now() - timedelta(hours=random.randint(0, 48))
        
        sample_logs.append({
            'user': user,
            'threat_type': threat_type,
            'risk_score': risk_score,
            'severity': severity,
            'timestamp': timestamp,
            'details': {
                'failed_attempts': random.randint(0, 10),
                'country': random.choice(["United States", "Nigeria", "United Kingdom", "Canada"]),
                'ip_address': f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
            }
        })
    
    return sample_logs

@app.route('/api/network_data', methods=['GET'])
def get_network_data():
    """Get live network monitoring data"""
    try:
        # Ensure monitoring is active
        if not network_monitor.is_monitoring:
            network_monitor.start_monitoring()
        
        # Get network statistics
        stats = network_monitor.get_network_stats()
        
        return jsonify({
            'status': 'success',
            'network_stats': stats,
            'is_monitoring': network_monitor.is_monitoring,
            'total_packets_analyzed': network_monitor.packet_counter
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/network_control', methods=['POST'])
def control_network_monitoring():
    """Control network monitoring (start/stop)"""
    try:
        data = request.get_json()
        action = data.get('action', 'status')
        
        if action == 'start':
            network_monitor.start_monitoring()
            return jsonify({'status': 'success', 'message': 'Network monitoring started', 'is_monitoring': True})
        elif action == 'stop':
            network_monitor.stop_monitoring()
            return jsonify({'status': 'success', 'message': 'Network monitoring stopped', 'is_monitoring': False})
        else:
            return jsonify({'status': 'success', 'is_monitoring': network_monitor.is_monitoring})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/recent', methods=['GET'])
def get_recent_alerts():
    """Get recent alerts for dashboard display"""
    try:
        alerts = alert_manager.get_recent_alerts(limit=10)
        return jsonify({
            'status': 'success',
            'alerts': alerts
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/test', methods=['POST'])
def test_alert():
    """Send a test alert to verify configuration"""
    try:
        data = request.get_json()
        channel = data.get('channel', 'all')
        
        results = alert_manager.test_alert(channel)
        
        return jsonify({
            'status': 'success',
            'message': 'Test alert sent',
            'results': results
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/config', methods=['GET', 'POST'])
def alert_config():
    """Get or update alert configuration"""
    try:
        if request.method == 'GET':
            # Return current configuration (without sensitive data)
            config = {
                'email': {
                    'enabled': alert_manager.config['email']['enabled'],
                    'recipients': len(alert_manager.config['email']['recipients'])
                },
                'telegram': {
                    'enabled': alert_manager.config['telegram']['enabled'],
                    'chat_ids': len(alert_manager.config['telegram']['chat_ids'])
                },
                'desktop': alert_manager.config['desktop'],
                'sound': alert_manager.config['sound'],
                'thresholds': alert_manager.config['thresholds']
            }
            return jsonify({
                'status': 'success',
                'config': config
            })
        
        elif request.method == 'POST':
            data = request.get_json()
            alert_manager.update_config(data)
            return jsonify({
                'status': 'success',
                'message': 'Alert configuration updated'
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/summary', methods=['GET'])
def get_report_summary():
    """Get security report summary"""
    try:
        days = int(request.args.get('days', 7))
        report_gen = init_report_generator(threat_logs)
        report = report_gen.generate_summary_report(days)
        return jsonify({'status': 'success', 'report': report})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/download', methods=['GET'])
def download_report():
    """Download security report in various formats"""
    try:
        days = int(request.args.get('days', 7))
        format_type = request.args.get('format', 'json')  # json, csv, html
        
        report_gen = init_report_generator(threat_logs)
        
        if format_type == 'json':
            report_data = report_gen.export_to_json(days)
            mimetype = 'application/json'
            filename = f'security_report_{datetime.now().strftime("%Y%m%d")}.json'
        elif format_type == 'csv':
            report_data = report_gen.export_to_csv(days)
            mimetype = 'text/csv'
            filename = f'security_report_{datetime.now().strftime("%Y%m%d")}.csv'
        elif format_type == 'html':
            report_data = report_gen.generate_pdf_report_content(days)
            mimetype = 'text/html'
            filename = f'security_report_{datetime.now().strftime("%Y%m%d")}.html'
        else:
            return jsonify({'error': 'Invalid format'}), 400
        
        from flask import Response
        return Response(
            report_data,
            mimetype=mimetype,
            headers={
                'Content-Disposition': f'attachment; filename={filename}'
            }
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting Cybersecurity Monitoring Dashboard...")
    print(f"📍 Dashboard will be available at: http://localhost:{port}")
    print("🔧 Using simplified rule-based detection (no ML dependencies)")
    app.run(host='0.0.0.0', port=port, debug=True)
