# 🛡️ AI Cybersecurity Monitoring Agent

A production-ready full-stack AI-powered Cybersecurity Monitoring Agent that detects abnormal login behavior, classifies phishing emails, calculates dynamic risk scores, and displays real-time threat intelligence through an interactive dashboard.

## 🚀 Features

### 🔍 Threat Detection
- **Login Anomaly Detection**: Uses Isolation Forest ML algorithm to detect suspicious login patterns
- **Phishing Email Classification**: TF-IDF Vectorizer with Logistic Regression for email analysis
- **Dynamic Risk Scoring**: Real-time risk calculation (0-100) based on multiple factors
- **Threat Categorization**: Classifies threats as Brute Force, Suspicious Login, Phishing, Malware, or Normal

### 📊 Real-Time Dashboard
- **SOC-style Interface**: Professional security operations center dashboard
- **Interactive Charts**: Threat trends, distribution patterns, user risk analysis
- **Live Monitoring**: Auto-refreshing data every 30 seconds
- **Alert System**: Color-coded severity indicators (Low/Medium/High)

### 🛠️ Technical Stack

#### Backend
- **Python 3.10+** with Flask framework
- **Scikit-learn** for machine learning models
- **Pandas & NumPy** for data processing
- **MongoDB Atlas** for cloud database storage
- **Gunicorn** for production deployment

#### Frontend
- **HTML5, CSS3, Bootstrap 5** for responsive design
- **JavaScript** with Chart.js for data visualization
- **Real-time updates** with asynchronous API calls

#### Deployment
- **Render Free Tier** compatible
- **Docker-ready** architecture
- **Environment variables** for secure configuration

## 📁 Project Structure

```
cybersecurity-agent/
├── app.py                    # Main Flask application
├── models/
│   ├── anomaly_model.py      # Login anomaly detection ML model
│   └── phishing_model.py     # Phishing email detection ML model
├── templates/
│   └── dashboard.html        # Main dashboard interface
├── static/
│   ├── css/
│   │   └── style.css         # Custom styling
│   └── js/
│       └── dashboard.js      # Frontend JavaScript logic
├── requirements.txt          # Python dependencies
├── Procfile                  # Render deployment configuration
├── runtime.txt               # Python version specification
└── README.md                 # This file
```

## 🧠 ML Models

### Login Anomaly Detection
- **Algorithm**: Isolation Forest
- **Features**: Failed attempts, login time, country changes, IP patterns
- **Risk Factors**:
  - Failed attempts > 5 → +40 risk points
  - Unusual login hours (22:00-06:00) → +20 risk points
  - Country different from usual → +30 risk points
  - Suspicious IP address → +10 risk points

### Phishing Email Detection
- **Algorithm**: TF-IDF Vectorizer + Logistic Regression
- **Features**: Keyword analysis, URL detection, urgency indicators
- **Risk Factors**:
  - Suspicious keywords → +5 per keyword
  - Multiple URLs → +15 risk points
  - Urgency language → +8 per instance
  - Phishing detected → +50 risk points

## 🎯 Risk Scoring System

### Risk Calculation
- **0-30**: Low severity (Green)
- **31-70**: Medium severity (Yellow)
- **71-100**: High severity (Red)

### Threat Categories
1. **Brute Force Attack**: Multiple failed login attempts
2. **Suspicious Login**: Unusual login patterns
3. **Phishing Attack**: Malicious email content
4. **Malware Detection**: Suspicious file patterns
5. **Normal Activity**: Legitimate user behavior

## 🚀 Quick Start

### Local Development

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd cybersecurity-agent
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set environment variables**
   ```bash
   export MONGO_URI="mongodb://localhost:27017/cybersecurity"
   export PORT=5000
   ```

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Access the dashboard**
   Open http://localhost:5000 in your browser

## 🌐 Render Deployment Guide

### Step 1: Prepare GitHub Repository
1. Create a new GitHub repository
2. Push all project files to the repository
3. Ensure these files exist:
   - `requirements.txt`
   - `Procfile`
   - `runtime.txt`

### Step 2: Create Render Account
1. Go to [https://render.com](https://render.com)
2. Sign up with your GitHub account
3. Verify your email address

### Step 3: Create Web Service
1. Click **New** → **Web Service**
2. Connect your GitHub repository
3. Configure settings:
   - **Name**: cybersecurity-agent
   - **Runtime**: Python
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`

### Step 4: Add Environment Variables
In your Render service dashboard, add:
- **Key**: `MONGO_URI`
- **Value**: Your MongoDB Atlas connection string
- **Key**: `PORT`
- **Value**: `5000`

### Step 5: Deploy
1. Click **Deploy**
2. Wait 3-5 minutes for deployment
3. Your app will be live at `https://your-app-name.onrender.com`

## 📊 API Endpoints

### Authentication & Analysis
- `POST /api/analyze_login` - Analyze login attempts for anomalies
- `POST /api/analyze_email` - Detect phishing in email content

### Dashboard & Data
- `GET /api/dashboard_data` - Get aggregated dashboard statistics
- `GET /api/threat_logs` - Retrieve all threat logs

### Sample API Usage

#### Analyze Login
```javascript
const loginData = {
    user_id: "john_doe",
    login_time: "14:30",
    failed_attempts: 3,
    country: "United States",
    ip_address: "192.168.1.1"
};

fetch('/api/analyze_login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(loginData)
})
.then(response => response.json())
.then(result => console.log(result));
```

#### Analyze Email
```javascript
const emailData = {
    user_id: "john_doe",
    email_content: "URGENT: Your account will be suspended. Click here immediately..."
};

fetch('/api/analyze_email', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(emailData)
})
.then(response => response.json())
.then(result => console.log(result));
```

## 🗄️ Database Schema

### MongoDB Collection: `threat_logs`
```javascript
{
    "_id": ObjectId,
    "user": "string",
    "threat_type": "string",
    "risk_score": "number",
    "severity": "string",
    "timestamp": "Date",
    "details": {
        "failed_attempts": "number",
        "country": "string",
        "ip_address": "string",
        "email_length": "number",
        "analysis_type": "string"
    }
}
```

## 🔧 Configuration

### Environment Variables
- `MONGO_URI`: MongoDB Atlas connection string
- `PORT`: Application port (default: 5000)
- `FLASK_ENV`: Environment mode (development/production)

### MongoDB Atlas Setup
1. Create a free MongoDB Atlas account
2. Create a new cluster (M0 free tier)
3. Add your application IP to whitelist (0.0.0.0/0 for Render)
4. Create a database user with read/write permissions
5. Get the connection string and add to environment variables

## 🧪 Testing

### Sample Test Data

#### Login Analysis Test
```json
{
    "user_id": "test_user",
    "login_time": "02:30",
    "failed_attempts": 7,
    "country": "Nigeria",
    "ip_address": "192.168.1.100"
}
```

#### Email Analysis Test
```json
{
    "user_id": "test_user",
    "email_content": "URGENT: Your account has been compromised. Click here immediately to verify your identity and secure your account. This is your final warning before suspension."
}
```

## 📈 Performance Metrics

### System Requirements
- **Minimum RAM**: 512MB (Render free tier)
- **CPU**: 1 core
- **Storage**: 1GB (for logs and models)
- **Network**: Standard internet connection

### Expected Performance
- **Login Analysis**: <500ms response time
- **Email Analysis**: <1s response time
- **Dashboard Load**: <2s initial load
- **Auto-refresh**: Every 30 seconds

## 🔒 Security Considerations

### Data Protection
- All sensitive data stored in encrypted MongoDB Atlas
- No plain text passwords or API keys in code
- Environment variables for configuration
- HTTPS enforced in production

### Rate Limiting
- Implement rate limiting for API endpoints
- Monitor for abuse patterns
- Automatic IP blocking for suspicious activity

## 🐛 Troubleshooting

### Common Issues

#### MongoDB Connection Error
```bash
# Check MONGO_URI format
mongodb+srv://username:password@cluster.mongodb.net/database_name
```

#### Import Errors
```bash
# Reinstall dependencies
pip install -r requirements.txt --upgrade
```

#### Port Issues
```bash
# Check if port is available
netstat -an | grep 5000
```

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📞 Support

For support and questions:
- Create an issue in the GitHub repository
- Check the troubleshooting section
- Review the API documentation

---

**Built with ❤️ for cybersecurity professionals**
