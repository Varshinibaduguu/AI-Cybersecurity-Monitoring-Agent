import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from datetime import datetime
import pytz

class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.user_profiles = {}  # Store user behavior patterns
        self.country_encoder = LabelEncoder()
        self.is_trained = False
        
    def extract_features(self, login_data):
        """Extract numerical features from login data"""
        features = []
        
        # Feature 1: Failed attempts (already numerical)
        failed_attempts = login_data.get('failed_attempts', 0)
        features.append(failed_attempts)
        
        # Feature 2: Login time (convert to hour and check if unusual)
        login_time = login_data.get('login_time', '')
        if login_time:
            try:
                # Parse time and get hour (0-23)
                if ':' in login_time:
                    hour = int(login_time.split(':')[0])
                else:
                    hour = datetime.now().hour
                
                # Unusual hours are 22:00-06:00
                unusual_hour = 1 if hour >= 22 or hour <= 6 else 0
                features.append(unusual_hour)
            except:
                features.append(0)
        else:
            features.append(0)
        
        # Feature 3: Country anomaly (check if different from usual)
        user_id = login_data.get('user_id', '')
        country = login_data.get('country', '')
        
        if user_id in self.user_profiles and country:
            usual_countries = self.user_profiles[user_id].get('countries', [])
            country_anomaly = 0 if country in usual_countries else 1
        else:
            country_anomaly = 0
        
        features.append(country_anomaly)
        
        # Feature 4: IP address risk (simplified - check for private vs public)
        ip_address = login_data.get('ip_address', '')
        ip_risk = 0
        if ip_address:
            # Simple check for private IP ranges
            if ip_address.startswith(('192.168.', '10.', '172.')):
                ip_risk = 0  # Private IP - lower risk
            else:
                ip_risk = 1  # Public IP - slightly higher risk
        
        features.append(ip_risk)
        
        return np.array(features).reshape(1, -1)
    
    def update_user_profile(self, login_data):
        """Update user behavior profile"""
        user_id = login_data.get('user_id', '')
        country = login_data.get('country', '')
        
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = {
                'countries': [],
                'login_count': 0,
                'failed_attempts_history': []
            }
        
        profile = self.user_profiles[user_id]
        
        # Update country list
        if country and country not in profile['countries']:
            profile['countries'].append(country)
        
        # Update login count
        profile['login_count'] += 1
        
        # Update failed attempts history
        failed_attempts = login_data.get('failed_attempts', 0)
        profile['failed_attempts_history'].append(failed_attempts)
        
        # Keep only last 10 entries
        if len(profile['failed_attempts_history']) > 10:
            profile['failed_attempts_history'] = profile['failed_attempts_history'][-10:]
    
    def calculate_risk_score(self, login_data, is_anomaly):
        """Calculate dynamic risk score based on multiple factors"""
        risk_score = 0
        
        # Base risk from failed attempts
        failed_attempts = login_data.get('failed_attempts', 0)
        if failed_attempts > 5:
            risk_score += 40
        elif failed_attempts > 2:
            risk_score += 20
        
        # Risk from unusual login time
        login_time = login_data.get('login_time', '')
        if login_time:
            try:
                if ':' in login_time:
                    hour = int(login_time.split(':')[0])
                else:
                    hour = datetime.now().hour
                
                if hour >= 22 or hour <= 6:
                    risk_score += 20
            except:
                pass
        
        # Risk from country anomaly
        user_id = login_data.get('user_id', '')
        country = login_data.get('country', '')
        
        if user_id in self.user_profiles and country:
            usual_countries = self.user_profiles[user_id].get('countries', [])
            if country not in usual_countries:
                risk_score += 30
        
        # Risk from anomaly detection
        if is_anomaly:
            risk_score += 25
        
        # Cap at 100
        risk_score = min(risk_score, 100)
        
        return risk_score
    
    def determine_severity(self, risk_score):
        """Determine severity based on risk score"""
        if risk_score <= 30:
            return "Low"
        elif risk_score <= 70:
            return "Medium"
        else:
            return "High"
    
    def classify_threat_type(self, login_data, risk_score):
        """Classify the type of threat"""
        failed_attempts = login_data.get('failed_attempts', 0)
        
        if failed_attempts > 5:
            return "Brute Force Attack"
        elif risk_score > 50:
            return "Suspicious Login"
        else:
            return "Normal Activity"
    
    def detect_anomaly(self, login_data):
        """Main method to detect login anomalies"""
        # Update user profile first
        self.update_user_profile(login_data)
        
        # Extract features
        features = self.extract_features(login_data)
        
        # Train model if not already trained (using current data as baseline)
        if not self.is_trained and len(self.user_profiles) > 5:
            # Create training data from existing profiles
            training_data = []
            for uid, profile in self.user_profiles.items():
                for i in range(min(profile['login_count'], 5)):  # Take up to 5 samples per user
                    sample = [
                        np.mean(profile['failed_attempts_history']) if profile['failed_attempts_history'] else 0,
                        0,  # Normal hour
                        0,  # Normal country
                        0   # Normal IP
                    ]
                    training_data.append(sample)
            
            if training_data:
                training_data = np.array(training_data)
                self.model.fit(training_data)
                self.is_trained = True
        
        # Detect anomaly
        if self.is_trained:
            is_anomaly = self.model.predict(features)[0] == -1
        else:
            # Simple rule-based detection if model not trained
            failed_attempts = login_data.get('failed_attempts', 0)
            is_anomaly = failed_attempts > 3
        
        # Calculate risk score
        risk_score = self.calculate_risk_score(login_data, is_anomaly)
        
        # Determine severity and threat type
        severity = self.determine_severity(risk_score)
        threat_type = self.classify_threat_type(login_data, risk_score)
        
        return {
            'threat_type': threat_type,
            'risk_score': risk_score,
            'severity': severity,
            'is_anomaly': is_anomaly,
            'confidence': 0.85 if self.is_trained else 0.70
        }
