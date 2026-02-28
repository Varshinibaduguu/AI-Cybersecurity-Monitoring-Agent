import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import re
from urllib.parse import urlparse
import pickle
import os

class PhishingDetector:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
        self.model = LogisticRegression(random_state=42)
        self.is_trained = False
        self.model_path = 'models/phishing_model.pkl'
        
        # Load pre-trained model if exists
        if os.path.exists(self.model_path):
            self.load_model()
        else:
            # Initialize with some basic training data
            self.initialize_model()
    
    def initialize_model(self):
        """Initialize model with basic phishing detection patterns"""
        # Basic training data for phishing detection
        phishing_samples = [
            "URGENT: Your account will be suspended. Click here immediately",
            "Congratulations! You've won $1000000. Claim your prize now",
            "Verify your account details or it will be closed permanently",
            "Click here to update your payment information",
            "Your package is delayed. Pay customs fee to receive",
            "Security alert: Unusual activity detected. Confirm identity",
            "Limited time offer: Get 90% discount on all products",
            "Your password has been compromised. Reset immediately",
            "Government notice: Tax refund available. Click to claim",
            "Bank alert: Suspicious login attempt. Verify account"
        ]
        
        legitimate_samples = [
            "Thank you for your recent purchase. Order confirmation attached",
            "Your monthly statement is now available for download",
            "Meeting reminder: Tomorrow at 2 PM in conference room",
            "Please review the attached document before our meeting",
            "Your subscription has been renewed successfully",
            "Welcome to our newsletter. Latest updates inside",
            "Thank you for contacting customer support",
            "Your appointment has been confirmed for next week",
            "Project update: Phase 1 completed successfully",
            "Quarterly report is now available for review"
        ]
        
        # Create training data
        X_train = phishing_samples + legitimate_samples
        y_train = [1] * len(phishing_samples) + [0] * len(legitimate_samples)
        
        # Train vectorizer and model
        X_train_vec = self.vectorizer.fit_transform(X_train)
        self.model.fit(X_train_vec, y_train)
        self.is_trained = True
        
        # Save model
        self.save_model()
    
    def extract_text_features(self, email_content):
        """Extract additional features from email content"""
        features = {}
        
        # Count suspicious keywords
        suspicious_keywords = [
            'urgent', 'immediate', 'suspended', 'verify', 'confirm',
            'click here', 'account', 'password', 'security', 'alert',
            'congratulations', 'winner', 'prize', 'claim', 'limited',
            'offer', 'discount', 'free', 'risk', 'threat', 'compromised'
        ]
        
        keyword_count = 0
        for keyword in suspicious_keywords:
            keyword_count += email_content.lower().count(keyword)
        
        features['suspicious_keywords'] = keyword_count
        
        # Count URLs
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, email_content)
        features['url_count'] = len(urls)
        
        # Check for suspicious URL patterns
        suspicious_url_count = 0
        for url in urls:
            if any(suspicious in url.lower() for suspicious in ['bit.ly', 'tinyurl', 'short.link']):
                suspicious_url_count += 1
        
        features['suspicious_urls'] = suspicious_url_count
        
        # Count email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, email_content)
        features['email_count'] = len(emails)
        
        # Check for urgency indicators
        urgency_words = ['urgent', 'immediately', 'asap', 'right now', 'quickly']
        urgency_count = sum(1 for word in urgency_words if word in email_content.lower())
        features['urgency_score'] = urgency_count
        
        # Check for capitalization abuse
        words = email_content.split()
        all_caps_words = sum(1 for word in words if word.isupper() and len(word) > 3)
        features['all_caps_ratio'] = all_caps_words / len(words) if words else 0
        
        return features
    
    def calculate_risk_score(self, email_content, is_phishing, text_features):
        """Calculate dynamic risk score for email"""
        risk_score = 0
        
        # Base risk from ML prediction
        if is_phishing:
            risk_score += 50
        
        # Risk from suspicious keywords
        risk_score += min(text_features['suspicious_keywords'] * 5, 30)
        
        # Risk from URLs
        if text_features['url_count'] > 3:
            risk_score += 15
        risk_score += text_features['suspicious_urls'] * 10
        
        # Risk from urgency
        risk_score += text_features['urgency_score'] * 8
        
        # Risk from capitalization abuse
        if text_features['all_caps_ratio'] > 0.3:
            risk_score += 10
        
        # Risk from multiple email addresses (potential spam)
        if text_features['email_count'] > 5:
            risk_score += 10
        
        return min(risk_score, 100)
    
    def determine_severity(self, risk_score):
        """Determine severity based on risk score"""
        if risk_score <= 30:
            return "Low"
        elif risk_score <= 70:
            return "Medium"
        else:
            return "High"
    
    def detect_phishing(self, email_content):
        """Main method to detect phishing emails"""
        if not email_content or len(email_content.strip()) < 10:
            return {
                'threat_type': 'Safe',
                'risk_score': 0,
                'severity': 'Low',
                'is_phishing': False,
                'confidence': 0.95
            }
        
        # Extract text features
        text_features = self.extract_text_features(email_content)
        
        # Vectorize email content
        email_vec = self.vectorizer.transform([email_content])
        
        # Predict using ML model
        if self.is_trained:
            prediction = self.model.predict(email_vec)[0]
            probability = self.model.predict_proba(email_vec)[0]
            is_phishing = bool(prediction)
            confidence = max(probability)
        else:
            # Fallback to rule-based detection
            is_phishing = text_features['suspicious_keywords'] > 3 or text_features['urgency_score'] > 1
            confidence = 0.70
        
        # Calculate risk score
        risk_score = self.calculate_risk_score(email_content, is_phishing, text_features)
        
        # Determine severity and threat type
        severity = self.determine_severity(risk_score)
        threat_type = "Phishing Attack" if is_phishing else "Safe"
        
        return {
            'threat_type': threat_type,
            'risk_score': risk_score,
            'severity': severity,
            'is_phishing': is_phishing,
            'confidence': confidence,
            'features': text_features
        }
    
    def save_model(self):
        """Save the trained model"""
        try:
            model_data = {
                'vectorizer': self.vectorizer,
                'model': self.model,
                'is_trained': self.is_trained
            }
            with open(self.model_path, 'wb') as f:
                pickle.dump(model_data, f)
        except Exception as e:
            print(f"Error saving model: {e}")
    
    def load_model(self):
        """Load the trained model"""
        try:
            with open(self.model_path, 'rb') as f:
                model_data = pickle.load(f)
                self.vectorizer = model_data['vectorizer']
                self.model = model_data['model']
                self.is_trained = model_data['is_trained']
        except Exception as e:
            print(f"Error loading model: {e}")
            self.initialize_model()
