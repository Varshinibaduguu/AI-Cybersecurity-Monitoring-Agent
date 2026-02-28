#!/usr/bin/env python3
"""
Sample Data Generator for Cybersecurity Monitoring Agent
Generates realistic test data for login attempts and email analysis
"""

import random
import json
from datetime import datetime, timedelta
import pymongo
import os

# Sample data for testing
SAMPLE_USERS = [
    "john_doe", "jane_smith", "bob_wilson", "alice_brown", "charlie_davis",
    "emma_jones", "frank_miller", "grace_taylor", "henry_anderson", "isabel_thomas"
]

COUNTRIES = [
    "United States", "United Kingdom", "Canada", "Germany", "France",
    "Australia", "Japan", "India", "Brazil", "Mexico",
    "Nigeria", "Russia", "China", "South Korea", "Italy"
]

SUSPICIOUS_COUNTRIES = ["Nigeria", "Russia", "China"]

PHISHING_EMAILS = [
    """URGENT: Your account will be suspended in 24 hours. Click here immediately to verify your identity and restore access. This is your final warning before permanent account closure.""",
    
    """Congratulations! You've won $1,000,000 in our international lottery! To claim your prize, please click here and provide your banking details within 48 hours.""",
    
    """Security Alert: We detected unusual activity on your account. Someone tried to login from a different country. Please confirm your identity immediately or your account will be locked.""",
    
    """Limited Time Offer: Get 90% discount on all products! This exclusive deal expires tonight. Click here to shop now and save thousands!""",
    
    """Government Notice: You are eligible for a tax refund of $2,450. Click here to claim your refund before the deadline. Immediate action required.""",
    
    """Your package has been delayed due to customs issues. Please pay the required fees online to receive your delivery. Click here for secure payment.""",
    
    """Bank Security Alert: Your debit card has been compromised. Please update your card details immediately to prevent unauthorized transactions.""",
    
    """Microsoft Support: We detected malware on your computer. Call our toll-free number now for immediate assistance before data loss occurs.""",
    
    """Social Media Update: Your account will be deleted due to policy violations. Click here to appeal this decision and save your profile.""",
    
    """Investment Opportunity: Guaranteed 300% returns in 7 days! Limited spots available. Invest now and become a millionaire!"""
]

LEGITIMATE_EMAILS = [
    """Thank you for your recent purchase. Your order #12345 has been confirmed and will be shipped within 2 business days. You can track your package using the link below.""",
    
    """Your monthly statement is now available for download. Please review your transactions and contact us if you have any questions about your account activity.""",
    
    """Meeting reminder: Tomorrow at 2 PM in Conference Room B. Please bring the quarterly reports and be prepared to discuss the budget allocation.""",
    
    """Welcome to our newsletter! This month we're excited to share our latest product updates and customer success stories. Click here to read more.""",
    
    """Your subscription has been successfully renewed. The next billing cycle will begin on the 15th of next month. Thank you for your continued support.""",
    
    """Thank you for contacting customer support. Your ticket #98765 has been created and our team will respond within 24 hours.""",
    
    """Your appointment has been confirmed for next Tuesday at 10:00 AM with Dr. Smith. Please arrive 15 minutes early for paperwork.""",
    
    """Project update: Phase 1 has been completed successfully. The team will begin Phase 2 on Monday. Please review the attached timeline.""",
    
    """Quarterly report is now available for review. Key metrics show a 15% increase in productivity and a 8% reduction in operational costs.""",
    
    """System maintenance scheduled for this weekend. Services may be temporarily unavailable between 2 AM and 6 AM on Sunday. Thank you for your patience."""
]

def generate_login_data(num_entries=100):
    """Generate sample login data"""
    login_data = []
    
    for i in range(num_entries):
        user_id = random.choice(SAMPLE_USERS)
        
        # Generate realistic login patterns
        if random.random() < 0.8:  # 80% normal logins
            failed_attempts = random.randint(0, 2)
            login_hour = random.randint(8, 18)  # Business hours
            country = random.choice(COUNTRIES[:10])  # Normal countries
        else:  # 20% suspicious logins
            failed_attempts = random.randint(3, 10)
            login_hour = random.choice([2, 3, 4, 5, 23, 0, 1])  # Unusual hours
            country = random.choice(SUSPICIOUS_COUNTRIES)
        
        login_time = f"{login_hour:02d}:{random.randint(0,59):02d}"
        ip_address = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
        
        login_data.append({
            "user_id": user_id,
            "login_time": login_time,
            "failed_attempts": failed_attempts,
            "country": country,
            "ip_address": ip_address
        })
    
    return login_data

def generate_email_data(num_entries=50):
    """Generate sample email data"""
    email_data = []
    
    for i in range(num_entries):
        user_id = random.choice(SAMPLE_USERS)
        
        # 40% phishing, 60% legitimate
        if random.random() < 0.4:
            email_content = random.choice(PHISHING_EMAILS)
        else:
            email_content = random.choice(LEGITIMATE_EMAILS)
        
        email_data.append({
            "user_id": user_id,
            "email_content": email_content
        })
    
    return email_data

def save_sample_data():
    """Save sample data to JSON files"""
    login_data = generate_login_data(100)
    email_data = generate_email_data(50)
    
    with open('sample_login_data.json', 'w') as f:
        json.dump(login_data, f, indent=2)
    
    with open('sample_email_data.json', 'w') as f:
        json.dump(email_data, f, indent=2)
    
    print("Sample data saved to:")
    print("- sample_login_data.json (100 entries)")
    print("- sample_email_data.json (50 entries)")

def populate_database():
    """Populate MongoDB with sample data"""
    try:
        mongo_uri = os.environ.get("MONGO_URI", "mongodb://localhost:27017/cybersecurity")
        client = pymongo.MongoClient(mongo_uri)
        db = client.get_database()
        threat_logs = db.threat_logs
        
        # Clear existing data
        threat_logs.delete_many({})
        
        # Generate and insert sample threat logs
        login_data = generate_login_data(100)
        email_data = generate_email_data(50)
        
        # Insert login threats
        for login in login_data:
            # Simulate threat analysis results
            risk_score = 0
            threat_type = "Normal Activity"
            severity = "Low"
            
            if login['failed_attempts'] > 5:
                risk_score += 40
                threat_type = "Brute Force Attack"
                severity = "High"
            elif login['failed_attempts'] > 2:
                risk_score += 20
                threat_type = "Suspicious Login"
                severity = "Medium"
            
            if login['country'] in SUSPICIOUS_COUNTRIES:
                risk_score += 30
                if threat_type == "Normal Activity":
                    threat_type = "Suspicious Login"
                    severity = "Medium"
            
            # Add time-based risk
            hour = int(login['login_time'].split(':')[0])
            if hour >= 22 or hour <= 6:
                risk_score += 20
                if severity == "Low":
                    severity = "Medium"
            
            risk_score = min(risk_score, 100)
            
            # Update severity based on final risk score
            if risk_score <= 30:
                severity = "Low"
            elif risk_score <= 70:
                severity = "Medium"
            else:
                severity = "High"
            
            threat_logs.insert_one({
                'user': login['user_id'],
                'threat_type': threat_type,
                'risk_score': risk_score,
                'severity': severity,
                'timestamp': datetime.now() - timedelta(
                    hours=random.randint(0, 72),
                    minutes=random.randint(0, 59)
                ),
                'details': {
                    'failed_attempts': login['failed_attempts'],
                    'country': login['country'],
                    'ip_address': login['ip_address'],
                    'analysis_type': 'login'
                }
            })
        
        # Insert email threats
        for email in email_data:
            # Simulate email threat analysis
            is_phishing = email['email_content'] in PHISHING_EMAILS
            risk_score = 50 if is_phishing else random.randint(5, 25)
            
            threat_type = "Phishing Attack" if is_phishing else "Safe"
            severity = "High" if is_phishing else "Low"
            
            threat_logs.insert_one({
                'user': email['user_id'],
                'threat_type': threat_type,
                'risk_score': risk_score,
                'severity': severity,
                'timestamp': datetime.now() - timedelta(
                    hours=random.randint(0, 72),
                    minutes=random.randint(0, 59)
                ),
                'details': {
                    'email_length': len(email['email_content']),
                    'analysis_type': 'email'
                }
            })
        
        print(f"Database populated with {len(login_data) + len(email_data)} threat logs")
        
    except Exception as e:
        print(f"Error populating database: {e}")

if __name__ == "__main__":
    print("🔧 Cybersecurity Monitoring Agent - Sample Data Generator")
    print("=" * 60)
    
    # Save sample data to files
    save_sample_data()
    
    # Try to populate database
    try:
        populate_database()
    except Exception as e:
        print(f"Database population failed: {e}")
        print("Make sure MongoDB is running and MONGO_URI is set correctly")
    
    print("\n✅ Sample data generation complete!")
    print("You can now start the application and view the dashboard.")
