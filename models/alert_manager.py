import os
import smtplib
import json
import requests
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional
import threading
import queue

class AlertManager:
    """Multi-channel alert management system for real-time threat notifications"""
    
    def __init__(self):
        self.alert_queue = queue.Queue()
        self.alert_history = []
        self.config = self._load_config()
        self.is_running = False
        self.alert_thread = None
        
    def _load_config(self) -> Dict:
        """Load alert configuration from environment or defaults"""
        return {
            'email': {
                'enabled': os.environ.get('ALERT_EMAIL_ENABLED', 'false').lower() == 'true',
                'smtp_server': os.environ.get('ALERT_SMTP_SERVER', 'smtp.gmail.com'),
                'smtp_port': int(os.environ.get('ALERT_SMTP_PORT', 587)),
                'username': os.environ.get('ALERT_EMAIL_USERNAME', ''),
                'password': os.environ.get('ALERT_EMAIL_PASSWORD', ''),
                'recipients': os.environ.get('ALERT_EMAIL_RECIPIENTS', '').split(',') if os.environ.get('ALERT_EMAIL_RECIPIENTS') else []
            },
            'telegram': {
                'enabled': os.environ.get('ALERT_TELEGRAM_ENABLED', 'false').lower() == 'true',
                'bot_token': os.environ.get('ALERT_TELEGRAM_BOT_TOKEN', ''),
                'chat_ids': os.environ.get('ALERT_TELEGRAM_CHAT_IDS', '').split(',') if os.environ.get('ALERT_TELEGRAM_CHAT_IDS') else []
            },
            'desktop': {
                'enabled': True,  # Always enabled for dashboard
                'high_risk_only': os.environ.get('ALERT_DESKTOP_HIGH_RISK_ONLY', 'true').lower() == 'true'
            },
            'sound': {
                'enabled': os.environ.get('ALERT_SOUND_ENABLED', 'true').lower() == 'true',
                'high_risk_only': os.environ.get('ALERT_SOUND_HIGH_RISK_ONLY', 'true').lower() == 'true'
            },
            'thresholds': {
                'high_risk': 70,
                'medium_risk': 40
            }
        }
    
    def start(self):
        """Start the alert processing thread"""
        if not self.is_running:
            self.is_running = True
            self.alert_thread = threading.Thread(target=self._process_alerts)
            self.alert_thread.daemon = True
            self.alert_thread.start()
            print("🚨 Alert Manager started")
    
    def stop(self):
        """Stop the alert processing thread"""
        self.is_running = False
        if self.alert_thread:
            self.alert_thread.join(timeout=2)
        print("🚨 Alert Manager stopped")
    
    def _process_alerts(self):
        """Process alerts from the queue"""
        while self.is_running:
            try:
                alert = self.alert_queue.get(timeout=1)
                self._send_alert(alert)
                self.alert_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Alert processing error: {e}")
    
    def trigger_alert(self, threat_data: Dict):
        """Trigger an alert based on threat data"""
        
        risk_score = threat_data.get('risk_score', 0)
        severity = threat_data.get('severity', 'Low')
        
        # Check if alert should be sent based on thresholds
        if risk_score < self.config['thresholds']['medium_risk']:
            return  # Skip low-risk alerts
        
        alert = {
            'timestamp': datetime.now().isoformat(),
            'title': f"🚨 Security Alert: {threat_data.get('threat_type', 'Unknown')}",
            'message': self._format_alert_message(threat_data),
            'risk_score': risk_score,
            'severity': severity,
            'threat_data': threat_data,
            'channels': self._determine_channels(severity, risk_score)
        }
        
        # Add to queue
        self.alert_queue.put(alert)
        
        # Add to history
        self.alert_history.append(alert)
        if len(self.alert_history) > 100:  # Keep last 100 alerts
            self.alert_history = self.alert_history[-100:]
        
        print(f"🚨 Alert triggered: {alert['title']} (Risk: {risk_score})")
    
    def _format_alert_message(self, threat_data: Dict) -> str:
        """Format alert message for different channels"""
        
        threat_type = threat_data.get('threat_type', 'Unknown')
        risk_score = threat_data.get('risk_score', 0)
        severity = threat_data.get('severity', 'Low')
        user = threat_data.get('user', 'Unknown')
        
        message = f"""
🔔 CYBERSECURITY ALERT

Threat Type: {threat_type}
Risk Score: {risk_score}/100
Severity: {severity}
User: {user}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

"""
        
        # Add details based on threat type
        details = threat_data.get('details', {})
        if 'filename' in details:
            message += f"File: {details['filename']}\n"
        if 'failed_attempts' in details:
            message += f"Failed Attempts: {details['failed_attempts']}\n"
        if 'country' in details:
            message += f"Country: {details['country']}\n"
        if 'email_length' in details:
            message += f"Email Length: {details['email_length']} chars\n"
        
        message += "\nPlease investigate immediately."
        
        return message
    
    def _determine_channels(self, severity: str, risk_score: int) -> List[str]:
        """Determine which channels to use based on severity"""
        channels = ['desktop']  # Desktop always enabled
        
        if self.config['sound']['enabled']:
            if not self.config['sound']['high_risk_only'] or risk_score >= self.config['thresholds']['high_risk']:
                channels.append('sound')
        
        if self.config['email']['enabled'] and risk_score >= self.config['thresholds']['medium_risk']:
            channels.append('email')
        
        if self.config['telegram']['enabled'] and risk_score >= self.config['thresholds']['medium_risk']:
            channels.append('telegram')
        
        return channels
    
    def _send_alert(self, alert: Dict):
        """Send alert through specified channels"""
        channels = alert.get('channels', [])
        
        for channel in channels:
            try:
                if channel == 'email':
                    self._send_email_alert(alert)
                elif channel == 'telegram':
                    self._send_telegram_alert(alert)
                elif channel == 'desktop':
                    self._send_desktop_notification(alert)
                elif channel == 'sound':
                    self._trigger_sound_alert(alert)
            except Exception as e:
                print(f"Failed to send {channel} alert: {e}")
    
    def _send_email_alert(self, alert: Dict):
        """Send email alert"""
        if not self.config['email']['enabled'] or not self.config['email']['recipients']:
            return
        
        try:
            msg = MIMEMultipart()
            msg['From'] = self.config['email']['username']
            msg['To'] = ', '.join(self.config['email']['recipients'])
            msg['Subject'] = alert['title']
            
            body = alert['message']
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(self.config['email']['smtp_server'], self.config['email']['smtp_port'])
            server.starttls()
            server.login(self.config['email']['username'], self.config['email']['password'])
            
            server.send_message(msg)
            server.quit()
            
            print(f"📧 Email alert sent to {len(self.config['email']['recipients'])} recipients")
            
        except Exception as e:
            print(f"Email alert failed: {e}")
    
    def _send_telegram_alert(self, alert: Dict):
        """Send Telegram alert"""
        if not self.config['telegram']['enabled'] or not self.config['telegram']['bot_token']:
            return
        
        try:
            bot_token = self.config['telegram']['bot_token']
            chat_ids = self.config['telegram']['chat_ids']
            
            message = f"*{alert['title']}*\n\n{alert['message']}"
            
            for chat_id in chat_ids:
                if chat_id.strip():
                    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
                    payload = {
                        'chat_id': chat_id.strip(),
                        'text': message,
                        'parse_mode': 'Markdown'
                    }
                    
                    response = requests.post(url, json=payload, timeout=10)
                    if response.status_code == 200:
                        print(f"📱 Telegram alert sent to chat {chat_id}")
                    else:
                        print(f"Telegram alert failed: {response.text}")
                        
        except Exception as e:
            print(f"Telegram alert failed: {e}")
    
    def _send_desktop_notification(self, alert: Dict):
        """Store desktop notification for frontend pickup"""
        # This will be retrieved by the frontend via API
        pass  # Alerts are stored in alert_history
    
    def _trigger_sound_alert(self, alert: Dict):
        """Mark sound alert for frontend"""
        # Frontend will check for sound_alerts flag
        pass  # Sound is handled by frontend
    
    def get_recent_alerts(self, limit: int = 10) -> List[Dict]:
        """Get recent alerts for dashboard display"""
        return sorted(self.alert_history, key=lambda x: x['timestamp'], reverse=True)[:limit]
    
    def update_config(self, new_config: Dict):
        """Update alert configuration"""
        self.config.update(new_config)
        print("🚨 Alert configuration updated")
    
    def test_alert(self, channel: str = 'all') -> Dict:
        """Send a test alert to verify configuration"""
        test_threat = {
            'threat_type': 'Test Alert',
            'risk_score': 85,
            'severity': 'High',
            'user': 'test_user',
            'details': {'test': True}
        }
        
        results = {}
        
        if channel in ['all', 'email'] and self.config['email']['enabled']:
            try:
                alert = {
                    'title': '🔔 Test Email Alert',
                    'message': 'This is a test email alert from Cybersecurity Dashboard.\n\nIf you received this, your email alerts are configured correctly!',
                    'risk_score': 85,
                    'severity': 'High'
                }
                self._send_email_alert(alert)
                results['email'] = 'success'
            except Exception as e:
                results['email'] = f'failed: {str(e)}'
        
        if channel in ['all', 'telegram'] and self.config['telegram']['enabled']:
            try:
                alert = {
                    'title': '🔔 Test Telegram Alert',
                    'message': 'This is a test Telegram alert from Cybersecurity Dashboard.\n\nIf you received this, your Telegram alerts are configured correctly!',
                    'risk_score': 85,
                    'severity': 'High'
                }
                self._send_telegram_alert(alert)
                results['telegram'] = 'success'
            except Exception as e:
                results['telegram'] = f'failed: {str(e)}'
        
        return results

# Global alert manager instance
alert_manager = AlertManager()
