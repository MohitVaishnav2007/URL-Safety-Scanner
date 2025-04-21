from datetime import datetime
from app import db

class URLCheck(db.Model):
    """Model for storing URL check history."""
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(2048), nullable=False, index=True)
    score = db.Column(db.Float, nullable=False)
    verdict = db.Column(db.String(20), nullable=False)
    malicious_count = db.Column(db.Integer, default=0)
    suspicious_count = db.Column(db.Integer, default=0)
    harmless_count = db.Column(db.Integer, default=0)
    undetected_count = db.Column(db.Integer, default=0)
    check_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<URLCheck {self.url} - {self.verdict}>'
    
    def to_dict(self):
        """Convert instance to dictionary."""
        return {
            'id': self.id,
            'url': self.url,
            'score': self.score,
            'verdict': self.verdict,
            'stats': {
                'malicious': self.malicious_count,
                'suspicious': self.suspicious_count,
                'harmless': self.harmless_count,
                'undetected': self.undetected_count
            },
            'check_date': self.check_date.strftime('%Y-%m-%d %H:%M:%S')
        }