# Configuration constants for the application

# Threat score thresholds
THREAT_THRESHOLDS = {
    'SAFE': 0,
    'SUSPICIOUS': 2,
    'DANGEROUS': 4
}

# VirusTotal API configuration
VIRUSTOTAL_API = {
    'URL': 'https://www.virustotal.com/api/v3/urls',
    'ANALYSIS_URL': 'https://www.virustotal.com/api/v3/analyses/'
}

# Decision engine configuration
DECISION_ENGINE = {
    'DEFAULT_WEIGHT': 1,
    'WEIGHTS': {
        'malicious': 1.5,
        'suspicious': 0.75,
        'undetected': 0,
        'harmless': -0.5
    }
}

# Logging configuration
LOGGING = {
    'LOG_LEVEL': 'DEBUG',
    'LOG_FORMAT': '%(asctime)s [%(levelname)s] - %(message)s',
    'DATE_FORMAT': '%Y-%m-%d %H:%M:%S'
}
