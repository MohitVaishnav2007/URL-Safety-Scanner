import logging
from datetime import datetime, timedelta
from flask import render_template, request, flash, redirect, url_for, jsonify
from app import app, db
from models import URLCheck
from services.validator import URLValidator
from services.virustotal_client import VirusTotalClient
from services.decision_engine import DecisionEngine

# Initialize services
validator = URLValidator()
vt_client = VirusTotalClient(app.config['VIRUSTOTAL_API_KEY'])
decision_engine = DecisionEngine()

@app.route('/')
def index():
    """Render the home page with the URL input form and recent checks."""
    # Get recent URL checks (last 10)
    recent_checks = URLCheck.query.order_by(URLCheck.check_date.desc()).limit(10).all()
    return render_template('index.html', recent_checks=recent_checks)

@app.route('/check', methods=['POST'])
def check_url():
    """Process URL submission and check its reputation."""
    url = request.form.get('url', '').strip()
    normalized_url = url  # Default value in case validation fails
    
    # Validate URL
    if not validator.is_valid(url):
        flash('Please enter a valid website address (like example.com or https://example.com).', 'danger')
        return redirect(url_for('index'))
    
    try:
        # Normalize and sanitize URL
        normalized_url = validator.normalize(url)
        
        # Log URL check request
        logging.info(f"Checking URL reputation: {normalized_url}")
        
        # Check if we have a recent result in database (last 24 hours)
        recent_check = URLCheck.query.filter_by(url=normalized_url) \
                              .filter(URLCheck.check_date > datetime.utcnow() - timedelta(hours=24)) \
                              .order_by(URLCheck.check_date.desc()) \
                              .first()
        
        if recent_check:
            # Use cached result if available
            flash(f"Showing recent results for {normalized_url}", 'info')
            logging.info(f"Using cached result for {normalized_url} from {recent_check.check_date}")
            
            result = {
                'score': recent_check.score,
                'verdict': recent_check.verdict,
                'color': decision_engine._get_color_for_verdict(recent_check.verdict),
                'details': {}
            }
            
            stats = {
                'malicious': recent_check.malicious_count,
                'suspicious': recent_check.suspicious_count,
                'harmless': recent_check.harmless_count,
                'undetected': recent_check.undetected_count
            }
            
            return render_template(
                'result.html', 
                url=normalized_url, 
                result=result,
                stats=stats,
                details={},
                cached=True,
                check_date=recent_check.check_date
            )
        
        # Otherwise, check URL reputation
        if not app.config['VIRUSTOTAL_API_KEY']:
            # Enable demo mode notice
            flash('Running in demo mode. For full functionality, please add a VirusTotal API key.', 'warning')
            # Return demo data instead of error - for educational purposes
            return use_demo_data(normalized_url)
            
        reputation_data = vt_client.check_url(normalized_url)
        
        # Analyze reputation data
        result = decision_engine.analyze(reputation_data)
        
        # Log result
        logging.info(f"URL check result for {normalized_url}: {result['verdict']} (Score: {result['score']})")
        
        # Save to database
        stats = reputation_data.get('stats', {})
        url_check = URLCheck(
            url=normalized_url,
            score=result['score'],
            verdict=result['verdict'],
            malicious_count=stats.get('malicious', 0),
            suspicious_count=stats.get('suspicious', 0),
            harmless_count=stats.get('harmless', 0),
            undetected_count=stats.get('undetected', 0)
        )
        db.session.add(url_check)
        db.session.commit()
        
        # Render results
        return render_template(
            'result.html', 
            url=normalized_url, 
            result=result,
            stats=stats,
            details=reputation_data.get('results', {}),
            cached=False,
            check_date=datetime.utcnow()
        )
    
    except Exception as e:
        error_message = str(e)
        logging.error(f"Error checking URL {url}: {error_message}")
        
        # Handle API key errors with demo mode
        if "VirusTotal API key is required" in error_message or "API key appears to be invalid" in error_message or "401" in error_message or "WrongCredentialsError" in error_message:
            # Log for admin attention
            logging.warning("API key issue detected, using demo mode")
            flash("Using demo mode - for full functionality, a valid VirusTotal API key is needed.", 'warning')
            # Return demo data instead of error
            return use_demo_data(normalized_url)
        # Handle other types of errors
        elif "Timed out" in error_message:
            flash("The security check took too long. Please try again in a moment.", 'warning')
            return redirect(url_for('index'))
        elif "rate limit" in error_message:
            flash("We've reached our daily limit for security checks. Please try again tomorrow.", 'warning')
            return redirect(url_for('index'))
        else:
            # For any other errors, use demo mode instead of showing error
            logging.warning(f"Unexpected error, falling back to demo mode: {error_message}")
            flash("Using demo mode due to a temporary issue with our security service.", 'warning')
            return use_demo_data(normalized_url)

@app.route('/recent', methods=['GET'])
def recent_checks():
    """API endpoint for recent URL checks."""
    checks = URLCheck.query.order_by(URLCheck.check_date.desc()).limit(20).all()
    return jsonify([check.to_dict() for check in checks])

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    return render_template('index.html', error="Sorry, we couldn't find that page."), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors."""
    logging.error(f"Internal server error: {str(e)}")
    
    # Get the current request URL if it's available
    current_url = request.args.get('url', '')
    
    # If this was a URL check, try to use demo mode instead of showing error
    if current_url and '/check' in request.path:
        logging.warning(f"500 error during URL check, falling back to demo mode")
        flash("Using demo mode due to a temporary issue with our security service.", 'warning')
        return use_demo_data(current_url)
    
    return render_template('index.html', error="Something went wrong on our end. Please try again later."), 500

def use_demo_data(url):
    """
    Provide demonstration data for educational purposes when API key is not available.
    
    Args:
        url (str): The URL for which to generate demo data
        
    Returns:
        Response: Rendered template with demo data
    """
    logging.info(f"Using demo data for URL: {url}")
    
    # Determine verdict based on URL content for demonstration
    if any(keyword in url.lower() for keyword in ['malware', 'virus', 'phish', 'hack']):
        verdict = 'DANGEROUS'
        score = 0.85
        stats = {'malicious': 15, 'suspicious': 8, 'harmless': 5, 'undetected': 12}
    elif any(keyword in url.lower() for keyword in ['suspicious', 'unknown', 'crypto', 'free', 'download']):
        verdict = 'SUSPICIOUS'
        score = 0.35
        stats = {'malicious': 5, 'suspicious': 10, 'harmless': 20, 'undetected': 25}
    else:
        verdict = 'SAFE'
        score = 0.05
        stats = {'malicious': 0, 'suspicious': 2, 'harmless': 35, 'undetected': 23}
    
    # Create a demo result
    result = {
        'score': score,
        'verdict': verdict,
        'color': 'danger' if verdict == 'DANGEROUS' else 'warning' if verdict == 'SUSPICIOUS' else 'success',
        'details': {}
    }
    
    # Save to database to maintain history
    url_check = URLCheck(
        url=url,
        score=score,
        verdict=verdict,
        malicious_count=stats.get('malicious', 0),
        suspicious_count=stats.get('suspicious', 0),
        harmless_count=stats.get('harmless', 0),
        undetected_count=stats.get('undetected', 0)
    )
    db.session.add(url_check)
    db.session.commit()
    
    # Render the demo result
    return render_template(
        'result.html',
        url=url,
        result=result,
        stats=stats,
        details={},
        cached=False,
        demo_mode=True,
        check_date=datetime.utcnow()
    )
