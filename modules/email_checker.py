import os
import re
import requests
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def validate_email(email):
    """Validate email format using regex."""
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_regex, email))

def check_email_reputation(email):
    """
    Check email reputation using emailrep.io API.
    Returns a dictionary with reputation details or error message.
    """
    try:
        # Validate email format
        if not validate_email(email):
            logger.error(f"Invalid email format: {email}")
            return {"error": "Invalid email format"}

        # Get API key
        api_key = os.getenv('EMAILREP_API_KEY')
        if not api_key:
            logger.error("EmailRep API key not configured")
            return {"error": "API key not configured"}

        # API request
        headers = {
            'Key': api_key,
            'User-Agent': 'CyberAnalyzer/1.0',
            'Accept': 'application/json'
        }
        url = f"https://emailrep.io/{email}"
        response = requests.get(url, headers=headers, timeout=10)

        # Check response status
        if response.status_code != 200:
            logger.error(f"EmailRep API request failed: {response.status_code} - {response.text}")
            return {"error": f"API request failed: {response.status_code}"}

        data = response.json()

        # Process response
        result = {
            "email": data.get('email', email),
            "reputation": data.get('reputation', 'N/A'),
            "suspicious": data.get('suspicious', False),
            "blacklisted": data.get('details', {}).get('blacklisted', False),
            "malicious_activity": data.get('details', {}).get('malicious_activity', False),
            "data_breach": data.get('details', {}).get('data_breach', False),
            "domain": data.get('details', {}).get('domain', {}).get('name', 'N/A'),
            "disposable": data.get('details', {}).get('disposable', False),
            "free_provider": data.get('details', {}).get('free', False),
            "last_seen": data.get('details', {}).get('last_seen', 'N/A'),
            "profiles": data.get('details', {}).get('profiles', []),
            "timestamp": datetime.now().isoformat(),
            "status_code": response.status_code,
            "error": None
        }

        logger.info(f"Email reputation checked for {email}: reputation={result['reputation']}")
        return result

    except requests.exceptions.RequestException as e:
        logger.error(f"Network error during EmailRep API request: {str(e)}")
        return {"error": f"Network error: {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error in check_email_reputation: {str(e)}")
        return {"error": f"Unexpected error: {str(e)}"}