import random
import uuid
import datetime

# Predefined categories and severity levels
CATEGORIES = ["network", "system", "user", "application", "database"]
SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]
SEVERITY_SCORE_MAP = {
    "Low": (1, 3),
    "Medium": (4, 6),
    "High": (7, 8),
    "Critical": (9, 10)
}

def generate_random_recommendation():
    """
    Generate a single mock recommendation with essential fields,
    including severity score, impact score, and AI flag.
    """
    rec_id = str(uuid.uuid4())
    title = f"Recommendation {random.randint(1000, 9999)}"
    content = f"Take action to address potential issues in the {random.choice(CATEGORIES)} domain."
    category = random.choice(CATEGORIES)
    severity = random.choice(SEVERITY_LEVELS)
    severity_score = random.randint(*SEVERITY_SCORE_MAP[severity])
    impact_score = random.randint(1, 10)
    created_at = (datetime.datetime.utcnow() - datetime.timedelta(days=random.randint(0, 365))).isoformat()
    
    return {
        "id": rec_id,
        "title": title,
        "content": content,
        "category": category,
        "severity": severity,
        "severity_score": severity_score,
        "impact_score": impact_score,
        "created_at": created_at,
        "ai_generated": random.choice([True, False]),
        "related_events": [],
        "related_threats": [],
        "related_predictions": []
    }

def generate_mock_recommendations(count=100):
    """
    Generate a list of mock recommendations.
    """
    return [generate_random_recommendation() for _ in range(count)]

# Example usage
if __name__ == "__main__":
    mock_data = generate_mock_recommendations(10)
    for rec in mock_data:
        print(rec)
