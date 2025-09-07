import sys
import traceback
import datetime
import os
from dotenv import load_dotenv
import openai
import logging

from flask import Blueprint, request, jsonify, render_template
from flask_login import login_required, current_user
from sqlalchemy import desc, func

from extensions import db
from models import Recommendation, ThreatDetails
from mock_recommendations import generate_mock_recommendations

# ------------------ Setup ------------------ #
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
if OPENAI_API_KEY:
    openai.api_key = OPENAI_API_KEY
else:
    logging.warning("OPENAI_API_KEY not set. AI features disabled.")

security_recommendations_bp = Blueprint("security_recommendations", __name__)

# ------------------ Utility Functions ------------------ #
def calculate_impact_score(rec):
    """Calculate impact score for a recommendation."""
    score = 0
    category = rec.get("category") if isinstance(rec, dict) else getattr(rec, "category", None)
    if category:
        category_lower = category.lower()
        if category_lower == "network":
            score += 3
        elif category_lower == "system":
            score += 2
        elif category_lower == "user":
            score += 1
    content = rec.get("content") if isinstance(rec, dict) else getattr(rec, "content", "")
    severity = rec.get("severity") if isinstance(rec, dict) else getattr(rec, "severity", "Medium")
    severity_weight = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    score += severity_weight.get(severity, 2)
    score += len(content) // 50
    return min(score, 10)

def enhance_with_ai(rec_dict):
    """Optional GPT-based content enhancement."""
    if not OPENAI_API_KEY:
        return rec_dict.get("content"), False
    try:
        related_events = rec_dict.get("related_events", [])
        related_threats = rec_dict.get("related_threats", [])
        related_predictions = rec_dict.get("related_predictions", [])
        ai_prompt = f"""
        You are a cybersecurity assistant. 
        Recommendation:
        - Title: {rec_dict.get("title")}
        - Content: {rec_dict.get("content")}
        - Category: {rec_dict.get("category")}
        Related Events: {', '.join([f'{e.get("event_type")} ({e.get("severity")})' for e in related_events]) or 'None'}
        Related Threats: {', '.join([f'{t.get("name")} ({t.get("severity")})' for t in related_threats]) or 'None'}
        Predictions: {', '.join([f'{p.get("predicted_level")} ({p.get("confidence_score")})' for p in related_predictions]) or 'None'}
        Generate a concise, actionable recommendation.
        """
        ai_response = openai.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a security AI assistant."},
                {"role": "user", "content": ai_prompt}
            ],
            max_tokens=50,
            temperature=0.3
        )
        return ai_response.choices[0].message.content.strip(), True
    except Exception as e:
        logging.warning(f"AI enhancement failed: {e}")
        return rec_dict.get("content"), False

# ------------------ Page Route ------------------ #
@security_recommendations_bp.route("/recommendations")
@login_required
def recommendations_page():
    return render_template("recommendations.html")

# ------------------ API Routes ------------------ #
@security_recommendations_bp.route("/api/recommendations", methods=["GET"])
@login_required
def list_recommendations():
    try:
        recs = Recommendation.query.filter_by(user_id=current_user.id).order_by(
            desc(Recommendation.created_at)
        ).all()
        if not recs:
            recs = generate_mock_recommendations(count=10)
            return jsonify({"status": "success", "data": recs, "mock": True}), 200
        return jsonify({"status": "success", "data": [r.to_dict() for r in recs]}), 200
    except Exception as e:
        logging.exception("Error in list_recommendations")
        return jsonify({"error": str(e)}), 500

@security_recommendations_bp.route("/api/recommendations", methods=["POST"])
@login_required
def create_recommendation():
    try:
        data = request.get_json()
        rec = Recommendation(
            user_id=current_user.id,
            title=data["title"],
            content=data["content"],
            category=data.get("category"),
            severity=data.get("severity", "Medium")
        )
        db.session.add(rec)
        db.session.commit()
        return jsonify({"status": "success", "data": rec.to_dict()}), 201
    except Exception as e:
        db.session.rollback()
        logging.exception("Error in create_recommendation")
        return jsonify({"error": str(e)}), 500

@security_recommendations_bp.route("/api/recommendations/analyze", methods=["POST"])
@login_required
def analyze_recommendations():
    try:
        data = request.get_json() or {}
        category = data.get("category", "all")
        sort_by = data.get("sort_by", "severity")
        sort_order = data.get("sort_order", "desc")
        page = int(data.get("page", 1))
        per_page = int(data.get("per_page", 10))

        query = Recommendation.query.filter_by(user_id=current_user.id)
        if category != "all":
            query = query.filter_by(category=category)

        total_count = query.count()
        if total_count == 0:
            recommendations = generate_mock_recommendations(count=per_page)
        else:
            pagination = query.paginate(page=page, per_page=per_page, error_out=False)
            recommendations = pagination.items

        analyzed_recommendations = []
        for rec in recommendations:
            rec_dict = rec if isinstance(rec, dict) else rec.to_dict()
            impact_score = calculate_impact_score(rec_dict)
            enhanced_content, ai_generated = enhance_with_ai(rec_dict)

            analyzed_recommendations.append({
                **rec_dict,
                "content": enhanced_content,
                "ai_generated": ai_generated,
                "impact_score": impact_score,
            })

        # Sort by severity
        severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        if sort_by == "severity":
            analyzed_recommendations.sort(
                key=lambda x: severity_order.get(x.get("severity", "Medium"), 2),
                reverse=(sort_order == "desc")
            )

        # Summary
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for r in analyzed_recommendations:
            sev = r.get("severity", "Medium")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        total_items = total_count or len(analyzed_recommendations)
        total_pages = (total_items + per_page - 1) // per_page

        return jsonify({
            "status": "success",
            "data": {
                "recommendations": analyzed_recommendations,
                "summary": {
                    "total": total_items,
                    "severity_counts": severity_counts,
                    "pagination": {
                        "page": page,
                        "per_page": per_page,
                        "total_pages": total_pages,
                        "total_items": total_items,
                    }
                }
            }
        }), 200
    except Exception as e:
        logging.exception("Error in analyze_recommendations")
        return jsonify({"error": str(e)}), 500

@security_recommendations_bp.route("/api/recommendations/severity-distribution", methods=["GET"])
@login_required
def severity_distribution():
    try:
        recs = Recommendation.query.filter_by(user_id=current_user.id).all()
        if not recs:
            recs = generate_mock_recommendations(count=10)

        distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        total_scores = 0
        for r in recs:
            sev = r.get("severity") if isinstance(r, dict) else getattr(r, "severity", "Medium")
            distribution[sev] = distribution.get(sev, 0) + 1
            score = r.get("severity_score") if isinstance(r, dict) else getattr(r, "severity_score", 5)
            total_scores += score

        average_severity_score = total_scores / max(len(recs), 1)
        return jsonify({
            "status": "success",
            "data": {
                "distribution": distribution,
                "average_severity_score": round(average_severity_score, 2)
            }
        }), 200
    except Exception as e:
        logging.exception("Error in severity_distribution")
        return jsonify({"status": "error", "error": str(e)}), 500

@security_recommendations_bp.route("/api/recommendations/timeline", methods=["GET"])
@login_required
def recommendations_timeline():
    try:
        recs = (
            db.session.query(
                func.date(Recommendation.created_at).label("date"),
                func.count(Recommendation.id).label("count"),
            )
            .filter(Recommendation.user_id == current_user.id)
            .group_by(func.date(Recommendation.created_at))
            .order_by(func.date(Recommendation.created_at))
            .all()
        )
        threats = (
            db.session.query(
                func.date(ThreatDetails.detected_at).label("date"),
                func.count(ThreatDetails.id).label("count"),
            )
            .group_by(func.date(ThreatDetails.detected_at))
            .order_by(func.date(ThreatDetails.detected_at))
            .all()
        )

        if not recs:
            mock_recs = generate_mock_recommendations(count=10)
            recs = [{"date": r["created_at"][:10], "count": 1} for r in mock_recs]
        if not threats:
            threats = []

        return jsonify({
            "status": "success",
            "data": {
                "recommendations": [{"date": str(r["date"]), "count": r["count"]} for r in recs],
                "threats": [{"date": str(t.date), "count": t.count} for t in threats],
            },
        }), 200
    except Exception as e:
        logging.exception("Error in recommendations_timeline")
        return jsonify({"error": str(e)}), 500

@security_recommendations_bp.route("/recommendations/voice-alert", methods=["POST"])
@login_required
def generate_voice_alert():
    try:
        if not OPENAI_API_KEY:
            return jsonify({"status": "error", "error": "OpenAI API key not configured"}), 503

        data = request.get_json() or {}
        threat_description = data.get("threat_description", "Unknown threat detected.")
        ai_prompt = f"Generate a short, clear, urgent voice alert for this security threat: {threat_description}. Make it actionable and concise."

        ai_response = openai.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a security AI assistant."},
                {"role": "user", "content": ai_prompt}
            ],
            max_tokens=50,
            temperature=0.3
        )

        alert_text = ai_response.choices[0].message.content.strip()
        return jsonify({"status": "success", "alert_text": alert_text}), 200
    except Exception as e:
        logging.exception("Error in generate_voice_alert")
        return jsonify({"status": "error", "error": str(e)}), 500
