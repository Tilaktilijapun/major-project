from flask import Blueprint, render_template
from flask_login import login_required
from extensions import db

aboutus_bp = Blueprint('aboutus', __name__)

@aboutus_bp.route('/about')
@login_required
def about():
    """
    Render the about us page
    """
    return render_template('aboutus.html')

@aboutus_bp.route('/about/team')
def team():
    """
    Render the team page
    """
    return render_template('aboutus.html', section='team')

@aboutus_bp.route('/about/company')
def company():
    """
    Render the company information page
    """
    return render_template('aboutus.html', section='company')