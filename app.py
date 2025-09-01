from flask import Flask, render_template, jsonify
import os
from datetime import datetime, timedelta
import json
from ssh_analyzer import SSHLogAnalyzer

app = Flask(__name__)

# Initialize the SSH analyzer
analyzer = SSHLogAnalyzer()

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    """Get SSH attack statistics"""
    try:
        stats = analyzer.get_attack_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/attacks-timeline')
def get_attacks_timeline():
    """Get timeline of SSH attacks"""
    try:
        timeline = analyzer.get_attacks_timeline()
        return jsonify(timeline)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/top-attackers')
def get_top_attackers():
    """Get top attacking IP addresses with geolocation"""
    try:
        attackers = analyzer.get_top_attackers()
        return jsonify(attackers)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/attack-methods')
def get_attack_methods():
    """Get breakdown of attack methods"""
    try:
        methods = analyzer.get_attack_methods()
        return jsonify(methods)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-report')
def generate_report():
    """Generate comprehensive security report"""
    try:
        report = analyzer.generate_security_report()
        return jsonify(report)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting SSH Security Monitor...")
    print("📊 Dashboard will be available at: http://127.0.0.1:5000")
    print("🔍 Analyzing SSH logs for security threats...")
    app.run(debug=True, host='0.0.0.0', port=5000)