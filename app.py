from flask import Flask, render_template, request, jsonify
from fraud_detector import WebsiteFraudDetector
import json

app = Flask(__name__)
detector = WebsiteFraudDetector()

# Store analysis history (in-memory for demo)
analysis_history = []


@app.route('/')
def index():
    """Display main page"""
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    """API endpoint for URL analysis"""
    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'Please provide a URL'}), 400

    # Analyze the URL
    result = detector.analyze_url(url)

    # Store in history
    analysis_history.append({
        'url': result.get('url', url),
        'risk_level': result.get('risk_level'),
        'risk_score': result.get('risk_score'),
        'timestamp': pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S') if 'pd' in globals() else 'Just now'
    })

    # Keep only last 50 analyses
    if len(analysis_history) > 50:
        analysis_history.pop(0)

    return jsonify(result)


@app.route('/history')
def history():
    """Get analysis history"""
    return jsonify(analysis_history[-10:])  # Return last 10


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)