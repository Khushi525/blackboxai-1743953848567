from flask import Flask, render_template, request, jsonify, redirect, url_for
from model import predict_url
from database import save_url, get_history
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/check-url', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        # Get prediction from ML model
        result, threat_level = predict_url(url)
        
        # Save to database
        save_url(url, result, threat_level)
        
        return jsonify({
            'result': result,
            'threat_level': threat_level
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/results')
def results():
    result = request.args.get('result', 'safe')
    threat_level = request.args.get('threat_level', 'low')
    return render_template('results.html', result=result, threat_level=threat_level)

@app.route('/history')
def history():
    history_data = get_history()
    return render_template('history.html', history=history_data)

@app.route('/api/history')
def api_history():
    history_data = get_history()
    return jsonify(history_data)

if __name__ == '__main__':
    # Create data directory if it doesn't exist
    os.makedirs('data', exist_ok=True)
    app.run(debug=True, port=8000)
