import os
import logging
from flask import Flask, render_template, request, flash, redirect, url_for
from analyzer import SecurityAnalyzer

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")

# Initialize the security analyzer
analyzer = SecurityAnalyzer()

@app.route('/', methods=['GET', 'POST'])
def index():
    """Main page for analyzing security content"""
    result = None
    
    if request.method == 'POST':
        content = request.form.get('content', '').strip()
        
        if not content:
            flash('Please enter content to analyze.', 'warning')
            return redirect(url_for('index'))
        
        try:
            # Analyze the content
            result = analyzer.analyze_content(content)
            logging.debug(f"Analysis result: {result}")
            
        except Exception as e:
            logging.error(f"Analysis error: {str(e)}")
            flash('An error occurred during analysis. Please try again.', 'danger')
            return redirect(url_for('index'))
    
    return render_template('index.html', result=result)

@app.route('/clear')
def clear():
    """Clear the current analysis and start fresh"""
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
