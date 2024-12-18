from flask import Flask, request
import os

app = Flask(__name__)

# Example of hard-coded secret
SECRET_KEY = "mysecretkey"  # Potential hard-coded secret

@app.route('/')
def home():
    return "Welcome to the example app!"

@app.route('/submit', methods=['POST'])
def submit():
    input_data = request.form['data']
    # Vulnerable to SQL injection if not properly parameterized
    query = f"SELECT * FROM users WHERE name = '{input_data}'"
    return "Data submitted!"

if __name__ == '__main__':
    app.run(debug=True)
