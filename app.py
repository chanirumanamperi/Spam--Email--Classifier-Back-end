from flask import Flask, request, jsonify, session, redirect, url_for, render_template
import mysql.connector
import bcrypt
import logging
from sklearn.feature_extraction.text import CountVectorizer
from flask_cors import CORS
import pickle

# Initialize Flask app
app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
CORS(app, supports_credentials=True, methods=["GET", "POST", "DELETE"])

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# MySQL Configuration
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="Chaniru.12",
    database="emails"
)
cursor = db.cursor()

# Create table if it doesn't exist
cursor.execute("""
    CREATE TABLE IF NOT EXISTS predictions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        text TEXT,
        prediction VARCHAR(255),
        user_id INT
    )
""")

# Load Naive Bayes model
pipe = pickle.load(open("Naive_model.pkl", "rb"))

@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({"message": "Registration successful"})

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    firstName = data.get('firstName')
    lastName = data.get('lastName')
    email = data.get('email')
    password = data.get('password')
    userType = data.get('userType', 'USER')

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    query = "INSERT INTO users (first_name, last_name, email, password, user_type) VALUES (%s, %s, %s, %s, %s)"
    cursor.execute(query, (firstName, lastName, email, hashed_password, userType))
    db.commit()

    logging.info("User registered: {}".format(email))

    return jsonify({"message": "Registration successful"})

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    try:
        cursor.execute("SELECT id, first_name, last_name, password, user_type FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            session['user_id'] = user[0]
            logging.info("User logged in: {}".format(email))
            return jsonify({
                "message": "Login successful",
                "id": user[0],
                "firstName": user[1],
                "lastName": user[2],
                "userType": user[4]
            })
        else:
            logging.error("Failed login attempt: {}".format(email))
            return jsonify({"error": "Invalid email or password"}), 401
    except Exception as e:
        logging.error("Error during login: {}".format(str(e)))
        return jsonify({"error": "An unexpected error occurred"}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    logging.info("User logged out")
    return jsonify({"message": "Logout successful"})

@app.route('/api/detect-spam', methods=["POST"])
def detect_spam():
    if request.method == "POST":
        data = request.get_json()
        email_content = data.get('email', '')

        # Predict if the email is spam
        output = pipe.predict([email_content])[0]

        # Convert numpy.int64 to int
        output = int(output)

        # Map numerical prediction to string labels
        prediction_label = "Spam" if output == 1 else "Not Spam"

        # Save prediction to the database
        user_id = session.get('user_id')
        cursor.execute("INSERT INTO predictions (text, prediction, user_id) VALUES (%s, %s, %s)", (email_content, prediction_label, user_id))
        db.commit()

        return jsonify({"prediction": prediction_label})
    
    
@app.route('/api/view-post', methods=['GET'])
def get_predictions():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized access"}), 401
    
    user_id = session['user_id']
    try:
        cursor.execute("SELECT id, text, prediction FROM predictions WHERE user_id = %s", (user_id,))
        predictions = cursor.fetchall()
        prediction_list = []
        for prediction in predictions:
            prediction_dict = {
                "id": prediction[0],
                "text": prediction[1],
                "prediction": prediction[2],  # Already in "spam" or "not spam"
                "user_id": user_id
            }
            prediction_list.append(prediction_dict)
        
        return jsonify({"predictions": prediction_list})
    except Exception as e:
        logging.error("Error fetching predictions: {}".format(str(e)))
        return jsonify({"error": "An unexpected error occurred while fetching predictions"}), 500


@app.route('/api/delete-prediction/<int:prediction_id>', methods=['DELETE'])
def delete_prediction(prediction_id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized access"}), 401
    
    user_id = session['user_id']
    try:
        # Check if the prediction belongs to the user
        cursor.execute("SELECT id FROM predictions WHERE id = %s AND user_id = %s", (prediction_id, user_id))
        prediction = cursor.fetchone()
        if prediction:
            # Delete the prediction
            cursor.execute("DELETE FROM predictions WHERE id = %s", (prediction_id,))
            db.commit()
            logging.info("Prediction deleted for user {}: {}".format(user_id, prediction_id))
            return jsonify({"message": "Prediction deleted successfully"})
        else:
            return jsonify({"error": "Prediction not found or unauthorized access to delete"}), 404
    except Exception as e:
        logging.error("Error deleting prediction: {}".format(str(e)))
        return jsonify({"error": "An unexpected error occurred while deleting prediction"}), 500



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
