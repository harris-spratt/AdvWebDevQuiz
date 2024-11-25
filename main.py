from flask import Flask, render_template, request, redirect, url_for, session, g
from quiz_data import quizzes
import sqlite3
import bcrypt
from functools import wraps

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Required for session management
db_location = 'var/sqlite3.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = sqlite3.connect(db_location)
        g._database = db
    return db

@app.teardown_appcontext
def close_db_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


@app.route('/signup', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())  # Hash the password

    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        db.commit()
    except sqlite3.IntegrityError:
        return "Username already exists!", 400

    return redirect(url_for('signin'))

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT id, password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[1]):

            session['user_id'] = user[0]  # Store the user's ID in the session
            session['username'] = username  # Store the username for easy access
            return redirect(url_for('home'))
        else:
            return "Invalid username or password!", 400

    return render_template('signin.html')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('signin'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def base():
    return render_template('base.html', quiz_categories=quizzes.keys())

@app.route('/home')
def home():
    return render_template('Home.html')
@app.route('/signup')
def signup():
    return render_template('signup.html')
@app.route('/signout')
def signout():
    session.clear()  # Clear all session data
    return redirect(url_for('base'))  # Redirect to the base page



@app.route('/quiz/<category>', methods=['GET', 'POST'])
@login_required
def quiz(category):
    if category not in quizzes:
        return "Quiz not found!", 404

    if 'current_question' not in session or session.get('current_category') != category:
        session['current_category'] = category
        session['current_question'] = 0
        session['user_answers'] = [None] * len(quizzes[category])  # Reset answers for the selected quiz

    if request.method == 'POST':
        selected_option = request.form.get('answer')
        if selected_option:
            session['user_answers'][session['current_question']] = selected_option

        if 'next' in request.form and session['current_question'] < len(quizzes[category]) - 1:
            session['current_question'] += 1
        elif 'prev' in request.form and session['current_question'] > 0:
            session['current_question'] -= 1
        elif 'submit' in request.form:
            session.modified = True
            return redirect(url_for('results', category=category))

    current_question = session['current_question']
    question_data = quizzes[category][current_question]

    return render_template(
        'quiz.html',
        question=question_data,
        question_num=current_question + 1,
        total_questions=len(quizzes[category]),
        category=category,
        current_question=current_question
    )


@app.route('/results/<category>')
def results(category):
    if category not in quizzes:
        return "Quiz not found!", 404

    # Get the user_id from session
    user_id = session.get('user_id')

    user_answers = session.get('user_answers', [])
    questions = quizzes[category]

    # Calculate the score
    score = 0
    for i, question in enumerate(questions):
        correct_answer = question['answer']
        user_answer = user_answers[i] if i < len(user_answers) else None

        if user_answer == correct_answer:
            score += 1

    # Now, insert the result only once for the completed quiz
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
            INSERT OR REPLACE INTO quiz_results (user_id, category, score, total_questions)
            VALUES (?, ?, ?, ?)
        """, (user_id, category, score, len(questions)))
    db.commit()

    # Clear session data for the completed quiz
    session.pop('current_category', None)
    session.pop('current_question', None)
    session.pop('user_answers', None)

    return render_template(
        'results.html',
        score=score,
        total=len(questions),
        category=category,
        username=session['username']
    )
@app.route('/leaderboard')
def leaderboard():
    db = get_db()
    cursor = db.cursor()

    # SQL query to get leaderboard data, including the date (timestamp)
    cursor.execute("""
        SELECT users.username, quiz_results.category, quiz_results.score, quiz_results.total_questions, quiz_results.date
        FROM quiz_results
        JOIN users ON quiz_results.user_id = users.id
        ORDER BY quiz_results.score DESC, quiz_results.category
    """)
    leaderboard_data = cursor.fetchall()

    return render_template('leaderboard.html', leaderboard_data=leaderboard_data, title="Leaderboard")







if __name__ == "__main__":
    init_db()
    app.run(host='0.0.0.0', debug=True)