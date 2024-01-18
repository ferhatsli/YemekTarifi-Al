from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import openai
import re
from werkzeug.urls import url_parse

app = Flask(__name__)
openai.api_key = "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"

# Uygulama yapılandırmaları
app.config['SECRET_KEY'] = 'ferhat3363'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)

# Kullanıcı modeli
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Tarif formatlama işlevi
def format_recipe(recipe_text):
    lines = recipe_text.split('\n')
    steps = []

    for line in lines:
        match = re.match(r'^(\d+)\.\s*(.*)', line)
        if match:
            steps.append(match.group(2).strip())
    return steps

@app.before_first_request
def create_database():
    db.create_all()

@app.route('/')
def home():
    # Kullanıcı zaten giriş yapmışsa, doğrudan dashboard'a yönlendir
    if current_user.is_authenticated:
        return render_template('home.html')
    # Kullanıcı giriş yapmamışsa, kayıt olma/giriş yapma sayfasına yönlendir
    return render_template('home.html') # Varsayılan olarak giriş sayfasına yönlendir

@app.route('/index')
def index():
    # Gerçek ana sayfa içeriği
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        hashed_password = generate_password_hash(password, method='sha256')

        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    next_page = request.args.get('next')

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)

            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('dashboard')
            return redirect(next_page)
        else:
            flash('Kullanıcı adı veya şifre hatalı', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/get-recipe', methods=['POST'])
def get_recipe():
    # Kullanıcı tarafından seçilen malzemeleri al
    selected_ingredients = request.form.getlist('ingredients')
    
    # Seçilen malzemeleri bir string'e çevir
    ingredients_string = ", ".join(selected_ingredients)

    # OpenAI ile iletişim kur
    prompt = f"Bu malzemeleri kullanarak ne tür bir yemek yapabilirim ve adım adım tarifi nedir? Malzemeler: {ingredients_string}. Lütfen tarifin sonunda yemeğin adını 'Yemek Adı:' etiketiyle belirtin."
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo-1106",
        messages=[{"role": "user", "content": prompt}]
    )
    recipe_text = response.choices[0].message['content'].strip()

    # Regex kullanarak yemeğin adını çıkarmak.
    match = re.search(r'Yemek Adı: (.+)', recipe_text)
    if match:
        recipe_title = match.group(1)  # Yemeğin adını al
    else:
        recipe_title = "Bilinmeyen Tarif"  # Eğer ad bulunamazsa varsayılan bir ad kullan

    recipe_steps = format_recipe(recipe_text)
    return render_template('recipe.html', recipe_title=recipe_title, recipe_steps=recipe_steps)



if __name__ == '__main__':
    app.run(debug=True)
