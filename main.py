import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import base64
from datetime import datetime


load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# --------------------
# Модели
# --------------------
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # Увеличено поле для хранения хеша пароля, чтобы вместить scrypt-хеш
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Category(db.Model):
    __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    products = db.relationship('Product', backref='category', lazy=True)


class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    stock = db.Column(db.Integer, default=0)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), nullable=False)


class ProductFile(db.Model):
    __tablename__ = 'product_files'
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    data_base64 = db.Column(db.Text, nullable=False)
    upload_date = db.Column(db.DateTime, server_default=db.func.current_timestamp(), nullable=False)



# Создаем таблицы, если они еще не созданы
with app.app_context():
    db.create_all()


# --------------------
# Контекстный процессор
# --------------------
@app.context_processor
def inject_user():
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
    return dict(user=user)


# --------------------
# Маршруты авторизации и основных страниц
# --------------------
@app.route('/')
def index():
    # При обращении к корню перенаправляем на главную страницу магазина.
    return redirect(url_for('shop_home'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip()
        password = request.form.get('password').strip()

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Пользователь с таким именем или email уже существует', 'error')
            return redirect(url_for('register'))

        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            is_admin=False
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            if user.is_admin:
                flash('Вы вошли как администратор', 'success')
                return redirect(url_for('admin_panel'))
            else:
                flash('Вы успешно вошли в систему', 'success')
                return redirect(url_for('shop_home'))
        else:
            flash('Неверное имя пользователя или пароль.', 'error')
            return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему для доступа к профилю.', 'error')
        return redirect(url_for('login'))
    # Заглушка для страницы профиля
    return render_template('profile.html')





@app.route('/shop')
def shop_home():
    # Если вы используете контекстный процессор, переменная user доступна в шаблоне.
    return render_template('shop.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('login'))


# --------------------
# Маршруты админ-панели
# --------------------
def admin_required():
    # Простая проверка прав администратора.
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему.', 'error')
        return False
    user = User.query.get(session['user_id'])
    if not (user and user.is_admin):
        flash('У вас нет прав доступа.', 'error')
        return False
    return True


@app.route('/admin')
def admin_panel():
    if not admin_required():
        return redirect(url_for('login'))
    return render_template('admin.html')


@app.route('/admin/products')
def manage_products():
    if not admin_required():
        return redirect(url_for('login'))
    # Здесь вы можете добавить логику для получения списка товаров из базы
    products = Product.query.all()
    return render_template('admin_products.html', products=products)


@app.route('/admin/products/add', methods=['GET', 'POST'])
def add_product():
    if not admin_required():
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form.get('name').strip()
        description = request.form.get('description').strip()
        price = request.form.get('price')
        stock = request.form.get('stock')
        category_id = request.form.get('category_id')

        new_product = Product(
            name=name,
            description=description,
            price=price,
            stock=stock,
            category_id=category_id
        )
        db.session.add(new_product)
        db.session.commit()


        uploaded_files = request.files.getlist('files')
        for file in uploaded_files:
            if file and file.filename:
                file_data = file.read()
                encoded_data = base64.b64encode(file_data).decode('utf-8')
                product_file = ProductFile(
                    product_id=new_product.id,
                    file_name=file.filename,
                    file_type=file.content_type,
                    data_base64=encoded_data
                )
                db.session.add(product_file)
        db.session.commit()

        flash('Товар успешно добавлен', 'success')
        return redirect(url_for('manage_products'))

    categories = Category.query.all()
    return render_template('admin_add_product.html', categories=categories)


@app.route('/admin/products/edit/<int:product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if not admin_required():
        return redirect(url_for('login'))
    product = Product.query.get_or_404(product_id)
    # Получаем все прикреплённые файлы для данного продукта
    product_files = ProductFile.query.filter_by(product_id=product.id).all()

    if request.method == 'POST':
        product.name = request.form.get('name').strip()
        product.description = request.form.get('description').strip()
        product.price = request.form.get('price')
        product.stock = request.form.get('stock')
        product.category_id = request.form.get('category_id')
        db.session.commit()

        # Если админ загрузил новый файл, удалим существующие (опционально)
        uploaded_files = request.files.getlist('files')
        if uploaded_files and any(f.filename for f in uploaded_files):
            # Удаляем старые файлы (при желании можно реализовать логику замены для конкретного файла)
            for pf in product_files:
                db.session.delete(pf)
            db.session.commit()
            # Сохраняем новый файл
            for file in uploaded_files:
                if file and file.filename:
                    file_data = file.read()
                    encoded_data = base64.b64encode(file_data).decode('utf-8')
                    new_pf = ProductFile(
                        product_id=product.id,
                        file_name=file.filename,
                        file_type=file.content_type,
                        data_base64=encoded_data
                    )
                    db.session.add(new_pf)
            db.session.commit()

        flash('Товар обновлён', 'success')
        return redirect(url_for('manage_products'))
    categories = Category.query.all()
    return render_template('admin_edit_product.html', product=product, categories=categories,
                           product_files=product_files)


@app.route('/admin/products/delete/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    if not admin_required():
        return redirect(url_for('login'))
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    flash('Товар удалён', 'info')
    return redirect(url_for('manage_products'))


@app.route('/admin/categories')
def manage_categories():
    if not admin_required():
        return redirect(url_for('login'))
    categories = Category.query.all()
    return render_template('admin_categories.html', categories=categories)


@app.route('/admin/categories/add', methods=['GET', 'POST'])
def add_category():
    if not admin_required():
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form.get('name').strip()
        description = request.form.get('description').strip()
        new_category = Category(name=name, description=description)
        db.session.add(new_category)
        db.session.commit()
        flash('Категория успешно добавлена', 'success')
        return redirect(url_for('manage_categories'))
    return render_template('admin_add_category.html')


@app.route('/admin/categories/edit/<int:category_id>', methods=['GET', 'POST'])
def edit_category(category_id):
    if not admin_required():
        return redirect(url_for('login'))
    category = Category.query.get_or_404(category_id)
    if request.method == 'POST':
        category.name = request.form.get('name').strip()
        category.description = request.form.get('description').strip()
        db.session.commit()
        flash('Категория обновлена', 'success')
        return redirect(url_for('manage_categories'))
    return render_template('admin_edit_category.html', category=category)


@app.route('/admin/categories/delete/<int:category_id>', methods=['POST'])
def delete_category(category_id):
    if not admin_required():
        return redirect(url_for('login'))
    category = Category.query.get_or_404(category_id)
    db.session.delete(category)
    db.session.commit()
    flash('Категория удалена', 'info')
    return redirect(url_for('manage_categories'))


@app.route('/admin/orders')
def manage_orders():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему.', 'error')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not (user and user.is_admin):
        flash('У вас нет прав доступа.', 'error')
        return redirect(url_for('shop_home'))
    return "Страница управления заказами (заглушка)"



@app.route('/admin/products/view/<int:product_id>')
def view_product(product_id):
    if not admin_required():
        return redirect(url_for('login'))
    product = Product.query.get_or_404(product_id)
    # Получаем все файлы, связанные с товаром, чтобы отобразить изображение
    product_files = ProductFile.query.filter_by(product_id=product.id).all()
    return render_template('admin_product_detail.html', product=product, product_files=product_files)





@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему.', 'error')
        return redirect(url_for('login'))
    if request.method == 'POST':
        # Получаем данные формы
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        user = User.query.get(session['user_id'])
        if not user.check_password(old_password):
            flash('Старый пароль не верный.', 'error')
            return redirect(url_for('change_password'))
        if new_password != confirm_password:
            flash('Новый пароль не совпадает.', 'error')
            return redirect(url_for('change_password'))
        # Обновляем пароль (не забудьте хешировать новый пароль)
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        flash('Пароль успешно изменён.', 'success')
        return redirect(url_for('profile'))
    return render_template('change_password.html')


@app.route('/profile/edit', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему для доступа к профилю.', 'error')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'GET':
        return render_template('edit_profile.html', user=user)

    # Если запрос POST, то обновляем данные из формы
    full_name = request.form.get('full_name', '').strip()
    phone = request.form.get('phone', '').strip()
    delivery_address = request.form.get('delivery_address', '').strip()
    birth_date_str = request.form.get('birth_date', '').strip()

    user.full_name = full_name
    user.phone = phone
    user.delivery_address = delivery_address
    if birth_date_str:
        try:
            user.birth_date = datetime.strptime(birth_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Некорректный формат даты рождения. Используйте формат ГГГГ-ММ-ДД.', 'error')
            return redirect(url_for('edit_profile'))
    else:
        user.birth_date = None

    db.session.commit()
    flash('Данные профиля обновлены.', 'success')
    return redirect(url_for('profile'))


if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)
