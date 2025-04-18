import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import base64


load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


@app.context_processor
def inject_globals():
    user = None
    cart_count = 0
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        cart_count = db.session.query(
            func.coalesce(func.sum(CartItem.quantity), 0)
        ).filter(CartItem.user_id == user.id).scalar()
    return {
        'user': user,
        'cart_count': cart_count,
        'current_year': datetime.utcnow().year
    }



# --------------------
# Модели
# --------------------
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    full_name = db.Column(db.String(150))
    phone = db.Column(db.String(20))
    birth_date = db.Column(db.Date)
    city = db.Column(db.String(100))
    street = db.Column(db.String(255))
    house = db.Column(db.String(50))
    apartment = db.Column(db.String(50))
    private_house = db.Column(db.Boolean, default=False, nullable=False)

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

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))  # Сообщения принадлежат пользователю
    subject = db.Column(db.String(150))
    message = db.Column(db.Text, nullable=False)
    sent_at = db.Column(db.DateTime, server_default=db.func.current_timestamp(), nullable=False)
    answered = db.Column(db.Boolean, default=False, nullable=False)


#Корзина
class CartItem(db.Model):
    __tablename__ = 'cart_items'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1, nullable=False)

    user = db.relationship('User', backref=db.backref('cart_items', lazy='dynamic'))
    product = db.relationship('Product')



class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    order_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default='pending')  # Статус заказа: pending, completed, canceled
    phone = db.Column(db.String(20))
    city = db.Column(db.String(100))
    street = db.Column(db.String(255))
    house = db.Column(db.String(50))
    apartment = db.Column(db.String(50))
    private_house = db.Column(db.Boolean, default=False, nullable=False)

    user = db.relationship('User', backref=db.backref('orders', lazy='dynamic'))

class OrderItem(db.Model):
    __tablename__ = 'order_items'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('orders.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    product = db.relationship('Product')




# Создаем таблицы, если они еще не созданы
with app.app_context():
    db.create_all()




# --------------------
# Маршруты авторизации и основных страниц
# --------------------
@app.route('/shop')
def shop_home():
    # Получаем 6 первых товаров для отображения
    products = Product.query.order_by(Product.id.desc()).limit(6).all()
    # Берём все категории (если понадобятся где‑то на главной)
    categories = Category.query.order_by(Category.name).all()
    # Для каждого товара достаём первое изображение
    images = {
        p.id: ProductFile.query.filter_by(product_id=p.id).first()
        for p in products
    }
    return render_template(
        'shop.html',
        products=products,
        categories=categories,
        images=images
    )



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


# @app.route('/admin/orders')
# def manage_orders():
#     if 'user_id' not in session:
#         flash('Пожалуйста, войдите в систему.', 'error')
#         return redirect(url_for('login'))
#
#     user = User.query.get(session['user_id'])
#     if not (user and user.is_admin):
#         flash('У вас нет прав доступа.', 'error')
#         return redirect(url_for('shop_home'))
#
#     # Получаем заказы с полными данными о пользователе
#     orders = db.session.query(
#         Order.id, Order.order_date, Order.status,
#         User.username, User.full_name, User.phone,
#         User.city, User.street, User.house, User.apartment, User.private_house
#     ).join(User, User.id == Order.user_id).all()
#
#     return render_template('admin_orders.html', orders=orders)
@app.route('/admin/orders')
def manage_orders():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему.', 'error')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not (user and user.is_admin):
        flash('У вас нет прав доступа.', 'error')
        return redirect(url_for('shop_home'))

    # Получаем заказы с полными данными о пользователе
    orders_data = db.session.query(
        Order.id, Order.order_date, Order.status,
        User.username, User.full_name, User.phone,
        User.city, User.street, User.house, User.apartment, User.private_house
    ).join(User, User.id == Order.user_id).all()

    # Для каждого заказа получаем товары и их цену
    order_items_data = {}
    for order in orders_data:
        order_items = db.session.query(
            OrderItem, Product.name, Product.price, OrderItem.quantity
        ).join(Product, Product.id == OrderItem.product_id).filter(OrderItem.order_id == order[0]).all()

        # Подсчитаем общую цену для этого заказа
        total_price = sum(item[2] * item[3] for item in order_items)
        order_items_data[order[0]] = {
            'items': order_items,
            'total_price': total_price
        }

    return render_template('admin_orders.html', orders=orders_data, order_items_data=order_items_data)


@app.route('/admin/orders/cancel/<int:order_id>', methods=['POST'])
def cancel_order(order_id):
    order = Order.query.get_or_404(order_id)

    order.status = 'canceled'
    db.session.commit()
    flash('Заказ отменен', 'info')
    return redirect(url_for('manage_orders'))


@app.route('/admin/orders/complete/<int:order_id>', methods=['POST'])
def complete_order(order_id):
    # Получаем заказ и связанные с ним данные о пользователе
    order = db.session.query(
        Order.id, Order.order_date, Order.status,
        User.username, User.full_name, User.phone,
        User.city, User.street, User.house, User.apartment, User.private_house
    ).join(User, User.id == Order.user_id).filter(Order.id == order_id).first()

    if not order:
        flash('Заказ не найден.', 'error')
        return redirect(url_for('manage_orders'))

    # Проверяем, если заказ в статусе "Ожидает"
    if order.status == 'pending':
        # Обновляем статус заказа
        db.session.query(Order).filter(Order.id == order_id).update({'status': 'completed'})
        db.session.commit()
        flash('Заказ завершён', 'success')
    else:
        flash('Невозможно завершить заказ, так как его статус уже изменен.', 'error')

    return redirect(url_for('manage_orders'))





@app.route('/admin/products/view/<int:product_id>')
def view_product(product_id):
    if not admin_required():
        return redirect(url_for('login'))
    product = Product.query.get_or_404(product_id)
    # Получаем все файлы, связанные с товаром, чтобы отобразить изображение
    product_files = ProductFile.query.filter_by(product_id=product.id).all()
    return render_template('admin_product_detail.html', product=product, product_files=product_files)




#
# @app.route('/change-password', methods=['GET', 'POST'])
# def change_password():
#     if 'user_id' not in session:
#         flash('Пожалуйста, войдите в систему.', 'error')
#         return redirect(url_for('login'))
#     if request.method == 'POST':
#         # Получаем данные формы
#         old_password = request.form.get('old_password')
#         new_password = request.form.get('new_password')
#         confirm_password = request.form.get('confirm_password')
#         user = User.query.get(session['user_id'])
#         if not user.check_password(old_password):
#             flash('Старый пароль не верный.', 'error')
#             return redirect(url_for('change_password'))
#         if new_password != confirm_password:
#             flash('Новый пароль не совпадает.', 'error')
#             return redirect(url_for('change_password'))
#         # Обновляем пароль (не забудьте хешировать новый пароль)
#         user.password_hash = generate_password_hash(new_password)
#         db.session.commit()
#         flash('Пароль успешно изменён.', 'success')
#         return redirect(url_for('profile'))
#     return render_template('change_password.html')
#

@app.route('/profile/edit', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему для доступа к профилю.', 'error')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'GET':
        return render_template('edit_profile.html', user=user)

    # Обновление личных данных
    user.full_name = request.form.get('full_name', '').strip()
    user.phone = request.form.get('phone', '').strip()
    birth_date_str = request.form.get('birth_date', '').strip()
    if birth_date_str:
        try:
            user.birth_date = datetime.strptime(birth_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('Некорректный формат даты рождения. Используйте формат ГГГГ-ММ-ДД.', 'error')
            return redirect(url_for('edit_profile'))
    else:
        user.birth_date = None

    # Обновление адреса доставки из отдельных полей
    user.city = request.form.get('city', '').strip()
    user.street = request.form.get('street', '').strip()
    user.house = request.form.get('house', '').strip()
    user.apartment = request.form.get('apartment', '').strip()  # может быть пустым, если private_house установлено
    user.private_house = True if request.form.get('private_house') == '1' else False

    db.session.commit()
    flash('Данные профиля обновлены.', 'success')
    return redirect(url_for('profile'))

@app.route('/contacts', methods=['GET', 'POST'])
def contacts():
    if request.method == 'POST':
        # Получаем данные формы
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        message_text = request.form.get('message', '').strip()

        # Формируем тему сообщения, вы можете изменить логику по необходимости
        subject = f"Сообщение от {name} ({email})"

        # Если пользователь авторизован, можно установить user_id, иначе оставить как None
        user_id = session.get('user_id')  # Будет None, если пользователь не залогинен

        new_message = Message(user_id=user_id, subject=subject, message=message_text)
        db.session.add(new_message)
        db.session.commit()

        flash('Ваше сообщение отправлено. Мы свяжемся с вами в ближайшее время!', 'success')
        return redirect(url_for('contacts'))
    return render_template('contacts.html')

@app.route('/messages')
def user_messages():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему для доступа к сообщениям.', 'error')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    # Предполагаем, что сообщения пользователя хранятся в таблице messages с user_id равным идентификатору пользователя
    user_msgs = Message.query.filter_by(user_id=user.id).order_by(Message.sent_at.desc()).all()
    return render_template('messages.html', messages=user_msgs)


@app.route('/admin/messages')
def admin_messages():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему.', 'error')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not (user and user.is_admin):
        flash('У вас нет прав доступа.', 'error')
        return redirect(url_for('shop_home'))

    messages_list = Message.query.order_by(Message.sent_at.desc()).all()
    return render_template('admin_messages.html', messages=messages_list)


@app.route('/admin/messages/mark_answered/<int:message_id>', methods=['POST'])
def mark_answered(message_id):
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему.', 'error')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not (user and user.is_admin):
        flash('У вас нет прав доступа.', 'error')
        return redirect(url_for('shop_home'))

    msg = Message.query.get_or_404(message_id)
    msg.answered = True
    db.session.commit()
    flash('Сообщение отмечено как отвеченное.', 'success')
    return redirect(url_for('admin_messages'))



@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    # Если пользователь не залогинен
    if 'user_id' not in session:
        flash('Пожалуйста, войдите в систему.', 'error')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        old = request.form['old_password']
        new = request.form['new_password']
        confirm = request.form['confirm_password']

        if not user.check_password(old):
            flash('Старый пароль неверен.', 'error')
            return redirect(url_for('change_password'))

        if new != confirm:
            flash('Пароли не совпадают.', 'error')
            return redirect(url_for('change_password'))

        user.password_hash = generate_password_hash(new)
        db.session.commit()

        flash('Пароль успешно изменён.', 'success')
        return redirect(url_for('profile'))

    return render_template('change_password.html')


@app.route('/catalog')
def catalog():
    # Получаем категории и товары
    categories = Category.query.order_by(Category.name).all()
    products = Product.query.order_by(Product.name).all()
    # Для каждого товара берём первое изображение (если есть)
    images = {}
    for p in products:
        img = ProductFile.query.filter_by(product_id=p.id).first()
        images[p.id] = img
    return render_template('catalog.html', categories=categories, products=products, images=images)


@app.route('/cart')
def view_cart():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите, чтобы посмотреть корзину.', 'error')
        return redirect(url_for('login'))
    items = CartItem.query.filter_by(user_id=session['user_id']).all()
    images = {
        item.product_id: ProductFile.query.filter_by(product_id=item.product_id).first()
        for item in items
    }
    total = sum(item.quantity * float(item.product.price) for item in items)

    return render_template('cart.html',
                           items=items,
                           images=images,
                           total=total)



@app.route('/cart/add/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user_id = session['user_id']
    item = CartItem.query.filter_by(user_id=user_id, product_id=product_id).first()
    if item:
        item.quantity += 1
    else:
        item = CartItem(user_id=user_id, product_id=product_id, quantity=1)
        db.session.add(item)
    db.session.commit()
    flash('Товар добавлен в корзину.', 'success')
    return redirect(request.referrer or url_for('catalog'))

@app.route('/cart/update/<int:item_id>', methods=['POST'])
def update_cart(item_id):
    qty = int(request.form.get('quantity', 1))
    item = CartItem.query.get_or_404(item_id)
    if qty < 1:
        db.session.delete(item)
    else:
        item.quantity = qty
    db.session.commit()
    return redirect(url_for('view_cart'))

@app.route('/cart/remove/<int:item_id>', methods=['POST'])
def remove_from_cart(item_id):
    item = CartItem.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    flash('Товар удалён из корзины.', 'info')
    return redirect(url_for('view_cart'))



@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if 'user_id' not in session:
        flash('Пожалуйста, войдите, чтобы оформить заказ.', 'error')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    items = CartItem.query.filter_by(user_id=user.id).all()
    total = sum(item.quantity * float(item.product.price) for item in items)

    # Проверяем, заполнены ли телефон и адрес
    missing_info = not (user.phone and user.city and user.street and user.house)

    # Собираем словарь изображений для каждого товара
    images = {}
    for item in items:
        img = ProductFile.query.filter_by(product_id=item.product_id).first()
        images[item.product_id] = img

    if request.method == 'POST':
        if missing_info:
            flash('Пожалуйста, заполните в профиле телефон и полный адрес доставки.', 'error')
            return redirect(url_for('checkout'))
        if not items:
            flash('Ваша корзина пуста.', 'error')
            return redirect(url_for('checkout'))

        order = Order(user_id=user.id)
        db.session.add(order)
        db.session.flush()
        for item in items:
            db.session.add(OrderItem(
                order_id=order.id,
                product_id=item.product_id,
                quantity=item.quantity
            ))
        CartItem.query.filter_by(user_id=user.id).delete()
        db.session.commit()
        flash('Заказ успешно оформлен!', 'success')
        return redirect(url_for('shop_home'))

    return render_template('checkout.html',
                           user=user,
                           items=items,
                           total=total,
                           missing_info=missing_info,
                           images=images)


@app.route('/search_products', methods=['GET'])
def search_products():
    query = request.args.get('query', '').strip()  # Получаем строку поиска из параметра запроса
    if query:
        # Ищем товары по имени или описанию
        products = db.session.query(Product).filter(
            Product.name.ilike(f'%{query}%') | Product.description.ilike(f'%{query}%')
        ).all()
    else:
        products = []

    return render_template('search_results.html', products=products)



if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)
