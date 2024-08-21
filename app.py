from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # 请替换成更安全的密钥
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cybercafe.db'
db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime)
    fee_per_minute = db.Column(db.Float, default=0.1)  # 每分钟费用，默认0.1元

    def __repr__(self):
        return '<User %r>' % self.username

    def calculate_fee(self):
        """计算费用"""
        if self.last_login:
            time_diff = datetime.now() - self.last_login
            minutes = time_diff.total_seconds() / 60
            return round(minutes * self.fee_per_minute, 2)
        else:
            return 0.00


# 创建默认管理员账户
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin_user = User(username='admin', password=generate_password_hash('admin'), is_admin=True)
        db.session.add(admin_user)
        db.session.commit()


@app.route('/api/login', methods=['POST'])
def login():
    username = request.form['username']
    user = User.query.filter_by(username=username).first()
    if user and user.last_login is not None:
        # 记录上机时间
        user.last_login = datetime.now()
        db.session.commit()
        return '上机成功'
    else:
        return '用户不存在或未登录'


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['logged_in'] = True
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            # 使用更具体的错误提示信息
            error_message = "用户名或密码错误。"
            return render_template('index.html', error=error_message)
    return render_template('index.html')


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('user_id', None)
    session.pop('is_admin', None)
    return redirect(url_for('index'))


@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('logged_in') or not session.get('is_admin'):
        return redirect(url_for('index'))
    users = User.query.all()  # 获取所有用户
    return render_template('admin_dashboard.html', users=users)


@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    return render_template('dashboard.html')


# 管理员修改密码
@app.route('/admin_change_password', methods=['GET', 'POST'])
def admin_change_password():
    if not session.get('logged_in') or not session.get('is_admin'):
        return redirect(url_for('index'))
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        user = User.query.get(session['user_id'])
        if user and check_password_hash(user.password, old_password):
            user.password = generate_password_hash(new_password)
            db.session.commit()
            return 'Password changed successfully!'
        else:
            return 'Invalid old password'
    return render_template('admin_change_password.html')


# 管理员编辑其他用户
@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if not session.get('logged_in') or not session.get('is_admin'):
        return redirect(url_for('index'))
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form['username']
        if request.form['password']:
            user.password = generate_password_hash(request.form['password'])
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_user.html', user=user)


@app.route('/add_user')
def add_user_form():
    return render_template('add_user.html')


@app.route('/add_user', methods=['POST'])
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # 验证用户名和密码
        # ...

        # 创建新用户
        new_user = User(username=username, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()

        # 重定向到管理员控制面板
        return redirect(url_for('admin_dashboard'))


if __name__ == '__main__':
    app.run(debug=True)
