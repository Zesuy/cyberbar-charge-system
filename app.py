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
    is_logged = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime, default=datetime.now().date())
    billing_group_id = db.Column(db.Integer, db.ForeignKey('billing_group.id'), nullable=False)  # 关联 BillingGroup 模型

    def __repr__(self):
        return '<User %r>' % self.username

    def calculate_fee(self):
        """计算费用"""
        if self.last_login:
            time_diff = datetime.now() - self.last_login
            minutes = time_diff.total_seconds() / 60
            return round(minutes * self.billing_group_price, 2)
        else:
            return 0.00


class BillingRecord(db.Model):
    __tablename__ = 'billing_record'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    last_login = db.Column(db.DateTime, nullable=False)
    logout_time = db.Column(db.DateTime)  # 下机时间
    fee = db.Column(db.Float, nullable=False)

    user = db.relationship('User', backref=db.backref('billing_records', lazy=True))

    def __repr__(self):
        return '<BillingRecord %r>' % self.username


class BillingGroup(db.Model):
    __tablename__ = 'billing_group'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    price = db.Column(db.Float, nullable=False)
    users = db.relationship('User', backref='billing_group', lazy=True)

    def __repr__(self):
        return f'<BillingGroup {self.name}>'


def create_billing_record(user_id, last_login, logout_time):
    """创建收费记录"""
    user = User.query.get(user_id)
    if user:
        fee = user.calculate_fee()
        billing_record = BillingRecord(
            user_id=user_id,
            username=user.username,  # 从 User 对象获取用户名
            last_login=last_login,
            logout_time=logout_time,
            fee=fee
        )
        db.session.add(billing_record)
        db.session.commit()
        return billing_record
    else:
        return None


# 创建默认管理员账户
with app.app_context():
    db.create_all()
    # 检查是否存在名为 '默认' 的计费组
    default_billing_group = BillingGroup.query.filter_by(name='默认').first()
    if not default_billing_group:
        # 创建默认计费组
        default_billing_group = BillingGroup(name='默认', price=0.1)
        db.session.add(default_billing_group)
        db.session.commit()

    # 检查是否存在名为 'admin' 的用户
    if not User.query.filter_by(username='admin').first():
        # 创建管理员用户
        admin_user = User(
            username='admin',
            password=generate_password_hash('admin'),
            is_admin=True,
            is_logged=False,
            last_login=datetime.now().date(),
            billing_group_id=default_billing_group.id  # 设置管理员用户的计费组
        )
        db.session.add(admin_user)
        db.session.commit()


@app.route('/api/login', methods=['POST'], endpoint='api_login')
def login():
    user_id = session.get('user_id')  # 获取用户 ID
    if user_id:
        user = User.query.get(user_id)  # 使用用户 ID 查询用户
        if user:
            # 记录上机时间
            user.last_login = datetime.now()
            db.session.commit()
            return '上机成功'
        else:
            return '用户不存在'
    else:
        return '请先登录'


@app.route('/api/logout', methods=['POST'], endpoint='api_logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            # 检查用户是否已上机
            if user.is_logged:
                # 记录下机时间
                logout_time = datetime.now()
                create_billing_record(user_id, user.last_login, logout_time)  # 创建计费记录

                # 清除上机时间
                user.last_login = None
                user.is_logged = False  # 更新用户状态为未上机

                db.session.commit()
                return '下机成功'
            else:
                return '您尚未上机'
        else:
            return '用户不存在'
    else:
        return '请先登录'


@app.route('/')
def index():
    if 'logged_in' in session and session['logged_in']:
        if session['is_admin']:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    else:
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


@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    user = User.query.get(user_id)

    # 检查 last_login 是否为 None
    if user.is_logged:
        last_login_str = "未上机"
    else:
        last_login_str = user.last_login.strftime('%Y-%m-%d %H:%M:%S')

    user_data = {
        'username': user.username,
        'last_login': last_login_str,
        "fee_per_minute": user.billing_group_price,
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'fee': User.calculate_fee(User.query.get(user_id))
    }
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    return render_template('dashboard.html', user_data=user_data, on_log=user.is_logged)


@app.route('/billing_history')
def billing_history():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            billing_records = BillingRecord.query.filter_by(user_id=user_id).all()
            return render_template('billing_history.html', billing_records=billing_records)
        else:
            return '用户不存在'
    else:
        return '请先登录'


@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('logged_in') or not session.get('is_admin'):
        return redirect(url_for('index'))
    users = User.query.all()  # 获取所有用户
    return render_template('admin_dashboard.html', users=users)


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
