from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cjMn873LamMR5kta4'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cybercafe.db'
db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_logged = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime, default=datetime.now())
    billing_group_id = db.Column(db.Integer, db.ForeignKey('billing_group.id'), nullable=False)  # 关联 BillingGroup 模型
    balance = db.Column(db.Float, nullable=False, default=0)
    balance_left = db.Column(db.Float, nullable=False, default=0)
    on_call = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return '<User %r>' % self.username

    def calculate_fee(self):
        """计算费用"""
        if self.last_login:
            time_diff = datetime.now() - self.last_login
            hours = time_diff.total_seconds() / 3600  # 计算小时数
            return round(hours * self.billing_group.price, 2)  # 修改为每小时计费
        else:
            return 0.00


def get_balance_left(user_id):
    user = User.query.filter_by(id=user_id).first_or_404()
    sum_result = sum(record.fee for record in user.billing_records if record.fee < 0)
    balance_left = user.balance + sum_result
    return balance_left


class BillingRecord(db.Model):
    __tablename__ = 'billing_record'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    last_login = db.Column(db.DateTime, nullable=False)
    logout_time = db.Column(db.DateTime)  # 下机时间
    fee = db.Column(db.Float, nullable=False)
    description = db.Column(db.String, nullable=False)
    billing_group_id = db.Column(db.Integer, db.ForeignKey('billing_group.id'), nullable=False)
    billing_group = db.relationship('BillingGroup', backref=db.backref('billing_records', lazy=True))
    user = db.relationship('User', backref=db.backref('billing_records', lazy=True))

    def calculate_fee(self):
        """计算费用"""
        if self.last_login:
            time_diff = datetime.now() - self.last_login
            hours = time_diff.total_seconds() / 3600  # 计算小时数
            return round(hours * self.billing_group.price, 2)  # 修改为每小时计费
        else:
            return 0.00


class BillingGroup(db.Model):
    __tablename__ = 'billing_group'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    price = db.Column(db.Float, nullable=False)
    users = db.relationship('User', backref='billing_group', lazy=True)

    def __repr__(self):
        return f'<BillingGroup {self.name}>'


def create_billing_record(user_id: object, last_login: object, logout_time: object, billing_group_id: object,
                          description="用户下机", fee=None):
    """创建收费记录"""
    user = User.query.get(user_id)
    if user:
        billing_group = BillingGroup.query.get(billing_group_id)  # 获取 BillingGroup 对象
        if billing_group:
            billing_record = BillingRecord(
                user_id=user_id,
                username=user.username,  # 从 User 对象获取用户名
                last_login=last_login,
                logout_time=logout_time,
                billing_group_id=billing_group_id,  # 添加计费组 ID
                billing_group=billing_group,  # 将 BillingGroup 对象关联到 BillingRecord
                description=description,  # 使用传入的 description 或者默认值
                fee=None if fee is None else -fee  # 使用传入的 fee 或者默认值
            )
            if fee is None:  # 如果没有传入 fee，则计算费用
                billing_record.fee = -billing_record.calculate_fee()
            db.session.add(billing_record)
            db.session.commit()
            return billing_record
        else:
            return None  # 计费组不存在
    else:
        return None


# 创建默认管理员账户
with app.app_context():
    db.create_all()
    # 检查是否存在名为 '默认' 的计费组
    default_billing_group = BillingGroup.query.filter_by(name='默认').first()
    if not default_billing_group:
        # 创建默认计费组
        default_billing_group = BillingGroup(name='默认', price=5)
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


@app.route('/api/cancel_call', methods=['POST'])
def cancel_call():
    if not session.get('logged_in'):
        return jsonify({'error': '未登录'}), 403
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    if user:
        user.on_call = False  # 取消用户的呼叫状态
        db.session.commit()
        return jsonify({'success': '取消呼叫成功'})
    return jsonify({'error': '用户不存在'}), 404


@app.route('/admin/cancel_call/<int:user_id>', methods=['POST'], endpoint='admin_cancel_call')
def admin_cancel_call(user_id):
    if not session.get('logged_in') or not session.get('is_admin'):
        return redirect(url_for('index'))

    # 获取对应用户并设置 on_call 为 False
    user = User.query.get(user_id)
    if user:
        user.on_call = False
        db.session.commit()

    return redirect(url_for('admin_dashboard'))


@app.route('/api/call_admin', methods=['POST'])
def call_admin():
    if not session.get('logged_in'):
        return jsonify({'error': '未登录'}), 403

    user_id = session.get('user_id')
    user = User.query.get(user_id)
    if user:
        user.on_call = True
        db.session.commit()
        return jsonify({'success': '呼叫管理员成功'})
    return jsonify({'error': '用户不存在'}), 404


@app.route('/api/login', methods=['POST'], endpoint='api_login')
def login():
    user_id = session.get('user_id')  # 获取用户 ID
    if user_id:
        user = User.query.get(user_id)  # 使用用户 ID 查询用户
        if user:
            if get_balance_left(user_id) > 0:
                # 记录上机时间
                user.last_login = datetime.now()
                user.is_logged = True
                db.session.commit()
            else:
                return "余额不足"
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
                create_billing_record(user_id, user.last_login, logout_time, user.billing_group_id)  # 创建计费记录

                # 清除上机时间
                user.is_logged = False  # 更新用户状态为未上机
                user.balance_left = get_balance_left(user_id)
                db.session.commit()
                return '下机成功'
            else:
                return '您尚未上机'
        else:
            return '用户不存在'
    else:
        return '请先登录'


@app.route('/api/recharge', methods=['GET', 'POST'])
def recharge():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user is None:
            return redirect(url_for('dashboard'))
        else:
            if request.method == 'GET':
                return render_template('recharge.html', user=user)
            elif request.method == 'POST':
                # 处理充值逻辑
                amount = int(request.form.get('amount'))
                # ... 其他充值逻辑 ...
                return render_template('success.html')
    else:
        return redirect(url_for('login'))


@app.route('/api/recharge/confirm/<int:amount>')
def confirm_recharge(amount):
    return render_template('confirm.html', amount=amount)


@app.route('/api/recharge/confirm/custom', methods=['POST'])
def confirm_custom_recharge():
    amount = int(request.form.get('amount'))
    return render_template('confirm.html', amount=amount)


@app.route('/api/recharge/process', methods=['POST'])
def process_recharge():
    amount = int(request.form.get('amount'))
    # 这里需要处理真正的充值逻辑，例如：
    # 1. 获取用户 ID
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    # 2. 更新用户余额
    user.balance = amount + user.balance
    # 3. 记录充值记录
    create_billing_record(user_id, datetime.now(), datetime.now(), user.billing_group_id, description='用户充值',
                          fee=-amount)
    return render_template('success.html')


@app.route('/', endpoint='index')
def index():
    user_ip = request.remote_addr
    if 'logged_in' in session and session['logged_in']:
        if session['is_admin']:
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    else:
        return render_template('index.html', user_ip=user_ip)


@app.route('/login', methods=['GET', 'POST'])
def login():
    user_ip = request.remote_addr  # 获取访问者的 IP 地址
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
    return render_template('index.html', user_ip=user_ip)  # 将 user_ip 传递给模板


@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    if user.is_logged:
        return redirect(url_for('dashboard'))
    session.pop('logged_in', None)
    session.pop('user_id', None)
    session.pop('is_admin', None)
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    # 检查 user_id 是否为空
    if user is None:
        return redirect(url_for('logout'))  # 返回错误页面

    if user.is_logged:
        last_login_str = user.last_login.strftime('%Y-%m-%d %H:%M:%S')
    else:
        last_login_str = "未上机"

    user_data = {
        'username': user.username,
        'last_login': last_login_str,
        "fee_per_minute": user.billing_group.price,  # 使用 user.billing_group.price 获取价格
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'fee': user.calculate_fee(),  # 使用 user.calculate_fee() 获取费用
        'oncall': user.on_call
    }
    balance_left = round(get_balance_left(user_id) - user.calculate_fee(), 2)
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    return render_template('dashboard.html', user_data=user_data, on_log=user.is_logged, group=user.billing_group.name,
                           balance=user.billing_group.price, balance_left=balance_left,
                           billing_records=user.billing_records)


@app.route('/billing_history')
def billing_history():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            billing_records = BillingRecord.query.filter_by(user_id=user_id).all()
            return render_template('billing_history.html', billing_records=billing_records)
        else:
            error = '用户不存在'
            return render_template('billing_history.html', error=error)
    else:
        error = '请先登录'
        return render_template('billing_history.html', error=error)


@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('logged_in') or not session.get('is_admin'):
        return redirect(url_for('index'))
    users = User.query.all()  # 获取所有用户
    billing_groups = BillingGroup.query.all()  # 获取所有计费组
    billing_records = BillingRecord.query.all()  # 获取所有计费记录
    # 查找正在呼叫的用户（假设 on_call 字段为布尔值，表示用户是否正在呼叫）
    calling_users = [user for user in users if user.on_call]
    return render_template('admin_dashboard.html', users=users, billing_groups=billing_groups,
                           billing_records=billing_records, calling_users=calling_users)


@app.route('/edit_billing_record/<int:record_id>', methods=['GET', 'POST'])
def edit_billing_record(record_id):
    if not session.get('logged_in') or not session.get('is_admin'):
        return redirect(url_for('index'))
    record = BillingRecord.query.get_or_404(record_id)
    if request.method == 'POST':
        record.last_login = datetime.strptime(request.form['last_login'], '%Y-%m-%d %H:%M:%S')
        record.logout_time = datetime.strptime(request.form['logout_time'], '%Y-%m-%d %H:%M:%S') if request.form[
            'logout_time'] else None
        record.fee = float(request.form['fee'])
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_billing_record.html', record=record)


@app.route('/delete_billing_record/<int:record_id>')
def delete_billing_record(record_id):
    if not session.get('logged_in') or not session.get('is_admin'):
        return redirect(url_for('index'))
    record = BillingRecord.query.get_or_404(record_id)
    db.session.delete(record)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))


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
    billing_groups = BillingGroup.query.all()  # 获取所有计费组
    if request.method == 'POST':
        user.username = request.form['username']
        user.billing_group_id = int(request.form['billing_group_id'])  # 更新计费组
        if request.form['password']:
            user.password = generate_password_hash(request.form['password'])
        # 添加修改余额的代码
        if 'balance' in request.form:
            user.balance = float(request.form['balance'])
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_user.html', user=user, billing_groups=billing_groups)


@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if not session.get('logged_in') or not session.get('is_admin'):
        return redirect(url_for('index'))
    billing_groups = BillingGroup.query.all()  # 获取所有计费组
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        billing_group_id = int(request.form['billing_group_id'])  # 获取计费组 ID

        # 验证用户名和密码
        # ...

        # 创建新用户
        new_user = User(username=username, password=generate_password_hash(password), billing_group_id=billing_group_id)
        db.session.add(new_user)
        db.session.commit()

        # 重定向到管理员控制面板
        return redirect(url_for('admin_dashboard'))
    return render_template('add_user.html', billing_groups=billing_groups)


@app.route('/add_billing_group', methods=['GET', 'POST'])
def add_billing_group():
    if not session.get('logged_in') or not session.get('is_admin'):
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form['name']
        price = float(request.form['price'])

        # 验证计费组名称和价格
        # ...

        # 创建新的计费组
        new_billing_group = BillingGroup(name=name, price=price)
        db.session.add(new_billing_group)
        db.session.commit()

        # 重定向到管理员控制面板
        return redirect(url_for('admin_dashboard'))
    return render_template('add_billing_group.html')


# 编辑计费组
@app.route('/edit_billing_group/<int:billing_group_id>', methods=['GET', 'POST'])
def edit_billing_group(billing_group_id):
    if not session.get('logged_in') or not session.get('is_admin'):
        return redirect(url_for('index'))
    billing_group = BillingGroup.query.get_or_404(billing_group_id)
    if request.method == 'POST':
        billing_group.name = request.form['name']
        billing_group.price = float(request.form['price'])
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_billing_group.html', billing_group=billing_group)


# 删除计费组
@app.route('/delete_billing_group/<int:billing_group_id>')
def delete_billing_group(billing_group_id):
    if not session.get('logged_in') or not session.get('is_admin'):
        return redirect(url_for('index'))
    billing_group = BillingGroup.query.get_or_404(billing_group_id)
    db.session.delete(billing_group)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))


@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if not session.get('logged_in') or not session.get('is_admin'):
        return redirect(url_for('index'))
    user = User.query.get_or_404(user_id)
    for record in user.billing_records:
        db.session.delete(record)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))



if __name__ == '__main__':
    app.run(debug=True)
