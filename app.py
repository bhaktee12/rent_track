from flask import Flask, render_template, request, redirect, url_for, flash, session
import mysql.connector
from mysql.connector import Error
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
from datetime import date

app = Flask(__name__)
app.secret_key = 'rent_tracker_secret'

# ── DB CONFIG ────────────────────────────────────────────────────────────────
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'lilo',             # <-- your MySQL password (blank if none)
    'database': 'rent_collection'
}
# ─────────────────────────────────────────────────────────────────────────────

def get_db():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except Error as e:
        print(f"Database connection error: {e}")
        return None


# ── AUTH / HELPERS ────────────────────────────────────────────────────────────
def ensure_auth_schema():
    """
    Create auth table (if missing) without changing your existing schema.
    """
    db = get_db()
    if not db:
        return
    cur = db.cursor()
    try:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS user_auth (
              user_id INT AUTO_INCREMENT PRIMARY KEY,
              role ENUM('tenant','owner') NOT NULL,
              role_id VARCHAR(16) NOT NULL,
              email VARCHAR(255) NOT NULL UNIQUE,
              password_hash VARCHAR(255) NOT NULL,
              created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
              INDEX idx_role_roleid (role, role_id)
            )
            """
        )
        db.commit()
    finally:
        cur.close()
        db.close()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('user'):
            flash('Please log in to continue.', 'error')
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapper


def role_required(role):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = session.get('user')
            if not user:
                flash('Please log in to continue.', 'error')
                return redirect(url_for('login'))
            if user.get('role') != role:
                flash('You are not allowed to access that page.', 'error')
                return redirect(url_for('home'))
            return fn(*args, **kwargs)
        return wrapper
    return deco


def next_tenant_id(db):
    cur = db.cursor()
    try:
        cur.execute(
            """
            SELECT tenant_id
            FROM tenant_s
            WHERE tenant_id LIKE 'T%'
            ORDER BY CAST(SUBSTRING(tenant_id, 2) AS UNSIGNED) DESC
            LIMIT 1
            """
        )
        row = cur.fetchone()
        last_num = int(row[0][1:]) if row and row[0] and len(row[0]) > 1 else 0
        return f"T{last_num + 1:03d}"
    finally:
        cur.close()


def next_owner_id(db):
    cur = db.cursor()
    try:
        cur.execute(
            """
            SELECT owner_id
            FROM owner_s
            WHERE owner_id LIKE 'L%'
            ORDER BY CAST(SUBSTRING(owner_id, 2) AS UNSIGNED) DESC
            LIMIT 1
            """
        )
        row = cur.fetchone()
        last_num = int(row[0][1:]) if row and row[0] and len(row[0]) > 1 else 0
        return f"L{last_num + 1:04d}"
    finally:
        cur.close()


@app.before_request
def _init_schema_once():
    if not app.config.get('_AUTH_SCHEMA_OK'):
        ensure_auth_schema()
        app.config['_AUTH_SCHEMA_OK'] = True


# ── PUBLIC HOME (NO LOGIN REQUIRED) ───────────────────────────────────────────
@app.route('/')
def public_home():
    db = get_db()
    q = (request.args.get('q') or '').strip()
    props = []
    if db:
        cur = db.cursor(dictionary=True)
        try:
            if q:
                cur.execute(
                    """
                    SELECT property_id, address, property_type, rent_amount
                    FROM property_s
                    WHERE address LIKE %s
                    ORDER BY property_id
                    LIMIT 60
                    """,
                    (f"%{q}%",),
                )
            else:
                cur.execute(
                    """
                    SELECT property_id, address, property_type, rent_amount
                    FROM property_s
                    ORDER BY property_id
                    LIMIT 60
                    """
                )
            props = cur.fetchall()
        except Error as e:
            flash(f'DB error: {e}', 'error')
        finally:
            cur.close()
            db.close()
    return render_template('public_home.html', properties=props, q=q)


# ── AUTH ROUTES ───────────────────────────────────────────────────────────────
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')

    role = (request.form.get('role') or '').strip().lower()
    name = (request.form.get('name') or '').strip()
    email = (request.form.get('email') or '').strip().lower()
    password = request.form.get('password') or ''
    contact = (request.form.get('contact') or '').strip()
    address = (request.form.get('address') or '').strip()

    if role not in ('tenant', 'owner'):
        flash('Please select a valid role.', 'error')
        return redirect(url_for('signup'))
    if not name or not email or not password:
        flash('Please fill all required fields.', 'error')
        return redirect(url_for('signup'))

    db = get_db()
    if not db:
        flash('Could not connect to database.', 'error')
        return redirect(url_for('signup'))

    try:
        cur = db.cursor()
        cur.execute("SELECT 1 FROM user_auth WHERE email=%s LIMIT 1", (email,))
        if cur.fetchone():
            flash('Email already registered. Please log in.', 'error')
            return redirect(url_for('login'))

        pw_hash = generate_password_hash(password)

        if role == 'tenant':
            tenant_id = next_tenant_id(db)
            cur.execute(
                "INSERT INTO tenant_s (tenant_name, tenant_id, email, contactNo) VALUES (%s,%s,%s,%s)",
                (name, tenant_id, email, contact or None),
            )
            role_id = tenant_id
        else:
            owner_id = next_owner_id(db)
            cur.execute(
                "INSERT INTO owner_s (owner_name, owner_id, address, contactNo) VALUES (%s,%s,%s,%s)",
                (name, owner_id, address or None, contact or None),
            )
            role_id = owner_id

        cur.execute(
            "INSERT INTO user_auth (role, role_id, email, password_hash) VALUES (%s,%s,%s,%s)",
            (role, role_id, email, pw_hash),
        )

        db.commit()

        session['user'] = {'role': role, 'role_id': role_id, 'email': email, 'name': name}
        flash(f'Welcome! Your ID is {role_id}.', 'success')
        return redirect(url_for('home'))
    except Error as e:
        db.rollback()
        flash(f'Signup failed: {e}', 'error')
        return redirect(url_for('signup'))
    finally:
        try:
            cur.close()
        except Exception:
            pass
        db.close()


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    email = (request.form.get('email') or '').strip().lower()
    password = request.form.get('password') or ''
    if not email or not password:
        flash('Please enter email and password.', 'error')
        return redirect(url_for('login'))

    db = get_db()
    if not db:
        flash('Could not connect to database.', 'error')
        return redirect(url_for('login'))

    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT * FROM user_auth WHERE email=%s LIMIT 1", (email,))
        u = cur.fetchone()
        if not u or not check_password_hash(u['password_hash'], password):
            flash('Invalid email or password.', 'error')
            return redirect(url_for('login'))

        # best-effort name lookup (for header)
        name = None
        if u['role'] == 'tenant':
            cur.execute("SELECT tenant_name AS name FROM tenant_s WHERE tenant_id=%s LIMIT 1", (u['role_id'],))
            r = cur.fetchone()
            name = (r or {}).get('name')
        else:
            cur.execute("SELECT owner_name AS name FROM owner_s WHERE owner_id=%s LIMIT 1", (u['role_id'],))
            r = cur.fetchone()
            name = (r or {}).get('name')

        session['user'] = {
            'role': u['role'],
            'role_id': u['role_id'],
            'email': u['email'],
            'name': name or u['email'].split('@')[0],
        }
        flash('Logged in successfully.', 'success')
        return redirect(url_for('home'))
    except Error as e:
        flash(f'Login failed: {e}', 'error')
        return redirect(url_for('login'))
    finally:
        cur.close()
        db.close()


@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out.', 'success')
    return redirect(url_for('public_home'))


# ── ROLE HOME ────────────────────────────────────────────────────────────────
@app.route('/home')
@login_required
def home():
    user = session['user']
    if user['role'] == 'owner':
        return redirect(url_for('owner_home'))
    return redirect(url_for('tenant_home'))


# ── OWNER HOME ───────────────────────────────────────────────────────────────
@app.route('/owner')
@role_required('owner')
def owner_home():
    user = session['user']
    db = get_db()
    props = []
    rent_rows = []
    leased_tenants = []
    owner_profile = {}
    stats = {'properties': 0, 'tenants': 0, 'paid': 0, 'pending': 0}

    if db:
        cur = db.cursor(dictionary=True)
        try:
            cur.execute(
                """
                SELECT p.property_id, p.address, p.property_type, p.rent_amount
                FROM property_s p
                WHERE p.owner_id = %s
                ORDER BY p.property_id
                LIMIT 2
                """,
                (user['role_id'],),
            )
            props = cur.fetchall()
            stats['properties'] = len(props)

            cur.execute(
                """
                SELECT owner_id, owner_name, address, contactNo
                FROM owner_s
                WHERE owner_id = %s
                LIMIT 1
                """,
                (user['role_id'],),
            )
            owner_profile = cur.fetchone() or {}

            cur.execute(
                """
                SELECT t.tenant_id, t.tenant_name, t.email, t.contactNo,
                       COUNT(DISTINCT l.property_id) AS leased_properties
                FROM lease l
                JOIN property_s p ON l.property_id = p.property_id
                JOIN tenant_s t ON l.tenant_id = t.tenant_id
                WHERE p.owner_id = %s
                GROUP BY t.tenant_id, t.tenant_name, t.email, t.contactNo
                ORDER BY t.tenant_name
                LIMIT 2
                """,
                (user['role_id'],),
            )
            leased_tenants = cur.fetchall()

            cur.execute(
                """
                SELECT COUNT(DISTINCT l.tenant_id) AS cnt
                FROM lease l
                JOIN property_s p ON l.property_id = p.property_id
                WHERE p.owner_id = %s
                """,
                (user['role_id'],),
            )
            stats['tenants'] = (cur.fetchone() or {}).get('cnt', 0)

            cur.execute(
                """
                SELECT
                  t.tenant_name,
                  p.address,
                  ps.payment_status,
                  ps.amount,
                  ps.pay_date
                FROM payment_s ps
                JOIN lease l ON ps.Lease_ID = l.lease_id
                JOIN tenant_s t ON l.tenant_id = t.tenant_id
                JOIN property_s p ON l.property_id = p.property_id
                WHERE p.owner_id = %s
                ORDER BY ps.pay_date DESC
                LIMIT 2
                """,
                (user['role_id'],),
            )
            rent_rows = cur.fetchall()

            stats['paid'] = sum(1 for r in rent_rows if r.get('payment_status') == 'Paid')
            stats['pending'] = sum(1 for r in rent_rows if r.get('payment_status') != 'Paid')
        except Error as e:
            flash(f'DB error: {e}', 'error')
        finally:
            cur.close()
            db.close()

    return render_template(
        'owner_home.html',
        user=user,
        properties=props,
        rent_rows=rent_rows,
        leased_tenants=leased_tenants,
        owner_profile=owner_profile,
        stats=stats,
    )


# ── TENANT HOME ──────────────────────────────────────────────────────────────
@app.route('/tenant')
@role_required('tenant')
def tenant_home():
    user = session['user']
    db = get_db()
    lease_info = None
    payments_list = []
    payment_history = []
    notifications = []
    owner_contact = {}
    tenant_profile = {}
    rent_status = {'status': 'Pending', 'amount_due': 0, 'due_date': None}
    stats = {'paid': 0, 'pending': 0}
    browse_q = (request.args.get('q') or '').strip()
    browse_properties = []

    if db:
        cur = db.cursor(dictionary=True)
        try:
            cur.execute(
                """
                SELECT l.lease_id, p.property_id, p.address, p.property_type, p.rent_amount,
                       p.owner_id, o.owner_name, o.contactNo,
                       t.tenant_name, t.email, t.contactNo AS tenant_contact
                FROM lease l
                JOIN property_s p ON l.property_id = p.property_id
                LEFT JOIN owner_s o ON p.owner_id = o.owner_id
                LEFT JOIN tenant_s t ON l.tenant_id = t.tenant_id
                WHERE l.tenant_id = %s
                ORDER BY l.lease_id DESC
                LIMIT 1
                """,
                (user['role_id'],),
            )
            lease_info = cur.fetchone()

            if lease_info:
                cur.execute(
                    """
                    SELECT payment_id, pay_date, payment_mode, amount, payment_status
                    FROM payment_s
                    WHERE Lease_ID = %s
                    ORDER BY pay_date DESC
                    LIMIT 20
                    """,
                    (lease_info['lease_id'],),
                )
                payments_list = cur.fetchall()
                stats['paid'] = sum(1 for r in payments_list if r.get('payment_status') == 'Paid')
                stats['pending'] = sum(1 for r in payments_list if r.get('payment_status') != 'Paid')

                for row in payments_list:
                    pay_date = row.get('pay_date')
                    month_label = pay_date.strftime('%b %Y') if pay_date else '—'
                    payment_history.append(
                        {
                            'month': month_label,
                            'amount': row.get('amount'),
                            'status': row.get('payment_status'),
                        }
                    )

                today = date.today()
                due_date = date(today.year, today.month, 5)
                rent_amount = int(lease_info.get('rent_amount') or 0)

                cur.execute(
                    """
                    SELECT payment_status
                    FROM payment_s
                    WHERE Lease_ID = %s
                      AND YEAR(pay_date) = %s
                      AND MONTH(pay_date) = %s
                    ORDER BY pay_date DESC
                    LIMIT 1
                    """,
                    (lease_info['lease_id'], today.year, today.month),
                )
                this_month = cur.fetchone()
                this_month_status = (this_month or {}).get('payment_status')

                if this_month_status == 'Paid':
                    rent_status['status'] = 'Paid'
                    rent_status['amount_due'] = 0
                elif today > due_date:
                    rent_status['status'] = 'Overdue'
                    rent_status['amount_due'] = rent_amount
                else:
                    rent_status['status'] = 'Pending'
                    rent_status['amount_due'] = rent_amount
                rent_status['due_date'] = due_date

                days_diff = (due_date - today).days
                if rent_status['status'] == 'Paid':
                    notifications.append('Payment received for current month.')
                elif rent_status['status'] == 'Pending' and days_diff <= 3:
                    notifications.append(f'Rent due in {max(days_diff, 0)} day(s).')
                elif rent_status['status'] == 'Overdue':
                    notifications.append(f'Rent overdue by {abs(days_diff)} day(s).')

                last_paid = next((p for p in payments_list if p.get('payment_status') == 'Paid'), None)
                if last_paid:
                    paid_date = last_paid.get('pay_date')
                    paid_label = paid_date.strftime('%d %b %Y') if paid_date else 'recent date'
                    notifications.append(f'Payment received on {paid_label}.')

                owner_contact = {
                    'name': lease_info.get('owner_name'),
                    'phone': lease_info.get('contactNo'),
                    'owner_id': lease_info.get('owner_id'),
                    'property': lease_info.get('address'),
                }
                tenant_profile = {
                    'name': lease_info.get('tenant_name') or user.get('name'),
                    'email': lease_info.get('email') or user.get('email'),
                    'phone': lease_info.get('tenant_contact'),
                    'tenant_id': user.get('role_id'),
                }
            else:
                tenant_profile = {
                    'name': user.get('name'),
                    'email': user.get('email'),
                    'phone': None,
                    'tenant_id': user.get('role_id'),
                }

            if browse_q:
                cur.execute(
                    """
                    SELECT
                      p.property_id, p.address, p.property_type, p.rent_amount,
                      p.owner_id, o.owner_name, o.contactNo
                    FROM property_s p
                    LEFT JOIN owner_s o ON p.owner_id = o.owner_id
                    WHERE p.address LIKE %s
                    ORDER BY p.property_id
                    LIMIT 60
                    """,
                    (f"%{browse_q}%",),
                )
                browse_properties = cur.fetchall()
        except Error as e:
            flash(f'DB error: {e}', 'error')
        finally:
            cur.close()
            db.close()

    return render_template(
        'tenant_home.html',
        user=user,
        lease=lease_info,
        payments=payments_list,
        payment_history=payment_history,
        notifications=notifications,
        owner_contact=owner_contact,
        tenant_profile=tenant_profile,
        rent_status=rent_status,
        stats=stats,
        browse_q=browse_q,
        browse_properties=browse_properties,
        active_page='dashboard'
    )


@app.route('/tenant/payments')
@role_required('tenant')
def tenant_payments():
    user = session['user']
    db = get_db()
    payments_list = []
    if db:
        cur = db.cursor(dictionary=True)
        try:
            cur.execute(
                "SELECT lease_id FROM lease WHERE tenant_id = %s",
                (user['role_id'],)
            )
            lease = cur.fetchone()
            if lease:
                cur.execute(
                    """
                    SELECT payment_id, pay_date, payment_mode, amount, payment_status
                    FROM payment_s
                    WHERE Lease_ID = %s
                    ORDER BY pay_date DESC
                    """,
                    (lease['lease_id'],)
                )
                payments_list = cur.fetchall()
        finally:
            cur.close()
            db.close()
    return render_template('tenant_payments.html', user=user, payments=payments_list, active_page='payments')


@app.route('/tenant/lease')
@role_required('tenant')
def tenant_lease():
    user = session['user']
    db = get_db()
    lease_info = None
    if db:
        cur = db.cursor(dictionary=True)
        try:
            cur.execute(
                """
                SELECT l.*, p.address, p.property_type, p.rent_amount, o.owner_name, o.contactNo AS owner_contact
                FROM lease l
                JOIN property_s p ON l.property_id = p.property_id
                JOIN owner_s o ON p.owner_id = o.owner_id
                WHERE l.tenant_id = %s
                ORDER BY l.lease_id DESC LIMIT 1
                """,
                (user['role_id'],)
            )
            lease_info = cur.fetchone()
        finally:
            cur.close()
            db.close()
    return render_template('tenant_lease.html', user=user, lease=lease_info, active_page='lease')


@app.route('/tenant/rent')
@role_required('tenant')
def tenant_rent():
    # Reuse logic from tenant_home for rent status
    user = session['user']
    db = get_db()
    rent_status = {'status': 'Pending', 'amount_due': 0, 'due_date': None}
    if db:
        cur = db.cursor(dictionary=True)
        try:
            cur.execute(
                "SELECT l.lease_id, p.rent_amount FROM lease l JOIN property_s p ON l.property_id = p.property_id WHERE l.tenant_id = %s LIMIT 1",
                (user['role_id'],)
            )
            lease = cur.fetchone()
            if lease:
                today = date.today()
                due_date = date(today.year, today.month, 5)
                rent_amount = int(lease.get('rent_amount') or 0)
                
                cur.execute(
                    "SELECT payment_status FROM payment_s WHERE Lease_ID = %s AND YEAR(pay_date) = %s AND MONTH(pay_date) = %s LIMIT 1",
                    (lease['lease_id'], today.year, today.month)
                )
                this_month = cur.fetchone()
                status = (this_month or {}).get('payment_status')
                
                if status == 'Paid':
                    rent_status = {'status': 'Paid', 'amount_due': 0, 'due_date': due_date}
                elif today > due_date:
                    rent_status = {'status': 'Overdue', 'amount_due': rent_amount, 'due_date': due_date}
                else:
                    rent_status = {'status': 'Pending', 'amount_due': rent_amount, 'due_date': due_date}
        finally:
            cur.close()
            db.close()
    return render_template('tenant_rent.html', user=user, rent_status=rent_status, active_page='rent')


# ── ADMIN DASHBOARD (OPTIONAL) ────────────────────────────────────────────────
@app.route('/admin')
@role_required('owner')
def dashboard():
    db = get_db()
    stats = {'tenants': 0, 'properties': 0, 'owners': 0, 'paid': 0, 'pending': 0, 'recent_tenants': [], 'recent_properties': []}
    recent_payments = []

    if db:
        cursor = db.cursor(dictionary=True)
        try:
            cursor.execute("SELECT COUNT(*) AS cnt FROM tenant_s")
            stats['tenants'] = cursor.fetchone()['cnt']

            cursor.execute("SELECT COUNT(*) AS cnt FROM property_s")
            stats['properties'] = cursor.fetchone()['cnt']

            cursor.execute("SELECT COUNT(*) AS cnt FROM owner_s")
            stats['owners'] = cursor.fetchone()['cnt']

            cursor.execute("SELECT COUNT(*) AS cnt FROM payment_s WHERE payment_status='Paid'")
            stats['paid'] = cursor.fetchone()['cnt']

            cursor.execute("SELECT COUNT(*) AS cnt FROM payment_s WHERE payment_status='Pending'")
            stats['pending'] = cursor.fetchone()['cnt']

            cursor.execute("""
                SELECT p.payment_id, t.tenant_name, p.amount, p.pay_date,
                       p.payment_status, p.payment_mode
                FROM payment_s p
                JOIN lease l ON p.Lease_ID = l.lease_id
                JOIN tenant_s t ON l.tenant_id = t.tenant_id
                ORDER BY p.pay_date DESC LIMIT 5
            """)
            recent_payments = cursor.fetchall()
        except Error as e:
            flash(f'DB error: {e}', 'error')
        finally:
            cursor.close()
            db.close()

    return render_template('dashboard.html', stats=stats, recent_payments=recent_payments)


# ── TENANTS ───────────────────────────────────────────────────────────────────
@app.route('/tenants')
@role_required('owner')
def tenants():
    user = session['user']
    db = get_db()
    tenants_list = []
    if db:
        cursor = db.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT DISTINCT t.*
                FROM tenant_s t
                JOIN lease l ON t.tenant_id = l.tenant_id
                JOIN property_s p ON l.property_id = p.property_id
                WHERE p.owner_id = %s
                ORDER BY t.tenant_id
                """,
                (user['role_id'],),
            )
            tenants_list = cursor.fetchall()
        except Error as e:
            flash(f'DB error: {e}', 'error')
        finally:
            cursor.close()
            db.close()
    return render_template('tenants.html', tenants=tenants_list)


@app.route('/tenants/add', methods=['POST'])
@role_required('owner')
def add_tenant():
    db = get_db()
    if db:
        cursor = db.cursor(dictionary=True)
        try:
            email = (request.form.get('email') or '').strip().lower()
            # Check if tenant with this email already exists
            cursor.execute("SELECT tenant_id FROM tenant_s WHERE email=%s LIMIT 1", (email,))
            existing = cursor.fetchone()
            if existing:
                flash(f'Tenant with this email already exists (ID: {existing["tenant_id"]}).', 'error')
            else:
                tenant_id = next_tenant_id(db)
                cursor.execute(
                    "INSERT INTO tenant_s (tenant_name, tenant_id, email, contactNo) VALUES (%s,%s,%s,%s)",
                    (request.form['name'], tenant_id, email, request.form.get('contact'))
                )
                db.commit()
                flash(f'Tenant added! Auto-assigned ID: {tenant_id}', 'success')
        except Error as e:
            flash(f'Error adding tenant: {e}', 'error')
        finally:
            cursor.close()
            db.close()
    return redirect(url_for('tenants'))


@app.route('/tenants/delete/<tenant_id>', methods=['POST'])
@role_required('owner')
def delete_tenant(tenant_id):
    db = get_db()
    if db:
        cursor = db.cursor()
        try:
            cursor.execute("DELETE FROM tenant_s WHERE tenant_id=%s", (tenant_id,))
            db.commit()
            flash('Tenant deleted.', 'success')
        except Error as e:
            flash(f'Error: {e}', 'error')
        finally:
            cursor.close()
            db.close()
    return redirect(url_for('tenants'))


# ── PROPERTIES ────────────────────────────────────────────────────────────────
@app.route('/properties')
@role_required('owner')
def properties():
    user = session['user']
    db = get_db()
    props = []
    owners = []
    if db:
        cursor = db.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT p.*, o.owner_name
                FROM property_s p
                LEFT JOIN owner_s o ON p.owner_id = o.owner_id
                WHERE p.owner_id = %s
                ORDER BY p.property_id
            """, (user['role_id'],))
            props = cursor.fetchall()
            cursor.execute("SELECT owner_id, owner_name FROM owner_s WHERE owner_id=%s", (user['role_id'],))
            owners = cursor.fetchall()
        except Error as e:
            flash(f'DB error: {e}', 'error')
        finally:
            cursor.close()
            db.close()
    return render_template('properties.html', properties=props, owners=owners)


@app.route('/properties/add', methods=['POST'])
@role_required('owner')
def add_property():
    user = session['user']
    db = get_db()
    if db:
        cursor = db.cursor(dictionary=True)
        try:
            owner_id = user['role_id']
            # Auto-generate property ID
            cursor.execute(
                "SELECT property_id FROM property_s ORDER BY property_id DESC LIMIT 1"
            )
            row = cursor.fetchone()
            if row:
                last_id = row['property_id']  # e.g. P00104
                try:
                    last_num = int(last_id[1:])
                except Exception:
                    last_num = 0
                new_id = f"P{last_num + 1:05d}"
            else:
                new_id = "P00101"

            cursor.execute(
                "INSERT INTO property_s (property_id, address, property_type, rent_amount, owner_id) VALUES (%s,%s,%s,%s,%s)",
                (new_id, request.form['address'],
                 request.form['property_type'], request.form['rent_amount'], owner_id)
            )
            db.commit()
            flash(f'Property added! Auto-assigned ID: {new_id}', 'success')
        except Error as e:
            flash(f'Error adding property: {e}', 'error')
        finally:
            cursor.close()
            db.close()
    return redirect(url_for('properties'))


# ── PAYMENTS ──────────────────────────────────────────────────────────────────
@app.route('/payments')
@role_required('owner')
def payments():
    user = session['user']
    db = get_db()
    payments_list = []
    leases = []
    if db:
        cursor = db.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT p.payment_id, t.tenant_name, p.amount, p.pay_date,
                       p.payment_status, p.payment_mode, p.Lease_ID AS lease_id
                FROM payment_s p
                JOIN lease l ON p.Lease_ID = l.lease_id
                JOIN tenant_s t ON l.tenant_id = t.tenant_id
                JOIN property_s ps ON l.property_id = ps.property_id
                WHERE ps.owner_id = %s
                ORDER BY p.pay_date DESC
            """, (user['role_id'],))
            payments_list = cursor.fetchall()
            cursor.execute("""
                SELECT l.lease_id, t.tenant_name, ps.address
                FROM lease l
                JOIN tenant_s t ON l.tenant_id = t.tenant_id
                JOIN property_s ps ON l.property_id = ps.property_id
                WHERE ps.owner_id = %s
            """, (user['role_id'],))
            leases = cursor.fetchall()
        except Error as e:
            flash(f'DB error: {e}', 'error')
        finally:
            cursor.close()
            db.close()
    return render_template('payments.html', payments=payments_list, leases=leases)


@app.route('/payments/add', methods=['POST'])
@role_required('owner')
def add_payment():
    db = get_db()
    if db:
        cursor = db.cursor()
        try:
            cursor.execute(
                "INSERT INTO payment_s (payment_id, pay_date, payment_mode, amount, payment_status, Lease_ID) VALUES (%s,%s,%s,%s,%s,%s)",
                (request.form['payment_id'], request.form['date'],
                 request.form['mode'], request.form['amount'],
                 request.form['status'], request.form['lease_id'])
            )
            db.commit()
            flash('Payment recorded!', 'success')
        except Error as e:
            flash(f'Error recording payment: {e}', 'error')
        finally:
            cursor.close()
            db.close()
    return redirect(url_for('payments'))


# ── OWNERS ────────────────────────────────────────────────────────────────────
@app.route('/owners')
@role_required('owner')
def owners():
    flash('Owners page is disabled in owner dashboard.', 'error')
    return redirect(url_for('owner_home'))


@app.route('/owners/add', methods=['POST'])
@role_required('owner')
def add_owner():
    db = get_db()
    if db:
        cursor = db.cursor()
        try:
            cursor.execute(
                "INSERT INTO owner_s (owner_name, owner_id, address, contactNo) VALUES (%s,%s,%s,%s)",
                (request.form['name'], request.form['owner_id'],
                 request.form['address'], request.form['contact'])
            )
            db.commit()
            flash('Owner added successfully!', 'success')
        except Error as e:
            flash(f'Error: {e}', 'error')
        finally:
            cursor.close()
            db.close()
    return redirect(url_for('owners'))


if __name__ == '__main__':
    app.run(debug=True)
