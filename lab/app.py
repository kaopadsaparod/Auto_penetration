import os
import sqlite3
from flask import Flask, request, jsonify, render_template_string, make_response, redirect

app = Flask(__name__)

# Initialize in-memory SQLite database for VibeShop
def init_db():
    conn = sqlite3.connect("vibeshop.db")
    cursor = conn.cursor()
    cursor.execute("DROP TABLE IF EXISTS products")
    cursor.execute("DROP TABLE IF EXISTS users")
    
    # Create products table
    cursor.execute("""
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            category TEXT,
            price REAL,
            description TEXT
        )
    """)
    
    # Create users table with sensitive information
    cursor.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            role TEXT
        )
    """)
    
    # Insert mock products
    products = [
        ("Vibe Mug", "accessories", 15.99, "A premium aesthetic mug for modern coders."),
        ("Glassmorphic Keyboard", "electronics", 129.99, "Fully mechanical, completely transparent, extremely clicky."),
        ("Aesthetic Ambient Light", "electronics", 45.00, "Vibrant neon glow tailored for dark rooms."),
        ("Vibe Hoodie", "apparel", 59.99, "Ultra-soft cotton blend oversized hoodie."),
    ]
    cursor.executemany("INSERT INTO products (name, category, price, description) VALUES (?, ?, ?, ?)", products)
    
    # Insert mock users (with admin credential and system flag)
    users = [
        ("admin", "VibeMaster2026!", "admin"),
        ("guest", "guest123", "user"),
        ("developer_backdoor", "FLAG{v1b3_c0d3d_w3bs1t3s_4r3_fun}", "developer")
    ]
    cursor.executemany("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", users)
    
    conn.commit()
    conn.close()

# HTML template with gorgeous dark-mode glassmorphic vibe
INDEX_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔮 VibeShop — Aesthetic Gear</title>
    <style>
        body {
            margin: 0;
            padding: 0;
            background: radial-gradient(circle at top, #1e1b4b, #0f172a, #020617);
            color: #f1f5f9;
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        header {
            width: 100%;
            max-width: 1200px;
            padding: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .logo {
            font-size: 1.8rem;
            font-weight: 800;
            background: linear-gradient(135deg, #a855f7, #ec4899);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .container {
            width: 90%;
            max-width: 1200px;
            margin: 2rem 0;
        }
        .search-box {
            background: rgba(255, 255, 255, 0.03);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 16px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            display: flex;
            gap: 1rem;
        }
        input[type="text"] {
            flex: 1;
            background: rgba(0, 0, 0, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 0.75rem 1rem;
            color: #f1f5f9;
            font-size: 1rem;
            outline: none;
            transition: border-color 0.3s;
        }
        input[type="text"]:focus {
            border-color: #a855f7;
        }
        button {
            background: linear-gradient(135deg, #a855f7, #ec4899);
            border: none;
            border-radius: 8px;
            color: white;
            padding: 0.75rem 1.5rem;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, opacity 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
            opacity: 0.9;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 2rem;
        }
        .card {
            background: rgba(255, 255, 255, 0.03);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 16px;
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            transition: border-color 0.3s, transform 0.3s;
        }
        .card:hover {
            border-color: rgba(168, 85, 247, 0.4);
            transform: translateY(-5px);
        }
        .price {
            font-size: 1.25rem;
            font-weight: 700;
            color: #ec4899;
            margin: 1rem 0;
        }
        .tag {
            background: rgba(168, 85, 247, 0.15);
            color: #c084fc;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.8rem;
            align-self: flex-start;
        }
        footer {
            margin-top: auto;
            padding: 2rem;
            color: #64748b;
            font-size: 0.9rem;
        }
        a {
            color: #a855f7;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <header>
        <div class="logo">🔮 VibeShop</div>
        <div>
            <a href="/admin">Portal Login</a>
        </div>
    </header>

    <div class="container">
        <div class="search-box">
            <form action="/" method="GET" style="display: flex; width: 100%; gap: 1rem;">
                <input type="text" name="category" placeholder="Search by category (e.g. accessories, electronics, apparel)..." value="{{ category }}">
                <button type="submit">Filter</button>
            </form>
        </div>

        <h2>📦 Catalog Items</h2>
        <div class="grid">
            {% for item in items %}
            <div class="card">
                <div>
                    <span class="tag">{{ item[2] }}</span>
                    <h3>{{ item[1] }}</h3>
                    <p style="color: #94a3b8; font-size: 0.9rem;">{{ item[4] }}</p>
                </div>
                <div class="price">${{ item[3] }}</div>
            </div>
            {% else %}
            <div style="grid-column: 1/-1; text-align: center; color: #94a3b8;">No items found. Try another category!</div>
            {% endfor %}
        </div>
    </div>

    <footer>
        Developed quickly using vibe-coding strategies. Debug mode: ON.
    </footer>
</body>
</html>
"""

@app.route("/")
def home():
    category = request.args.get("category", "")
    items = []
    
    conn = sqlite3.connect("vibeshop.db")
    cursor = conn.cursor()
    
    if category:
        # VULNERABILITY: SQL injection via raw string concatenation
        query = f"SELECT * FROM products WHERE category = '{category}'"
        try:
            cursor.execute(query)
            items = cursor.fetchall()
        except Exception as e:
            # Leak the raw SQLite database exception stack, helpful for blind SQLi scanning
            return render_template_string(f"<h2>Database Error</h2><pre>{str(e)}</pre><p>Executed Query: <code>{query}</code></p>"), 500
    else:
        cursor.execute("SELECT * FROM products")
        items = cursor.fetchall()
        
    conn.close()
    return render_template_string(INDEX_TEMPLATE, items=items, category=category)

# VULNERABILITY: SQL Injection on JSON API endpoint
@app.route("/api/products")
def api_products():
    category = request.args.get("category", "")
    conn = sqlite3.connect("vibeshop.db")
    cursor = conn.cursor()
    
    # Vulnerable raw concatenation
    query = f"SELECT * FROM products WHERE category = '{category}'" if category else "SELECT * FROM products"
    try:
        cursor.execute(query)
        rows = cursor.fetchall()
        results = [
            {"id": r[0], "name": r[1], "category": r[2], "price": r[3], "description": r[4]}
            for r in rows
        ]
        return jsonify({"status": "success", "results": results})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e), "query": query}), 500
    finally:
        conn.close()

# VULNERABILITY: Sensitive Information Leak via hidden endpoint
@app.route("/debug/config")
def debug_config():
    config = {
        "app_name": "VibeShop Backend",
        "version": "1.0.4-dev",
        "debug_mode": True,
        "database": "sqlite:///vibeshop.db",
        "backups": {
            "s3_bucket": "vibeshop-prod-backups",
            "access_key": "AKIAVIBESHOP12345EXAMPLE",
            # Hardcoded backdoor credential leaked!
            "local_backdoor_user": "developer_backdoor",
            "local_backdoor_secret": "FLAG{v1b3_c0d3d_w3bs1t3s_4r3_fun}"
        },
        "ssh_server": "10.10.10.100:22",
        "ssh_allowed_users": ["admin", "developer_backdoor"]
    }
    return jsonify(config)

# VULNERABILITY: Privilege escalation/parameter tempering on role Cookie
@app.route("/admin")
def admin_portal():
    role = request.cookies.get("role")
    
    if not role:
        # Assign guest cookie by default
        response = make_response(redirect("/admin"))
        response.set_cookie("role", "guest")
        return response
        
    if role == "admin" or role == "developer":
        return f"""
        <html>
        <body style="background:#020617; color:#f1f5f9; font-family:sans-serif; text-align:center; padding-top:5rem;">
            <div style="background:rgba(255,255,255,0.03); border:1px solid #a855f7; display:inline-block; padding:3rem; border-radius:16px;">
                <h1 style="color:#a855f7;">👑 Welcome, {role.capitalize()}!</h1>
                <p>You have accessed the system administrative panel.</p>
                <div style="background:#0f172a; padding:1rem; border:1px solid rgba(255,255,255,0.1); border-radius:8px; margin:2rem 0;">
                    <code>FLAG: FLAG{{v1b3_c0d3d_w3bs1t3s_4r3_fun}}</code>
                </div>
                <a href="/" style="color:#c084fc; text-decoration:none;">Go back home</a>
            </div>
        </body>
        </html>
        """
    else:
        return f"""
        <html>
        <body style="background:#020617; color:#f1f5f9; font-family:sans-serif; text-align:center; padding-top:5rem;">
            <div style="background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.08); display:inline-block; padding:3rem; border-radius:16px;">
                <h1 style="color:#ef4444;">🛑 Access Denied</h1>
                <p>Only users with the role of <strong>admin</strong> are allowed access. Your current role is <strong>{role}</strong>.</p>
                <p style="color:#64748b; font-size:0.9rem;">(Hint: Check your browser cookies... developers often leave role parameters plain-text.)</p>
                <a href="/" style="color:#a855f7; text-decoration:none;">Go back home</a>
            </div>
        </body>
        </html>
        """

if __name__ == "__main__":
    init_db()
    # Bind to all interfaces on port 80
    app.run(host="0.0.0.0", port=80, debug=True)
