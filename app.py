import sqlite3
import time
import os
import secrets
import json
from threading import Thread
from instagrapi import Client
from instagrapi.exceptions import ClientError, LoginRequired
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from datetime import datetime
import logging
import bcrypt
from functools import wraps
from dotenv import load_dotenv
import random
import re
import tenacity
from sqlite3 import dbapi2 as sqlite
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager
import uuid

# Code version for debugging
CODE_VERSION = "3.2.6"  # Updated for welcome.html and admin checkbox

# Load environment variables
load_dotenv()

# Set up logging with UTF-8 encoding
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler('crm.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
logger.info(f"Starting app.py version {CODE_VERSION}")

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(32))
app.config['TEMPLATES_AUTO_RELOAD'] = True

clients = {}
initial_messages = []
dm_count = 0  # Track total DMs sent
initial_dms_sent = False  # Global flag to gate auto_respond

# Database connection pool
db_pool = sqlite.connect('crm.db', timeout=50, check_same_thread=False, factory=sqlite.Connection)

# Global dictionary to store WebDriver instances by session ID
webdriver_instances = {}

# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "danger")
            return redirect(url_for('user_login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash("Admin access required.", "danger")
            return redirect(url_for('user_login'))
        return f(*args, **kwargs)
    return decorated_function

# Helper functions
def get_user_info(user_id):
    conn = db_pool
    c = conn.cursor()
    c.execute('SELECT plan, credits FROM users WHERE id = ?', (user_id,))
    return c.fetchone()

def get_accounts(user_id, role):
    conn = db_pool
    c = conn.cursor()
    if role == 'admin':
        c.execute('SELECT username, needs_reauth FROM accounts')
    else:
        c.execute('SELECT username, needs_reauth FROM accounts WHERE user_id = ?', (user_id,))
    return c.fetchall()

@tenacity.retry(
    stop=tenacity.stop_after_attempt(5),
    wait=tenacity.wait_exponential(multiplier=2, min=5, max=30),
    retry=tenacity.retry_if_exception_type(sqlite3.OperationalError),
    before_sleep=lambda retry_state: logger.warning(f"Database locked, retrying attempt {retry_state.attempt_number}...")
)
def execute_with_retry(cursor, query, params=()):
    cursor.execute(query, params)
    return cursor

def init_db():
    try:
        conn = db_pool
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS accounts
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER,
                      username TEXT NOT NULL,
                      session_file TEXT,
                      needs_reauth INTEGER DEFAULT 0,
                      has_sent_initial_dms INTEGER DEFAULT 0,
                      proxy_settings TEXT,
                      UNIQUE(user_id, username),
                      FOREIGN KEY (user_id) REFERENCES users(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS initial_dms
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      account_id INTEGER,
                      username TEXT NOT NULL,
                      sent_timestamp INTEGER,
                      UNIQUE(account_id, username),
                      FOREIGN KEY (account_id) REFERENCES accounts(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS dms
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      account_id INTEGER,
                      thread_id TEXT,
                      contact_name TEXT,
                      last_message TEXT,
                      message_id TEXT,
                      timestamp INTEGER,
                      responded INTEGER DEFAULT 0,
                      is_system_message INTEGER DEFAULT 0,
                      follow_up_stage INTEGER DEFAULT 0,
                      last_response TEXT,
                      waiting_for_contact INTEGER DEFAULT 0,
                      UNIQUE(thread_id, message_id),
                      FOREIGN KEY (account_id) REFERENCES accounts(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT NOT NULL UNIQUE,
                      password_hash TEXT NOT NULL,
                      role TEXT NOT NULL DEFAULT 'customer',
                      credits INTEGER DEFAULT 0,
                      plan TEXT DEFAULT '')''')
        c.execute('PRAGMA table_info(accounts)')
        columns = [col[1] for col in c.fetchall()]
        if 'has_sent_initial_dms' not in columns:
            c.execute('ALTER TABLE accounts ADD COLUMN has_sent_initial_dms INTEGER DEFAULT 0')
        if 'proxy_settings' not in columns:
            c.execute('ALTER TABLE accounts ADD COLUMN proxy_settings TEXT')
        c.execute('PRAGMA table_info(dms)')
        columns = [col[1] for col in c.fetchall()]
        if 'follow_up_stage' not in columns:
            c.execute('ALTER TABLE dms ADD COLUMN follow_up_stage INTEGER DEFAULT 0')
        if 'message_id' not in columns:
            c.execute('ALTER TABLE dms ADD COLUMN message_id TEXT')
        if 'last_response' not in columns:
            c.execute('ALTER TABLE dms ADD COLUMN last_response TEXT')
        if 'waiting_for_contact' not in columns:
            c.execute('ALTER TABLE dms ADD COLUMN waiting_for_contact INTEGER DEFAULT 0')
        default_admin_username = 'admin'
        default_admin_password = 'supersecret123'
        hashed_password = bcrypt.hashpw(default_admin_password.encode(), bcrypt.gensalt()).decode()
        c.execute('SELECT id FROM users WHERE username = ?', (default_admin_username,))
        if not c.fetchone():
            c.execute('INSERT INTO users (username, password_hash, role, credits, plan) VALUES (?, ?, ?, ?, ?)',
                      (default_admin_username, hashed_password, 'admin', 0, ''))
        conn.commit()
        logger.info("Database initialized successfully")
    except sqlite3.Error as e:
        logger.error(f"Database initialization failed: {str(e)}")
        raise

def load_instagrapi_client(session_file):
    try:
        if not os.path.exists(session_file):
            logger.warning(f"Session file {session_file} does not exist")
            return None
        conn = db_pool
        c = conn.cursor()
        c.execute('SELECT proxy_settings FROM accounts WHERE session_file = ?', (session_file,))
        result = c.fetchone()
        proxy_settings = json.loads(result[0]) if result and result[0] else None
        cl = Client(request_timeout=15, proxy=proxy_settings["proxy"] if proxy_settings else None)
        cl.load_settings(session_file)
        logger.info(f"Instagrapi client loaded from {session_file} with proxy: {proxy_settings}")
        return cl
    except Exception as e:
        logger.error(f"Failed to load instagrapi client from {session_file}: {str(e)}")
        return None

def get_client(user_id, username):
    conn = db_pool
    c = conn.cursor()
    c.execute('SELECT needs_reauth, session_file FROM accounts WHERE user_id = ? AND username = ?', (user_id, username))
    result = c.fetchone()
    if not result:
        logger.error(f"Account {username} not found for user_id {user_id}")
        return None
    needs_reauth, session_file = result
    client_key = f"{user_id}_{username}"
    if needs_reauth:
        logger.warning(f"Account {username} (user_id {user_id}) marked as needs_reauth")
        if client_key in clients:
            del clients[client_key]
        return None
    if client_key not in clients:
        cl = load_instagrapi_client(session_file)
        if cl:
            try:
                if not cl.user_id:
                    logger.warning(f"No user_id in session for {username} (user_id {user_id})")
                    c.execute('UPDATE accounts SET needs_reauth = 1 WHERE user_id = ? AND username = ?', (user_id, username))
                    conn.commit()
                    return None
                cl.user_info(cl.user_id)
                clients[client_key] = cl
                c.execute('UPDATE accounts SET needs_reauth = 0 WHERE user_id = ? AND username = ?', (user_id, username))
                conn.commit()
                logger.info(f"Valid session loaded for {username} (user_id {user_id})")
            except (LoginRequired, ClientError) as e:
                logger.warning(f"Session invalid for {username} (user_id {user_id}): {str(e)}")
                c.execute('UPDATE accounts SET needs_reauth = 1 WHERE user_id = ? AND username = ?', (user_id, username))
                conn.commit()
                return None
        else:
            logger.warning(f"Failed to load client for {username} (user_id {user_id}), marking as needs_reauth")
            c.execute('UPDATE accounts SET needs_reauth = 1 WHERE user_id = ? AND username = ?', (user_id, username))
            conn.commit()
            return None
    return clients.get(client_key)

def normalize_message(message):
    return re.sub(r'[^\w\s]', '', message.lower()).strip()

def is_contact_info(message):
    phone_pattern = r'(\+\d{10,15}|\(\d{3}\)\s*\d{3}-\d{4}|\d{3}-\d{3}-\d{4})'
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return bool(re.search(phone_pattern, message) or re.search(email_pattern, message))

def clean_response(response):
    music_keywords = ['music', 'song', 'artist', 'genre', 'recommendations', 'updates', 'musical']
    for keyword in music_keywords:
        response = re.sub(rf'\b{keyword}\b', '', response, flags=re.IGNORECASE)
    response = re.sub(r'\s+', ' ', response).strip()
    return response

def huggingface_chatbot(message):
    logger.debug(f"Processing message: {message}")
    normalized = normalize_message(message)
    logger.debug(f"Normalized message: {normalized}")
    
    if normalized in ['hey', 'hi', 'hello', 'yo', 'sup']:
        logger.debug("Detected greeting message, returning hardcoded greeting")
        response = "Hello! Thanks for your interest! :) How can I assist you today?"
    elif normalized in ['interested', 'imterested', 'intriguing', 'intrested', 'thrilled', 'excited']:
        logger.debug("Detected 'interested' message, returning contact request")
        response = "Awesome, glad you're intrigued! :) Could you share your email or phone number to dive deeper?"
    elif normalized in ['cool', 'nice', 'awesome']:
        logger.debug("Detected positive message, returning generic response")
        response = "Glad you think so! :) What's on your mind?"
    elif is_contact_info(message):
        logger.debug("Detected contact info, returning confirmation")
        response = "Thanks for sharing! I'll get back to you soon! :)"
    else:
        logger.debug("Using fallback response")
        response = "Thanks for replying! :) What's on your mind?"
    
    cleaned_response = clean_response(response)
    logger.debug(f"Cleaned response: {cleaned_response}")
    return cleaned_response

def auto_respond():
    global dm_count, initial_dms_sent
    THREAD_COOLDOWN = 300  # 5 minutes in seconds
    while True:
        if not initial_dms_sent:
            logger.debug("Initial DMs not sent yet, skipping auto_respond cycle")
            time.sleep(60)
            continue
        try:
            conn = db_pool
            c = conn.cursor()
            c.execute('SELECT DISTINCT user_id, username FROM accounts WHERE needs_reauth = 0 AND has_sent_initial_dms = 1')
            accounts = c.fetchall()
            logger.debug(f"Checking threads for {len(accounts)} accounts with initial DMs sent")
            pending_inserts = []
            for user_id, username in accounts:
                try:
                    c.execute('SELECT COUNT(*), MAX(sent_timestamp) FROM initial_dms WHERE account_id = (SELECT id FROM accounts WHERE user_id = ? AND username = ?)', 
                              (user_id, username))
                    initial_dm_count, max_sent_timestamp = c.fetchone()
                    if initial_dm_count == 0:
                        logger.debug(f"No initial DMs sent for {username} (user_id {user_id}), skipping auto_respond")
                        continue
                    cl = get_client(user_id, username)
                    if not cl:
                        logger.warning(f"Skipping {username} (user_id {user_id}) due to invalid session")
                        continue
                    cl_user_id = cl.user_id
                    c.execute('SELECT username FROM initial_dms WHERE account_id = (SELECT id FROM accounts WHERE user_id = ? AND username = ?)', 
                              (user_id, username))
                    initial_usernames = {row[0] for row in c.fetchall()}
                    try:
                        threads = cl.direct_threads(amount=10)
                    except (LoginRequired, ClientError) as e:
                        logger.error(f"API error for {username} (user_id {user_id}): {str(e)}")
                        c.execute('UPDATE accounts SET needs_reauth = 1 WHERE user_id = ? AND username = ?', (user_id, username))
                        conn.commit()
                        client_key = f"{user_id}_{username}"
                        if client_key in clients:
                            del clients[client_key]
                        continue
                    threads.sort(key=lambda x: x.last_activity_at.timestamp() if x.last_activity_at else 0, reverse=True)
                    logger.info(f"Fetched {len(threads)} threads for {username} (user_id {user_id})")
                    for thread in threads:
                        if not thread.messages or not thread.users:
                            logger.debug(f"Thread {thread.id} has no messages or users, skipping")
                            continue
                        contact_name = thread.users[0].username
                        if contact_name not in initial_usernames:
                            logger.debug(f"Thread {thread.id} with {contact_name} not in initial_dms, skipping")
                            continue
                        c.execute('SELECT MAX(timestamp) FROM dms WHERE thread_id = ? AND account_id = (SELECT id FROM accounts WHERE user_id = ? AND username = ?)',
                                  (thread.id, user_id, username))
                        last_response_timestamp = c.fetchone()[0] or 0
                        current_time = int(time.time())
                        if last_response_timestamp and (current_time - last_response_timestamp) < THREAD_COOLDOWN:
                            logger.debug(f"Thread {thread.id} with {contact_name} is in cooldown (last response at {last_response_timestamp}), skipping")
                            continue
                        c.execute('SELECT waiting_for_contact FROM dms WHERE thread_id = ? AND account_id = (SELECT id FROM accounts WHERE user_id = ? AND username = ?) ORDER BY timestamp DESC LIMIT 1',
                                  (thread.id, user_id, username))
                        waiting = c.fetchone()
                        waiting_for_contact = waiting[0] if waiting else 0
                        messages = sorted(thread.messages, key=lambda x: x.timestamp.timestamp() if x.timestamp else 0, reverse=True)[:10]
                        for msg in messages:
                            message_id = msg.id
                            last_message = msg.text if msg.text else ""
                            timestamp = int(msg.timestamp.timestamp()) if msg.timestamp else 0
                            is_user_message = msg.user_id != cl_user_id if msg.user_id else False
                            logger.debug(f"Processing message {message_id} in thread {thread.id} from {contact_name}: '{last_message}' (timestamp: {timestamp}, is_user: {is_user_message})")
                            if not is_user_message:
                                logger.debug(f"Message {message_id} is sent by viewer, skipping")
                                continue
                            if timestamp <= last_response_timestamp:
                                logger.debug(f"Message {message_id} (timestamp {timestamp}) is older than last response ({last_response_timestamp}), skipping")
                                continue
                            c.execute('SELECT id, responded, last_response FROM dms WHERE thread_id = ? AND message_id = ? AND account_id = (SELECT id FROM accounts WHERE user_id = ? AND username = ?)', 
                                      (thread.id, message_id, user_id, username))
                            existing = c.fetchone()
                            if existing:
                                existing_id, existing_responded, last_response = existing
                                if existing_responded:
                                    logger.debug(f"Message {message_id} already responded to, skipping")
                                    continue
                            if is_user_message and last_message:
                                if waiting_for_contact and not is_contact_info(last_message):
                                    logger.debug(f"Thread {thread.id} is waiting for contact info, skipping message {message_id}: '{last_message}'")
                                    continue
                                response = huggingface_chatbot(last_message)
                                c.execute('SELECT last_response FROM dms WHERE thread_id = ? AND account_id = (SELECT id FROM accounts WHERE user_id = ? AND username = ?) ORDER BY timestamp DESC LIMIT 5',
                                          (thread.id, user_id, username))
                                recent_responses = {row[0] for row in c.fetchall() if row[0]}
                                if response in recent_responses:
                                    logger.debug(f"Response '{response}' is identical to a recent response in thread {thread.id}, skipping")
                                    continue
                                try:
                                    cl.direct_send(response, thread_ids=[thread.id])
                                    waiting_for_contact_new = 1 if response.startswith("Awesome, glad you're intrigued!") else 0
                                    pending_inserts.append((
                                        user_id, username, thread.id, contact_name, last_message, message_id, timestamp, response, waiting_for_contact_new
                                    ))
                                    dm_count += 1
                                    logger.info(f"Sent chatbot response to {contact_name} (thread {thread.id}, message {message_id}) for {username} (user_id {user_id}): {response}")
                                except Exception as e:
                                    logger.error(f"Failed to send chatbot response to {contact_name} (thread {thread.id}, message {message_id}): {str(e)}")
                                    raise
                    if pending_inserts:
                        try:
                            c.executemany(
                                'INSERT OR REPLACE INTO dms (account_id, thread_id, contact_name, last_message, message  _id, timestamp, responded, is_system_message, follow_up_stage, last_response, waiting_for_contact) VALUES ((SELECT id FROM accounts WHERE user_id = ? AND username = ?), ?, ?, ?, ?, ?, 1, 1, 1, ?, ?)',
                                pending_inserts
                            )
                            conn.commit()
                            logger.debug(f"Batched {len(pending_inserts)} DM inserts for {username} (user_id {user_id})")
                            pending_inserts.clear()
                        except sqlite3.OperationalError as e:
                            logger.error(f"Batch insert failed for {username} (user_id {user_id}): {str(e)}")
                            raise
                except Exception as e:
                    logger.error(f"Auto-respond error for {username} (user_id {user_id}): {str(e)}")
            conn.commit()
        except sqlite3.OperationalError as e:
            logger.error(f"Database error in auto_respond: {str(e)}")
            if "database is locked" in str(e):
                logger.warning("Retrying after 10 seconds due to database lock")
                time.sleep(10)
                continue
        except Exception as e:
            logger.error(f"auto_respond loop error: {str(e)}")
        time.sleep(60)
        logger.debug("auto_respond loop completed, sleeping for 60 seconds")

# Initialize Selenium WebDriver
def init_driver():
    options = webdriver.ChromeOptions()
    # Essential headless mode settings
    options.add_argument("--headless=new")  # New headless mode for Chrome 96+
    options.add_argument("--no-sandbox")  # Required for Linux servers
    options.add_argument("--disable-dev-shm-usage")  # Prevent shared memory issues
    options.add_argument("--disable-gpu")  # Disable GPU for headless stability
    options.add_argument("--window-size=1920,1080")  # Set window size to avoid rendering issues
    options.add_argument("--remote-debugging-port=9222")  # Fix DevToolsActivePort issue
    options.add_argument("--disable-setuid-sandbox")  # Additional stability on Linux
    
    # Anti-bot detection settings
    options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
    options.add_argument("--disable-blink-features=AutomationControlled")  # Avoid bot detection
    options.add_argument("--disable-extensions")  # Reduce resource usage
    options.add_argument("--start-maximized")  # Ensure full rendering
    options.add_experimental_option("excludeSwitches", ["enable-automation"])  # Hide automation flags
    options.add_experimental_option("useAutomationExtension", False)  # Disable automation extension
    
    # Logging for debugging
    options.add_argument("--enable-logging")  # Enable Chrome logs
    options.add_argument("--log-level=0")  # Detailed logs
    options.add_argument("--v=1")  # Verbose logging for diagnostics
    
    try:
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        driver.set_page_load_timeout(60)
        logger.info("WebDriver initialized successfully")
        return driver
    except WebDriverException as e:
        logger.error(f"Failed to initialize WebDriver: {str(e)}")
        raise

@app.route('/')
def index():
    return redirect(url_for('user_login'))

@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin = request.form.get('is_admin') == 'on'
        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template('welcome.html')
        conn = db_pool
        c = conn.cursor()
        c.execute('SELECT id, username, password_hash, role, credits, plan FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        if user and bcrypt.checkpw(password.encode(), user[2].encode()):
            if is_admin and user[3] != 'admin':
                flash("Invalid admin credentials.", "danger")
                return render_template('welcome.html')
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]
            session['credits'] = user[4]
            session['plan'] = user[5]
            flash(f"Welcome, {username}! Connected", "success")
            return redirect(url_for('dashboard'))
        flash("Invalid username or password.", "danger")
        return render_template('welcome.html')
    return render_template('welcome.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' not in session:
        flash("Please log in to your CRM account first.", "danger")
        return redirect(url_for('user_login'))
    
    user_id = session['user_id']
    role = session.get('role')
    user_info = get_user_info(user_id)
    if not user_info:
        flash("User not found.", "danger")
        return redirect(url_for('dashboard'))
    plan, credits = user_info
    if not plan:
        flash("You must have an active plan to add Instagram accounts.", "danger")
        return redirect(url_for('dashboard'))
    plan_configs = {
        'plan1': {'credits_per_account': 20},
        'plan2': {'credits_per_account': 30},
        'plan3': {'credits_per_account': 34}
    }
    credits_needed = plan_configs.get(plan, {}).get('credits_per_account', 20)
    if credits < credits_needed:
        flash(f"Insufficient credits. You need {credits_needed} credits to add an account, but you have {credits}.", "danger")
        return redirect(url_for('dashboard'))

    # Limit concurrent WebDriver instances
    MAX_CONCURRENT_DRIVERS = 2
    if len(webdriver_instances) >= MAX_CONCURRENT_DRIVERS:
        logger.warning("Too many concurrent WebDriver instances")
        flash("Server is busy. Please try again later.", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        instagram_username = request.form.get("username")
        instagram_password = request.form.get("password")
        
        if not instagram_username or not instagram_password:
            logger.error("Instagram username or password missing")
            flash("Instagram username and password are required.", "danger")
            return render_template("login.html")

        # Store Instagram credentials in session
        session["instagram_username"] = instagram_username
        session["instagram_password"] = instagram_password
        session["session_id"] = str(uuid.uuid4())
        driver = None
        try:
            logger.info(f"Attempting Instagram login for {instagram_username}")
            driver = init_driver()
            webdriver_instances[session["session_id"]] = driver
            driver.get("https://www.instagram.com/accounts/login/")
            time.sleep(random.uniform(2, 4))
            
            try:
                current_url = driver.current_url
                logger.debug(f"Current URL after load: {current_url}")
                if "challenge" in current_url or "auth_platform/codeentry" in current_url:
                    logger.info("Immediate challenge detected, redirecting to /challenge")
                    session["challenge_url"] = current_url
                    return redirect(url_for('challenge'))

                # Wait for username field
                WebDriverWait(driver, 30).until(
                    EC.presence_of_element_located((By.NAME, "username"))
                )
                logger.debug("Username field found")
                driver.find_element(By.NAME, "username").send_keys(instagram_username)
                driver.find_element(By.NAME, "password").send_keys(instagram_password)
                
                # Handle cookie banner if present
                try:
                    cookie_button = WebDriverWait(driver, 5).until(
                        EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'Accept All') or contains(text(), 'Allow all cookies') or contains(text(), 'Decline')]"))
                    )
                    cookie_button.click()
                    logger.debug("Cookie banner dismissed")
                    time.sleep(1)
                except TimeoutException:
                    logger.debug("No cookie banner found")
                
                # Wait for submit button to be clickable
                submit_button = None
                submit_locators = [
                    (By.XPATH, "//button[@type='submit']"),
                    (By.XPATH, "//div[contains(text(), 'Log in')]"),
                    (By.CSS_SELECTOR, "button[type='submit']"),
                    (By.XPATH, "//button[contains(., 'Log in')]")
                ]
                for by, value in submit_locators:
                    try:
                        submit_button = WebDriverWait(driver, 10).until(
                            EC.element_to_be_clickable((by, value))
                        )
                        break
                    except TimeoutException:
                        continue
                
                if submit_button:
                    try:
                        # Try direct click
                        submit_button.click()
                        logger.debug("Submit button clicked directly")
                    except ElementClickInterceptedException:
                        # Fallback to JavaScript click
                        driver.execute_script("arguments[0].click();", submit_button)
                        logger.debug("Submit button clicked via JavaScript")
                    time.sleep(random.uniform(3, 5))
                else:
                    raise NoSuchElementException("Submit button not found")
                
                current_url = driver.current_url
                logger.debug(f"Current URL after submit: {current_url}")
                
                if "challenge" in current_url or "auth_platform/codeentry" in current_url:
                    logger.info("Challenge detected, redirecting to /challenge")
                    session["challenge_url"] = current_url
                    return redirect(url_for('challenge'))
                
                # Wait for post-login elements
                WebDriverWait(driver, 30).until(
                    EC.presence_of_element_located((
                        By.XPATH, 
                        "//span[contains(text(), 'Home')] | //a[contains(@href, '/explore/')] | //div[contains(text(), 'Your activity')]"
                    ))
                )
                logger.info("Instagram login successful")
                
                session_file = f"sessions/{instagram_username}_{user_id}.json"
                os.makedirs(os.path.dirname(session_file), exist_ok=True)
                cl = Client(request_timeout=15)
                try:
                    cl.login(instagram_username, instagram_password)
                    cl.dump_settings(session_file)
                    logger.info(f"Instagrapi session saved for {instagram_username} at {session_file}")
                except Exception as e:
                    logger.error(f"Failed to save instagrapi session for {instagram_username}: {str(e)}")
                    flash(f"Failed to save Instagram session: {str(e)}", "danger")
                    return redirect(url_for('dashboard'))

                conn = db_pool
                c = conn.cursor()
                new_credits = credits - credits_needed
                c.execute('UPDATE users SET credits = ? WHERE id = ?', (new_credits, user_id))
                c.execute('INSERT OR REPLACE INTO accounts (user_id, username, session_file, needs_reauth, has_sent_initial_dms, proxy_settings) VALUES (?, ?, ?, 0, 0, ?)',
                         (user_id, instagram_username, session_file, None))
                conn.commit()
                session['credits'] = new_credits
                client_key = f"{user_id}_{instagram_username}"
                clients[client_key] = cl
                logger.info(f"Account {instagram_username} added successfully for user_id {user_id}, credits deducted: {credits_needed}")
                flash(f"Instagram account '{instagram_username}' added successfully! {credits_needed} credits deducted. Remaining credits: {new_credits}", "success")
                return redirect(url_for('dashboard'))
            
            except TimeoutException as e:
                logger.error(f"Timeout waiting for elements: {str(e)}")
                if driver:
                    driver.save_screenshot("login_timeout.png")
                    with open("login_page_source.html", "w", encoding="utf-8") as f:
                        f.write(driver.page_source)
                    logger.debug("Saved login_timeout.png and login_page_source.html")
                flash(f"Timeout during Instagram login: {str(e)}", "danger")
                return redirect(url_for('dashboard'))
            except NoSuchElementException as e:
                logger.error(f"Element not found: {str(e)}")
                if driver:
                    driver.save_screenshot("login_element_not_found.png")
                    with open("login_page_source.html", "w", encoding="utf-8") as f:
                        f.write(driver.page_source)
                    logger.debug("Saved login_element_not_found.png and login_page_source.html")
                flash(f"Element not found during Instagram login: {str(e)}", "danger")
                return redirect(url_for('dashboard'))
            except ElementClickInterceptedException as e:
                logger.error(f"Click intercepted: {str(e)}")
                if driver:
                    driver.save_screenshot("login_click_intercepted.png")
                    with open("login_page_source.html", "w", encoding="utf-8") as f:
                        f.write(driver.page_source)
                    logger.debug("Saved login_click_intercepted.png and login_page_source.html")
                flash(f"Click intercepted during Instagram login: {str(e)}", "danger")
                return redirect(url_for('dashboard'))
            except WebDriverException as e:
                logger.error(f"WebDriver error: {str(e)}")
                if driver:
                    driver.save_screenshot("login_webdriver_error.png")
                    with open("login_page_source.html", "w", encoding="utf-8") as f:
                        f.write(driver.page_source)
                    logger.debug("Saved login_webdriver_error.png and login_page_source.html")
                flash(f"WebDriver error during Instagram login: {str(e)}", "danger")
                return redirect(url_for('dashboard'))
            except Exception as e:
                logger.error(f"Unexpected error: {str(e)}")
                if driver:
                    driver.save_screenshot("login_unexpected_error.png")
                    with open("login_page_source.html", "w", encoding="utf-8") as f:
                        f.write(driver.page_source)
                    logger.debug("Saved login_unexpected_error.png and login_page_source.html")
                flash(f"Unexpected error during Instagram login: {str(e)}", "danger")
                return redirect(url_for('dashboard'))
        
        finally:
            if "challenge_url" not in session and driver:
                try:
                    driver.quit()
                    logger.info(f"WebDriver closed for session {session.get('session_id')}")
                except Exception as e:
                    logger.error(f"Error closing WebDriver: {str(e)}")
                if session.get("session_id") in webdriver_instances:
                    del webdriver_instances[session.get("session_id")]
    
    logger.info("Rendering login.html")
    return render_template("login.html")

@app.route('/challenge', methods=['GET', 'POST'])
def challenge():
    if 'user_id' not in session:
        flash("Please log in to your CRM account first.", "danger")
        return redirect(url_for('user_login'))
    
    user_id = session['user_id']
    user_info = get_user_info(user_id)
    if not user_info:
        flash("User not found.", "danger")
        return redirect(url_for('dashboard'))
    plan, credits = user_info
    plan_configs = {
        'plan1': {'credits_per_account': 20},
        'plan2': {'credits_per_account': 30},
        'plan3': {'credits_per_account': 34}
    }
    credits_needed = plan_configs.get(plan, {}).get('credits_per_account', 20)

    if request.method == 'POST':
        code = request.form.get("code")
        if not code:
            logger.error("Verification code missing")
            flash("Verification code missing.", "danger")
            return render_template("challenge.html", challenge_url=session.get("challenge_url", ""))

        session_id = session.get("session_id")
        if not session_id or session_id not in webdriver_instances:
            logger.error("No WebDriver instance found for this session")
            flash("Session expired or invalid. Please start over.", "danger")
            return redirect(url_for('dashboard'))
        
        driver = webdriver_instances[session_id]
        instagram_username = session.get("instagram_username")
        instagram_password = session.get("instagram_password")
        try:
            logger.info(f"Submitting verification code: {code}")
            challenge_url = session.get("challenge_url")
            if not challenge_url:
                logger.error("No challenge URL in session")
                flash("No challenge data available.", "danger")
                return redirect(url_for('dashboard'))
            
            driver.get(challenge_url)
            WebDriverWait(driver, 15).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            logger.debug("Challenge page loaded")
            driver.save_screenshot("challenge_page_load.png")
            logger.debug("Screenshot saved: challenge_page_load.png")
            
            try:
                email_confirm_button = WebDriverWait(driver, 15).until(
                    EC.element_to_be_clickable((By.XPATH, "/html/body/div[1]/div/div/div[2]/div/div/div[1]/div[1]/div[2]/div/div/div/div/div[3]/div/div[2]/div/div/div"))
                )
                logger.debug("Email confirmation step detected, clicking Continue")
                email_confirm_button.click()
                WebDriverWait(driver, 20).until(
                    EC.presence_of_element_located((By.XPATH, "/html/body/div[1]/div/div/div[2]/div/div/div[1]/div[1]/div[2]/div/div/div/div/div[3]/div/form/div/div/div/div/div[1]/input"))
                )
                logger.debug("Transitioned to code entry page")
            except TimeoutException:
                logger.debug("No email confirmation step or already on code entry page")
            
            code_field = WebDriverWait(driver, 20).until(
                EC.element_to_be_clickable((By.XPATH, "/html/body/div[1]/div/div/div[2]/div/div/div[1]/div[1]/div[2]/div/div/div/div/div[3]/div/form/div/div/div/div/div[1]/input"))
            )
            logger.debug("Security code field found")
            code_field.clear()
            for char in code:
                code_field.send_keys(char)
                time.sleep(0.1)
            logger.debug(f"Entered code: {code}")
            driver.save_screenshot("challenge_code_entered.png")
            logger.debug("Screenshot saved: challenge_code_entered.png")
            
            submit_button = WebDriverWait(driver, 20).until(
                EC.element_to_be_clickable((By.XPATH, "/html/body/div[1]/div/div/div[2]/div/div/div[1]/div[1]/div[2]/div/div/div/div/div[3]/div/div[2]/div/div/div"))
            )
            logger.debug("Continue button found, clicking")
            submit_button.click()
            logger.debug("Challenge submit button clicked")
            driver.save_screenshot("challenge_submit_clicked.png")
            logger.debug("Screenshot saved: challenge_submit_clicked.png")
            
            try:
                WebDriverWait(driver, 45).until(
                    lambda d: "challenge" not in d.current_url and "auth_platform/codeentry" not in d.current_url
                )
                logger.debug(f"Redirected to: {driver.current_url}")
            except TimeoutException:
                try:
                    error_message = driver.find_element(By.XPATH, "//div[contains(text(), 'incorrect') or contains(text(), 'invalid') or contains(text(), 'try again')]")
                    logger.error(f"Challenge failed: {error_message.text}")
                    driver.save_screenshot("challenge_error.png")
                    logger.debug("Screenshot saved: challenge_error.png")
                    flash(f"Invalid code: {error_message.text}", "danger")
                    return render_template("challenge.html", challenge_url=challenge_url)
                except NoSuchElementException:
                    logger.error("Still on challenge page with no clear error message")
                    with open("challenge_page_source.html", "w", encoding="utf-8") as f:
                        f.write(driver.page_source)
                    driver.save_screenshot("challenge_timeout.png")
                    logger.debug("Page source saved: challenge_page_source.html")
                    logger.debug("Screenshot saved: challenge_timeout.png")
                    flash("Failed to verify code. Check challenge_page_source.html and challenge_timeout.png for details.", "danger")
                    return redirect(url_for('dashboard'))
            
            profile_url = f"https://www.instagram.com/{instagram_username}/"
            driver.get(profile_url)
            WebDriverWait(driver, 30).until(
                EC.presence_of_element_located((
                    By.XPATH, 
                    "//header//h2 | //span[contains(text(), 'Home')] | //div[contains(@aria-label, 'Profile')]"
                ))
            )
            logger.info("Instagram login successful, profile page loaded")
            driver.save_screenshot("profile_success.png")
            logger.debug("Screenshot saved: profile_success.png")
            
            session_file = f"sessions/{instagram_username}_{user_id}.json"
            os.makedirs(os.path.dirname(session_file), exist_ok=True)
            cl = Client(request_timeout=15)
            try:
                cl.login(instagram_username, instagram_password)
                cl.dump_settings(session_file)
                logger.info(f"Instagrapi session saved for {instagram_username} at {session_file}")
            except Exception as e:
                logger.error(f"Failed to save instagrapi session for {instagram_username}: {str(e)}")
                flash(f"Failed to save Instagram session: {str(e)}", "danger")
                return redirect(url_for('dashboard'))

            conn = db_pool
            c = conn.cursor()
            new_credits = credits - credits_needed
            c.execute('UPDATE users SET credits = ? WHERE id = ?', (new_credits, user_id))
            c.execute('INSERT OR REPLACE INTO accounts (user_id, username, session_file, needs_reauth, has_sent_initial_dms, proxy_settings) VALUES (?, ?, ?, 0, 0, ?)',
                     (user_id, instagram_username, session_file, None))
            conn.commit()
            session['credits'] = new_credits
            client_key = f"{user_id}_{instagram_username}"
            clients[client_key] = cl
            logger.info(f"Account {instagram_username} added successfully for user_id {user_id}, credits deducted: {credits_needed}")
            flash(f"Instagram account '{instagram_username}' added successfully! {credits_needed} credits deducted. Remaining credits: {new_credits}", "success")
            return redirect(url_for('dashboard'))
        
        except TimeoutException as e:
            logger.error(f"Timeout in challenge: {str(e)}")
            logger.debug(f"Current URL: {driver.current_url}")
            logger.debug(f"Page source: {driver.page_source[:1000]}")
            driver.save_screenshot("challenge_timeout_exception.png")
            logger.debug("Screenshot saved: challenge_timeout_exception.png")
            flash(f"Timeout during challenge: {str(e)}", "danger")
            return redirect(url_for('dashboard'))
        except NoSuchElementException as e:
            logger.error(f"Challenge element not found: {str(e)}")
            logger.debug(f"Current URL: {driver.current_url}")
            logger.debug(f"Page source: {driver.page_source[:1000]}")
            driver.save_screenshot("challenge_element_not_found.png")
            logger.debug("Screenshot saved: challenge_element_not_found.png")
            flash(f"Challenge element not found: {str(e)}", "danger")
            return redirect(url_for('dashboard'))
        except WebDriverException as e:
            logger.error(f"WebDriver error in challenge: {str(e)}")
            driver.save_screenshot("challenge_webdriver_error.png")
            logger.debug("Screenshot saved: challenge_webdriver_error.png")
            flash(f"WebDriver error: {str(e)}", "danger")
            return redirect(url_for('dashboard'))
        except Exception as e:
            logger.error(f"Unexpected error in challenge: {str(e)}")
            driver.save_screenshot("challenge_unexpected_error.png")
            logger.debug("Screenshot saved: challenge_unexpected_error.png")
            flash(f"Unexpected error: {str(e)}", "danger")
            return redirect(url_for('dashboard'))
        
        finally:
            driver.quit()
            if session_id in webdriver_instances:
                del webdriver_instances[session_id]
            session.pop("session_id", None)
            session.pop("challenge_url", None)
            session.pop("instagram_username", None)
            session.pop("instagram_password", None)
    
    logger.info("Rendering challenge.html")
    return render_template("challenge.html", challenge_url=session.get("challenge_url", ""))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    session.pop('credits', None)
    session.pop('plan', None)
    flash("You have been logged out.", "success")
    return redirect(url_for('user_login'))

@app.route('/admin/users', methods=['GET', 'POST'])
@admin_required
def admin_users():
    conn = db_pool
    c = conn.cursor()
    
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'create':
            username = request.form.get('username')
            password = request.form.get('password')
            if not username or not password:
                flash("Username and password are required.", "danger")
            else:
                hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                try:
                    c.execute('INSERT INTO users (username, password_hash, role, credits, plan) VALUES (?, ?, ?, ?, ?)',
                              (username, hashed_password, 'customer', 0, ''))
                    conn.commit()
                    flash(f"User {username} created successfully.", "success")
                except sqlite3.IntegrityError:
                    flash("Username already exists.", "danger")
        elif action == 'delete':
            user_id = request.form.get('user_id')
            c.execute('DELETE FROM users WHERE id = ? AND role != ?', (user_id, 'admin'))
            conn.commit()
            flash("User deleted successfully.", "success")
        elif action == 'assign_plan':
            user_id = request.form.get('user_id')
            plan = request.form.get('plan')
            plan_configs = {
                'plan1': {'credits': 100, 'max_accounts': 5, 'credits_per_account': 20, 'credits_per_dm': 1},
                'plan2': {'credits': 300, 'max_accounts': 10, 'credits_per_account': 30, 'credits_per_dm': 1},
                'plan3': {'credits': 500, 'max_accounts': 15, 'credits_per_account': 34, 'credits_per_dm': 1}
            }
            if plan in plan_configs:
                c.execute('UPDATE users SET plan = ?, credits = ? WHERE id = ? AND role != ?',
                          (plan, plan_configs[plan]['credits'], user_id, 'admin'))
                conn.commit()
                flash(f"Plan {plan} assigned to user ID {user_id}.", "success")
            else:
                flash("Invalid plan selected.", "danger")

    c.execute('SELECT id, username, role, credits, plan FROM users')
    users = c.fetchall()

    return render_template('admin_users.html', users=users)

@app.route('/get-logs', methods=['GET'])
@login_required
def get_logs():
    log_entries = []
    if os.path.exists('crm.log'):
        with open('crm.log', 'r', encoding='utf-8') as log_file:
            log_entries = log_file.readlines()[-20:]
    return jsonify({'logs': log_entries})

@app.route('/dashboard', defaults={'selected_account': None})
@app.route('/dashboard/<selected_account>')
@login_required
def dashboard(selected_account):
    user_id = session['user_id']
    role = session['role']
    accounts = get_accounts(user_id, role)
    for username, needs_reauth in accounts:
        if needs_reauth:
            flash(f"Session for {username} has expired. Please re-authenticate the account.", "danger")
    valid_usernames = [acc[0] for acc in accounts]
    if selected_account and selected_account not in valid_usernames:
        flash("Invalid account selected.", "danger")
        selected_account = None
    user_info = get_user_info(user_id)
    credits, plan = user_info if user_info else (0, '')
    log_entries = []
    if os.path.exists('crm.log'):
        with open('crm.log', 'r', encoding='utf-8') as log_file:
            log_entries = log_file.readlines()[-10:]
    return render_template('dashboard.html', accounts=accounts, selected_account=selected_account, credits=credits, plan=plan, log_entries=log_entries, dm_count=dm_count)

@app.route('/send-dms', methods=['GET', 'POST'])
@login_required
def send_dms():
    global initial_messages, dm_count, initial_dms_sent
    user_id = session['user_id']
    role = session['role']
    accounts = get_accounts(user_id, role)
    if request.method == 'POST':
        account = request.form.get('account')
        usernames_file = request.files.get('usernames')
        messages_file = request.files.get('messages')
        num_messages = request.form.get('num_messages', '1')
        try:
            num_messages = max(1, min(10, int(num_messages)))
        except ValueError:
            num_messages = 1
            flash("Invalid number of messages. Using default value of 1.", "warning")
        if not account or not usernames_file or not messages_file:
            flash("Account, usernames file, and messages file are required.", "danger")
            return render_template('dashboard.html', accounts=accounts)
        conn = db_pool
        c = conn.cursor()
        c.execute('SELECT id FROM accounts WHERE username = ?' + (' AND user_id = ?' if role != 'admin' else ''),
                  (account, user_id) if role != 'admin' else (account,))
        account_id = c.fetchone()
        if not account_id:
            flash("Invalid account selected.", "danger")
            return render_template('dashboard.html', accounts=accounts)
        account_id = account_id[0]
        user_info = get_user_info(user_id)
        if not user_info:
            flash("User not found.", "danger")
            return render_template('dashboard.html', accounts=accounts)
        plan, credits = user_info
        plan_configs = {
            'plan1': {'credits_per_dm': 1},
            'plan2': {'credits_per_dm': 1},
            'plan3': {'credits_per_dm': 1}
        }
        if not plan or plan not in plan_configs:
            flash("You must have an active plan to send DMs.", "danger")
            return render_template('dashboard.html', accounts=accounts)
        try:
            usernames = usernames_file.read().decode('utf-8').strip().splitlines()
            usernames = [u.strip() for u in usernames if u.strip()]
        except Exception as e:
            flash(f"Failed to read usernames file: {str(e)}", "danger")
            return render_template('dashboard.html', accounts=accounts)
        try:
            messages_raw = messages_file.read().decode('utf-8').strip()
            try:
                messages_json = json.loads(messages_raw)
                if isinstance(messages_json, dict):
                    initial_messages = [messages_json.get("text", messages_json.get("message", messages_raw.strip()))] * num_messages
                elif isinstance(messages_json, list):
                    initial_messages = [msg.get("text", msg.get("message", "")) for msg in messages_json if "text" in msg or "message" in msg]
                    if len(initial_messages) < num_messages:
                        initial_messages = initial_messages * (num_messages // len(initial_messages)) + initial_messages[:num_messages % len(initial_messages)]
                    initial_messages = initial_messages[:num_messages]
                else:
                    initial_messages = [messages_raw.strip()] * num_messages
            except json.JSONDecodeError:
                initial_messages = [messages_raw.strip()] * num_messages
            if not initial_messages or not all(m.strip() for m in initial_messages):
                flash("Messages file must contain valid message content.", "danger")
                return render_template('dashboard.html', accounts=accounts)
        except Exception as e:
            flash(f"Failed to read messages file: {str(e)}", "danger")
            return render_template('dashboard.html', accounts=accounts)
        credits_needed = len(usernames) * plan_configs[plan]['credits_per_dm']
        if credits < credits_needed:
            flash(f"Insufficient credits. You need {credits_needed} credits to send {len(usernames)} DMs, but you have {credits}.", "danger")
            return render_template('dashboard.html', accounts=accounts)
        cl = get_client(user_id if role != 'admin' else 0, account)
        if not cl:
            flash(f"Cannot send DMs for {account}: Session expired.", "danger")
            return render_template('dashboard.html', accounts=accounts)
        sent_count = 0
        current_timestamp = int(time.time())
        try:
            for username in usernames:
                try:
                    user_id_target = cl.user_id_from_username(username)
                    message = initial_messages[sent_count % len(initial_messages)]
                    cl.direct_send(message, [user_id_target])
                    c = execute_with_retry(c, 
                        'INSERT OR REPLACE INTO initial_dms (account_id, username, sent_timestamp) VALUES (?, ?, ?)',
                        (account_id, username, current_timestamp))
                    sent_count += 1
                    dm_count += 1
                    logger.info(f"Sent initial DM to {username} from {account} (user_id {user_id}): {message}")
                    time.sleep(0.2)
                except Exception as e:
                    logger.error(f"Failed to send DM to {username} from {account}: {str(e)}")
                    flash(f"Failed to send DM to {username}: {str(e)}", "warning")
            c.execute('UPDATE accounts SET has_sent_initial_dms = 1 WHERE id = ?', (account_id,))
            new_credits = credits - (sent_count * plan_configs[plan]['credits_per_dm'])
            c.execute('UPDATE users SET credits = ? WHERE id = ?', (new_credits, user_id))
            conn.commit()
            session['credits'] = new_credits
            initial_dms_sent = True
            if sent_count > 0:
                flash(f"Sent {sent_count} DMs successfully! {sent_count * plan_configs[plan]['credits_per_dm']} credits deducted. Remaining credits: {new_credits}", "success")
                flash(f"Total DMs sent so far: {dm_count}", "info")
            else:
                flash("No DMs sent.", "info")
        except Exception as e:
            logger.error(f"Error sending DMs: {str(e)}")
            flash(f"Error sending DMs: {str(e)}", "danger")
        return redirect(url_for('dashboard'))
    return render_template('dashboard.html', accounts=accounts)

if __name__ == '__main__':
    init_db()
    Thread(target=auto_respond, daemon=True).start()
    app.run(debug=True, host='0.0.0.0', port=5000)
