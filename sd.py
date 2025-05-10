from flask import Flask, request, jsonify, render_template
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import os
import json
import logging
import logging.handlers

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
handler = logging.handlers.RotatingFileHandler('app.log', maxBytes=1000000, backupCount=5)
handler.setLevel(logging.INFO)
app = Flask(__name__)
app.logger.addHandler(handler)

# Ensure sessions folder exists
if not os.path.exists('sessions'):
    os.makedirs('sessions')
    app.logger.info("Created sessions directory")

@app.route('/')
def index():
    return jsonify({"message": "Flask server is running. Access /add-account-page to log in."})

@app.route('/add-account-page')
def add_account_page():
    return render_template('add_account.html')

@app.route('/get_logs')
def get_logs():
    try:
        with open('app.log', 'r') as f:
            logs = f.readlines()[-10:]  # Last 10 lines
        return jsonify({"logs": logs})
    except:
        return jsonify({"logs": []})

@app.route('/dashboard')
def dashboard():
    return jsonify({"message": "Dashboard placeholder"})

@app.route('/add-account', methods=['POST'])
def add_account():
    username = request.form.get('username')
    password = request.form.get('password')
    proxy_host = request.form.get('proxy_host')
    proxy_port = request.form.get('proxy_port')
    proxy_username = request.form.get('proxy_username')
    proxy_password = request.form.get('proxy_password')

    app.logger.info(f"Attempting login for {username}")

    # Set up Selenium with proxy
    chrome_options = Options()
    chrome_options.add_argument('--headless')  # Run in background
    if proxy_host and proxy_port:
        proxy = f"{proxy_username}:{proxy_password}@{proxy_host}:{proxy_port}" if proxy_username and proxy_password else f"{proxy_host}:{proxy_port}"
        chrome_options.add_argument(f'--proxy-server=http://{proxy}')
        app.logger.info(f"Using proxy: {proxy}")

    try:
        driver = webdriver.Chrome(ChromeDriverManager().install(), options=chrome_options)
    except Exception as e:
        app.logger.error(f"Failed to initialize ChromeDriver: {str(e)}")
        return jsonify({"success": False, "message": f"ChromeDriver error: {str(e)}"})

    try:
        driver.get("https://www.instagram.com/accounts/login/")
        app.logger.info("Loaded Instagram login page")

        # Fill login form
        WebDriverWait(driver, 20).until(EC.presence_of_element_located((By.NAME, "username")))
        driver.find_element(By.NAME, "username").send_keys(username)
        driver.find_element(By.NAME, "password").send_keys(password)
        driver.find_element(By.XPATH, "//button[@type='submit']").click()
        app.logger.info("Submitted login form")

        # Check for verification prompt
        try:
            WebDriverWait(driver, 20).until(
                EC.presence_of_element_located((By.NAME, "verificationCode"))
            )
            app.logger.info("Verification code prompt detected")
            return jsonify({
                "success": False,
                "challenge_required": True,
                "verification_type": "challenge",
                "username": username,
                "message": "Instagram requires email verification. Please enter the 6-digit code sent to your email."
            })
        except:
            # Assume login successful if no verification prompt
            app.logger.info("No verification prompt; assuming login successful")
            cookies = driver.get_cookies()
            with open(f"sessions/{username}.json", "w") as f:
                json.dump(cookies, f)
            return jsonify({"success": True, "message": "Login successful"})
    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({"success": False, "message": f"Login failed: {str(e)}"})
    finally:
        driver.quit()
        app.logger.info("Closed Selenium driver")

@app.route('/verify-code', methods=['POST'])
def verify_code():
    code = request.form.get('verification_code')
    username = request.form.get('username')  # Pass username from front-end
    if not username or not code:
        app.logger.error("Missing username or verification code")
        return jsonify({"success": False, "message": "Username and verification code are required"})

    app.logger.info(f"Verifying code for {username}")

    chrome_options = Options()
    chrome_options.add_argument('--headless')
    try:
        driver = webdriver.Chrome(ChromeDriverManager().install(), options=chrome_options)
    except Exception as e:
        app.logger.error(f"Failed to initialize ChromeDriver: {str(e)}")
        return jsonify({"success": False, "message": f"ChromeDriver error: {str(e)}"})

    try:
        driver.get("https://www.instagram.com/accounts/login/")
        # Load cookies if available
        if os.path.exists(f"sessions/{username}.json"):
            with open(f"sessions/{username}.json", "r") as f:
                cookies = json.load(f)
            for cookie in cookies:
                driver.add_cookie(cookie)
            driver.refresh()
            app.logger.info("Loaded session cookies")

        # Enter verification code
        WebDriverWait(driver, 20).until(EC.presence_of_element_located((By.NAME, "verificationCode")))
        driver.find_element(By.NAME, "verificationCode").send_keys(code)
        driver.find_element(By.XPATH, "//button[@type='submit']").click()
        app.logger.info("Submitted verification code")

        # Check if login succeeded
        WebDriverWait(driver, 20).until(EC.url_contains("instagram.com"))
        cookies = driver.get_cookies()
        with open(f"sessions/{username}.json", "w") as f:
            json.dump(cookies, f)
        app.logger.info("Login successful after verification")
        return jsonify({"success": True, "message": "Verification successful"})
    except Exception as e:
        app.logger.error(f"Verification error: {str(e)}")
        return jsonify({"success": False, "message": "Invalid verification code or session expired"})
    finally:
        driver.quit()
        app.logger.info("Closed Selenium driver")

if __name__ == '__main__':
    import webbrowser
    webbrowser.open('http://localhost:5000/add-account-page')
    app.run(host='0.0.0.0', port=5000, debug=True)