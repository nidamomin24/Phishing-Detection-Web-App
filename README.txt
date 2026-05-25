Final Phishing URL Detection Project (with Login + PDF Report + MySQL)
---
Quick start:
1. Install requirements: pip install -r requirements.txt
2. Create MySQL database and tables by running db_setup.sql (or run commands manually)
3. Train model: python train_model.py  (creates phishing_model.pkl)
4. Run app: python app.py
5. Open: http://127.0.0.1:5000
Notes:
- Add VT_API_KEY and DB credentials in a .env file or set as environment variables:
  DB_HOST, DB_USER, DB_PASS, DB_NAME, VT_API_KEY, FLASK_SECRET
- Use /register to create an admin user (set role=admin)