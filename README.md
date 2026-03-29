# Anomaly-Detection
This project uses machine learning to detect unusual login activities based on user behavior patterns. Instead of blocking access, the system sends real-time alerts to the security team — ensuring legitimate but uncommon actions (e.g., travel, emergencies) are still permitted while being closely monitored.

The system is built with:

    --> Backend (ML model) → Isolation Forest (unsupervised anomaly detection).
    --> Frontend (Streamlit app) → Visualizes anomalies interactively.
    --> Email Notifications → Sends alerts + CSV reports of anomalies.
    --> Database (Postgres) → Stores anomalies for historical tracking.

# Features 
    --> Upload login activity CSV and detect anomalies in real-time.
    --> Isolation Forest assigns both anomaly score and anomaly flag.
    --> Interactive Streamlit dashboard for visualization.
    --> Anomalies automatically saved to PostgreSQL (managed via Adminer).
    --> Automated email alerts with attached CSV of anomalies.

# Workflow

User Login Events
           
    CSV input contains login records (IP address, timestamp, location, etc.).

Anomaly Detection

    The ML model (IsolationForest) learns normal login patterns.
    Assigns each login an anomaly score and an anomaly flag (0 = normal, 1 = anomaly).

Detected Anomalies are:

    Stored in PostgreSQL for persistence
    Emailed to security team (HTML + CSV report)
    Displayed in Streamlit with filtering & anomaly highlighting

# Tech Stack

    Python (Pandas, Scikit-learn, SQLAlchemy)
    Streamlit (frontend dashboard)
    PostgreSQL + Adminer – Database and management
    SMTP (Gmail for email alerts)
    Altair (visualizations)

# Output Screenshots
## ML Output
     
    The ML model assigns an anomaly score & flag for each login event. 
![ML Output](https://github.com/LEO-FRANCIS-A/Anomaly-Detection/blob/main/Screenshots/anomaly_ml.png?raw=true)

## Frontend Output
![Frontend Output](https://github.com/LEO-FRANCIS-A/Anomaly-Detection/blob/main/Screenshots/Anomaly%20Frontend.png?raw=true)

## PostgreSQL Database View (via Adminer)
![Adminer Database View](https://github.com/LEO-FRANCIS-A/Anomaly-Detection/blob/main/Screenshots/Anomaly%20Adminer.png?raw=true)

## Email notification sent to the security team, including a summary and CSV attachment of anomalies.  
![Email Alert](https://github.com/LEO-FRANCIS-A/Anomaly-Detection/blob/main/Screenshots/email_alert.png?raw=true)

# Installation & Setup
## Clone the Repository
    git clone https://github.com/LEO-FRANCIS-A/Anomaly-Detection.git
    cd Anomaly-Detection

## Backend Setup (Machine Learning + API)

Go to backend folder:

    cd backend

Create a Virtual Environment
   
    python -m venv venv
    source venv/bin/activate   # On Linux/Mac
    venv\Scripts\activate      # On Windows

Install Dependencies

    pip install -r requirements.txt

Run the ML pipeline / backend service:

    python3 machine.py

## Frontend & Database Setup 

Go to Frontend&Database folder:

    cd ../Frontend&Database

Create a Virtual Environment by following the steps which is given above (if not already created) 
Install dependencies (if not already installed in backend):

    pip install -r requirements.txt

Database Setup (PostgreSQL + Adminer)
Make sure you have a PostgreSQL instance running (cloud or local).
Connection string format:
   
    postgresql://<username>:<password>@<host>:<port>/<database_name>

Email Alerts Setup
Enable App Passwords for your Gmail (or use another SMTP provider).
Add your credentials in the code:
        
    EMAIL_ADDRESS = "your_email@gmail.com"
    EMAIL_PASSWORD = "your_app_password"
    TO_EMAIL = "recipient@gmail.com"

Run Streamlit app

    Streamlit run frontend_database.py

## Future Improvements

    Add role-based access control in frontend
    Deploy backend + frontend on Docker
    Real-time anomaly detection (instead of batch CSV upload)
    Multi-dataset support

## License

    This project is licensed under the MIT License.

