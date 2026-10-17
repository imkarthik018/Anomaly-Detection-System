# Anomaly Detection System

An intelligent, machine-learning-based security monitoring system that detects unusual login activities by analyzing user behavior patterns. The system identifies suspicious login events and sends real-time-style email alerts to the security team without automatically blocking users, helping security teams investigate anomalies while minimizing disruption to legitimate users.

## Overview

The system uses the **Isolation Forest** algorithm to identify anomalous login activity. Detected anomalies are visualized through an interactive Streamlit dashboard, stored in PostgreSQL for historical tracking, and reported to the security team through email notifications with CSV attachments.

## Key Features

- **Machine Learning Detection:** Uses Isolation Forest for unsupervised anomaly detection.
- **CSV Upload:** Accepts login activity datasets for analysis.
- **Anomaly Scoring:** Generates anomaly scores and flags unusual login events.
- **Interactive Dashboard:** Visualizes login activity and highlights detected anomalies using Streamlit.
- **Database Integration:** Stores detected anomalies in PostgreSQL for historical analysis.
- **Email Notifications:** Sends anomaly reports to the security team with CSV attachments.
- **Database Management:** Supports database inspection and management through Adminer.

## System Workflow

1. **Input Data:** Upload a CSV file containing login activity, such as IP addresses, timestamps, locations, and other available login attributes.
2. **Data Processing:** Load and preprocess the login records using Python and Pandas.
3. **Anomaly Detection:** Apply the Isolation Forest model to identify login events that differ from learned patterns.
4. **Result Generation:** Produce anomaly scores and classification flags for the analyzed records.
5. **Data Persistence:** Save detected anomalies to PostgreSQL.
6. **Visualization:** Display results in the Streamlit dashboard with anomaly highlighting and filtering.
7. **Email Alerts:** Send an email summary and CSV report of detected anomalies to the designated security team.

## Technology Stack

| Component | Technology |
|---|---|
| Programming Language | Python |
| Machine Learning | Scikit-learn, Isolation Forest |
| Data Processing | Pandas |
| Dashboard | Streamlit |
| Database | PostgreSQL |
| Database Administration | Adminer |
| Database Connectivity | SQLAlchemy |
| Visualization | Altair |
| Email Notifications | SMTP (Gmail or compatible provider) |

## Screenshots

### 1. Machine Learning Output

The model produces anomaly scores and flags for login events.

![Machine Learning Output](https://github.com/imkarthik018/Anomaly-Detection-main/blob/main/Screenshots/anomaly_ml.png?raw=true)

### 2. Streamlit Dashboard

Interactive visualization of login activity and detected anomalies.

![Streamlit Dashboard](https://github.com/imkarthik018/Anomaly-Detection-main/blob/main/Screenshots/Anomaly%20Frontend.png?raw=true)

### 3. PostgreSQL Database

Historical anomaly records viewed through Adminer.

![PostgreSQL Database View](https://github.com/imkarthik018/Anomaly-Detection-main/blob/main/Screenshots/Anomaly%20Adminer.png?raw=true)

### 4. Email Notifications

Email alerts containing a summary of detected anomalies and a CSV report.

![Email Alert](https://github.com/imkarthik018/Anomaly-Detection-main/blob/main/Screenshots/email_alert.png?raw=true)

## Installation and Setup

### Prerequisites

- Python 3
- pip
- PostgreSQL
- Adminer (optional, for database management)
- Gmail account with an app password, or another SMTP provider

### 1. Clone the Repository

```bash
git clone https://github.com/imkarthik018/Anomaly-Detection-main.git
cd Anomaly-Detection-main
```

### 2. Set Up the Backend

Navigate to the backend directory:

```bash
cd backend
```

Create and activate a virtual environment.

**Windows:**

```bash
python -m venv venv
venv\Scripts\activate
```

**Linux/macOS:**

```bash
python3 -m venv venv
source venv/bin/activate
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

Run the machine learning pipeline:

```bash
python machine.py
```

> Ensure you are using the correct entry point and working directory for your implementation.

### 3. Configure the Database

Make sure your PostgreSQL instance is running and create the required database.

Use a connection string in the following format:

```text
postgresql://<username>:<password>@<host>:<port>/<database_name>
```

Configure the database connection in your application using environment variables or a local configuration file, as supported by your code.

Adminer can be used to inspect and manage the database.

### 4. Configure Email Notifications

Configure the SMTP credentials and recipient address for email alerts.

For Gmail, generate an app password if required. **Do not use your regular Gmail password or commit email credentials to GitHub.**

For example, use environment variables:

```text
EMAIL_ADDRESS=your_email@gmail.com
EMAIL_PASSWORD=your_app_password
TO_EMAIL=recipient@gmail.com
```

Update your application to read these variables if it does not already support environment-based configuration.

### 5. Run the Streamlit Dashboard

From the repository root, navigate to the frontend and database directory:

```bash
cd "Frontend&Database"
```

Activate the appropriate virtual environment and install the required dependencies if necessary.

Run the dashboard:

```bash
streamlit run frontend_database.py
```

Open the local URL displayed in your terminal to access the dashboard.

> Follow the actual directory structure and configuration files in your repository if they differ from these instructions.

## Future Enhancements

- Role-based access control for dashboard users.
- Docker-based deployment for easier setup and portability.
- Continuous monitoring of incoming login events.
- Support for multiple datasets and additional anomaly detection algorithms.
- Improved model evaluation, threshold tuning, and anomaly explanations.
- Enhanced security, logging, and monitoring capabilities.

## License

Review the original project's license before distributing this adapted version. Retain applicable copyright notices and comply with the original license terms. Add or update a `LICENSE` file only when its contents accurately reflect the rights and terms applicable to this repository.

## Acknowledgments

This project was adapted from an existing anomaly detection implementation and further modified for its current use case. Original authors and source repositories should be credited in accordance with the original project's license and attribution requirements.

## Author

**Karthik**

GitHub: [@imkarthik018](https://github.com/imkarthik018)
