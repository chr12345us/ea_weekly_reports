import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
import os
from datetime import datetime


def get_project_root():
    """
    Get the project root directory (ea_weekly_reports).
    Works regardless of where the script is executed from.
    """
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # If we're in script_files, go up one level to get to project root
    if os.path.basename(script_dir) == 'script_files':
        return os.path.dirname(script_dir)
    else:
        # If we're already in project root
        return script_dir


def send_weekly_email(cust_id: str, week_end_date: str, email_config: dict) -> bool:
    """
    Send weekly report email with CSV and HTML attachments.
    
    Args:
        cust_id: Customer identifier (e.g., "EA")
        week_end_date: Week end date in YYYY-MM-DD format
        email_config: Dictionary containing email configuration:
            - smtp_host: SMTP server host
            - smtp_port: SMTP server port
            - email_user: Email username
            - email_pass: Email password
            - from_email: From email address
            - to_emails: List of recipient emails
            - subject: Email subject
            
    Returns:
        True if email sent successfully, False otherwise
    """
    try:
        project_root = get_project_root()
        
        # Generate file paths using absolute paths
        report_dir = os.path.join(project_root, "report_files", cust_id)
        csv_filename = f"weekly_trends_{week_end_date}.csv"
        html_filename = f"weekly_trends_chart_{week_end_date}.html"
        csv_path = os.path.join(report_dir, csv_filename)
        html_path = os.path.join(report_dir, html_filename)
        
        print(f"Project root: {project_root}")
        print(f"Looking for files in: {report_dir}")
        
        # Check if files exist
        if not os.path.exists(csv_path):
            print(f"CSV file not found: {csv_path}")
            return False
        if not os.path.exists(html_path):
            print(f"HTML file not found: {html_path}")
            return False
        
        # Create message container
        msg = MIMEMultipart()
        msg['From'] = email_config['from_email']
        msg['To'] = ', '.join(email_config['to_emails'])
        msg['Subject'] = email_config['subject']
        
        # Email body
        body = f"""
{cust_id}: Weekly Attack Trends Report

Week End Date: {week_end_date}

Please find attached:
- CSV data file: {csv_filename}
- HTML chart file: {html_filename}

Best regards,
Radware Automated Reporting System
"""
        msg.attach(MIMEText(body, 'plain'))
        
        # Attach CSV file
        print(f"Attaching CSV file: {csv_path}")
        with open(csv_path, "rb") as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
        
        encoders.encode_base64(part)
        part.add_header(
            'Content-Disposition',
            f'attachment; filename= {csv_filename}'
        )
        msg.attach(part)
        
        # Attach HTML file
        print(f"Attaching HTML file: {html_path}")
        with open(html_path, "rb") as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
        
        encoders.encode_base64(part)
        part.add_header(
            'Content-Disposition',
            f'attachment; filename= {html_filename}'
        )
        msg.attach(part)
        
        # Connect to server and send email
        print(f"Connecting to SMTP server: {email_config['smtp_host']}:{email_config['smtp_port']}")
        server = smtplib.SMTP(email_config['smtp_host'], email_config['smtp_port'])
        
        # Enable TLS if configured
        use_tls = email_config.get('use_tls', True)  # Default to True for backward compatibility
        print(f"DEBUG: use_tls value from config: {use_tls}")
        print(f"DEBUG: email_config keys: {list(email_config.keys())}")
        if use_tls:
            print("Enabling TLS...")
            server.starttls()
        else:
            print("TLS disabled")
        
        # Authenticate if configured
        use_auth = email_config.get('use_authentication', True)  # Default to True for backward compatibility
        print(f"DEBUG: use_authentication value from config: {use_auth}")
        if use_auth:
            print("Authenticating with SMTP server...")
            server.login(email_config['email_user'], email_config['email_pass'])
        else:
            print("Authentication disabled")
        
        text = msg.as_string()
        server.sendmail(email_config['from_email'], email_config['to_emails'], text)
        server.quit()
        
        print(f"Email sent successfully to: {', '.join(email_config['to_emails'])}")
        return True
        
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


# For backward compatibility when run directly
if __name__ == '__main__':
    # Default configuration for direct execution
    cust_id = "EA"
    week_end_date = datetime.now().strftime('%Y-%m-%d')
    
    email_config = {
        'smtp_host': 'smtp.gmail.com',
        'smtp_port': 587,
        'email_user': 'your_email@gmail.com',
        'email_pass': 'your_app_password',
        'from_email': 'your_email@gmail.com',
        'to_emails': ['recipient@example.com'],
        'subject': f'Weekly Attack Trends Report - {cust_id} - Week Ending {week_end_date}'
    }
    
    success = send_weekly_email(cust_id, week_end_date, email_config)
    if not success:
        exit(1)
