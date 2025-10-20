#!/usr/bin/env python3
"""
Main Weekly Reports Script - Import-based Architecture with INI Configuration
This script reads configuration from INI file and orchestrates the weekly attack reports
"""

import sys
import os
import configparser
from datetime import datetime

# Since main_weekly.py is now in script_files directory alongside the other modules,
# we can import them directly without path manipulation

# Import our modules
try:
    import weekly_reports
    import email_send_weekly
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure weekly_reports.py and email_send_weekly.py are in the same directory as main_weekly.py")
    sys.exit(1)


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


def load_configuration():
    """
    Load configuration from INI file.
    """
    project_root = get_project_root()
    config_file_path = os.path.join(project_root, 'config_files', 'weekly_config.ini')
    
    try:
        config = configparser.ConfigParser()
        config.read(config_file_path)
        print(f"✓ Configuration loaded from: {os.path.relpath(config_file_path, project_root)}")
        return config
    except FileNotFoundError:
        print(f"ERROR: Configuration file not found: {config_file_path}")
        sys.exit(1)
    except configparser.Error as e:
        print(f"ERROR: Invalid INI format in configuration file: {e}")
        sys.exit(1)


def main():
    """
    Main function that orchestrates the weekly reporting process.
    Configuration is loaded from JSON file.
    """
    print("=" * 60)
    print("WEEKLY ATTACK TRENDS REPORT - INI-BASED CONFIGURATION")
    print("=" * 60)
    print()
    
    # Show where we're running from
    project_root = get_project_root()
    print(f"Project root directory: {project_root}")
    print(f"Current working directory: {os.getcwd()}")
    print()
    
    # ================================
    # LOAD CONFIGURATION FROM INI
    # ================================
    
    config = load_configuration()
    
    # Extract configuration sections
    weekly_config = config['weekly_reports']
    email_config = config['email']
    global_config = config['global']
    
    # Debug: Print the email config values
    print(f"DEBUG: email_config from INI: {dict(email_config)}")
    print(f"DEBUG: use_tls from INI: {email_config.get('use_tls', 'NOT_FOUND')}")
    print(f"DEBUG: use_authentication from INI: {email_config.get('use_authentication', 'NOT_FOUND')}")
    print()
    
    # Handle current date override from global config
    current_date = datetime.now()  # Default to current time
    if global_config.get('cur_date'):
        try:
            # Parse the date format from global config
            date_format = global_config.get('datetime_format', '%Y-%m-%d %H:%M:%S')
            current_date = datetime.strptime(global_config.get('cur_date'), date_format)
            print(f"DEBUG: Using override date from config: {current_date}")
        except ValueError as e:
            print(f"WARNING: Invalid cur_date format in config: {e}")
            print("Using current datetime instead.")
            current_date = datetime.now()
    else:
        print(f"DEBUG: Using current datetime: {current_date}")
    print()
    
    # Core Report Configuration
    REPORT_CONFIG = {
        'CUST_ID': weekly_config.get('CUST_ID', 'EA'),
        'WEEK_END_DAY': weekly_config.getint('WEEK_END_DAY', 6),  # Sunday = 6 (0=Monday, 6=Sunday)
        'WEEKS_NO': weekly_config.getint('WEEKS_NO', 6),          # Number of weeks to include in report
        'CURRENT_DATE': current_date
    }
    
    # Email Configuration
    EMAIL_CONFIG = {
        'smtp_host': email_config.get('smtp_host', 'smtp.gmail.com'),
        'smtp_port': email_config.getint('smtp_port', 587),
        'email_user': email_config.get('email_user', ''),
        'email_pass': email_config.get('email_pass', ''),
        'from_email': email_config.get('from_email', ''),
        'to_emails': email_config.get('to_emails', '').split(','),
        'use_authentication': email_config.getboolean('use_authentication', True),
        'use_tls': email_config.getboolean('use_tls', True),
        'subject': None  # Will be set dynamically using template
    }
    
    # Debug: Print the final EMAIL_CONFIG
    print(f"DEBUG: Final EMAIL_CONFIG use_tls: {EMAIL_CONFIG['use_tls']}")
    print(f"DEBUG: Final EMAIL_CONFIG use_authentication: {EMAIL_CONFIG['use_authentication']}")
    print()
    
    # Email Feature Toggle
    SEND_EMAIL = email_config.getboolean('send_email', True)  # From INI configuration
    
    # ================================
    # REPORT GENERATION
    # ================================
    
    print("Configuration:")
    print(f"  Customer ID: {REPORT_CONFIG['CUST_ID']}")
    print(f"  Week End Day: {REPORT_CONFIG['WEEK_END_DAY']} (Sunday=6)")
    print(f"  Number of Weeks: {REPORT_CONFIG['WEEKS_NO']}")
    print(f"  Current Date: {REPORT_CONFIG['CURRENT_DATE'].strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Email Enabled: {SEND_EMAIL}")
    print(f"  Email Authentication: {EMAIL_CONFIG['use_authentication']}")
    print(f"  Email TLS: {EMAIL_CONFIG['use_tls']}")
    print()
    
    try:
        # Step 1: Generate weekly reports using import-based call
        print("Step 1: Generating weekly attack reports...")
        success = weekly_reports.generate_weekly_reports(
            cust_id=REPORT_CONFIG['CUST_ID'],
            week_end_day=REPORT_CONFIG['WEEK_END_DAY'],
            weeks_no=REPORT_CONFIG['WEEKS_NO'],
            current_date=REPORT_CONFIG['CURRENT_DATE']
        )
        
        if not success:
            print("ERROR: Weekly report generation failed!")
            return False
        
        print("✓ Weekly reports generated successfully!")
        print()
        
        # Step 2: Send email if enabled
        if SEND_EMAIL:
            print("Step 2: Sending email with attachments...")
            
            # Calculate week end date for file naming
            last_week_start, last_week_end = weekly_reports.get_one_week_behind(
                REPORT_CONFIG['CURRENT_DATE'], 
                REPORT_CONFIG['WEEK_END_DAY']
            )
            week_end_str = last_week_end.strftime('%Y-%m-%d')
            
            # Set dynamic email subject using template
            subject_template = email_config.get('subject_template', 
                                               'Weekly Attack Trends Report - {customer_id} - Week Ending {week_end_date}')
            EMAIL_CONFIG['subject'] = subject_template.format(
                customer_id=REPORT_CONFIG['CUST_ID'],
                week_end_date=week_end_str
            )
            
            # Send email using import-based call
            email_success = email_send_weekly.send_weekly_email(
                cust_id=REPORT_CONFIG['CUST_ID'],
                week_end_date=week_end_str,
                email_config=EMAIL_CONFIG
            )
            
            if not email_success:
                print("WARNING: Email sending failed, but reports were generated successfully")
                return True  # Don't fail the whole process for email issues
            
            print("✓ Email sent successfully!")
        else:
            print("Step 2: Email sending disabled")
        
        print()
        print("=" * 60)
        print("WEEKLY REPORTING PROCESS COMPLETED SUCCESSFULLY!")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"ERROR: An unexpected error occurred: {e}")
        return False


def validate_configuration():
    """
    Validate that all required configuration is present and files exist.
    """
    print("Validating configuration...")
    
    project_root = get_project_root()
    
    # Check if configuration file exists
    config_file_path = os.path.join(project_root, 'config_files', 'weekly_config.ini')
    if not os.path.exists(config_file_path):
        print(f"ERROR: Configuration file missing: {config_file_path}")
        return False
    else:
        relative_path = os.path.relpath(config_file_path, project_root)
        print(f"✓ Configuration file exists: {relative_path}")
    
    # Check if required directories exist
    required_dirs = [
        os.path.join(project_root, 'database_files', 'EA'),
        os.path.join(project_root, 'report_files', 'EA'),
        os.path.join(project_root, 'script_files')
    ]
    
    for dir_path in required_dirs:
        if not os.path.exists(dir_path):
            print(f"WARNING: Directory does not exist: {dir_path}")
        else:
            relative_path = os.path.relpath(dir_path, project_root)
            print(f"✓ Directory exists: {relative_path}")
    
    # Check if required scripts exist
    script_dir = os.path.dirname(os.path.abspath(__file__))
    required_scripts = [
        os.path.join(script_dir, 'weekly_reports.py'),
        os.path.join(script_dir, 'email_send_weekly.py')
    ]
    
    for script_path in required_scripts:
        if not os.path.exists(script_path):
            print(f"ERROR: Required script missing: {script_path}")
            return False
        else:
            script_name = os.path.basename(script_path)
            print(f"✓ Script exists: {script_name}")
    
    print("Configuration validation completed.")
    print()
    return True


if __name__ == '__main__':
    print("Starting Weekly Attack Trends Report System...")
    print()
    
    # Validate configuration first
    if not validate_configuration():
        print("Configuration validation failed. Exiting.")
        sys.exit(1)
    
    # Run main process
    success = main()
    
    if success:
        print("Program completed successfully.")
        sys.exit(0)
    else:
        print("Program failed. Check the error messages above.")
        sys.exit(1)
