# Weekly Attack Trends Report System
A comprehensive Python-based system for generating automated weekly attack trend reports with interactive charts, daily attack breakdowns, and email delivery capabilities.
## Overview
This system processes attack data from SQLite databases, generates detailed CSV reports with both weekly and daily breakdowns, creates interactive HTML charts with value annotations, and automatically emails comprehensive reports to specified recipients. The system now uses an INI-based configuration approach with organized sections for maximum flexibility and maintainability.
## Architecture
### Import-Based Design
- **Modular Architecture**: Uses Python imports instead of subprocess calls
- **INI Configuration**: All settings managed through organized INI configuration sections
- **Path Independence**: Can be executed from any directory
- **Error Handling**: Comprehensive validation and error reporting
- **Data Validation**: Sanity checks between daily and weekly attack totals
### Key Components
```
script_files/
├── main_weekly.py          # Main orchestrator with INI support
├── weekly_reports.py       # Enhanced report generation with daily attacks and charts
├── email_send_weekly.py    # Email delivery with multiple attachments
config_files/
├── weekly_config.ini       # INI configuration with sections
└── weekly_config.ini.example # Configuration template
```
## Features
### Report Generation
- **Daily Attack Analysis**: Day-by-day attack breakdown for the past week
- **Weekly Trend Analysis**: Traditional weekly attack summaries
- **Dual CSV Outputs**: Both daily (`weekly_day_trends_*.csv`) and weekly (`weekly_trends_*.csv`) files
- **Interactive HTML Charts**: Google Charts with value annotations and stems
- **Data Validation**: Sanity checks ensure daily totals match weekly totals
- **Flexible Week End Day**: Configurable week ending day (default: Sunday)
### Email Delivery
- **Multi-recipient Support**: Send to multiple email addresses via comma-separated list
- **Triple Attachments**: Daily CSV, Weekly CSV, and HTML chart files
- **Configurable SMTP**: Support for various email servers
- **Authentication Control**: Optional SMTP authentication
- **TLS Support**: Configurable TLS/STARTTLS encryption
### Advanced Configuration
- **INI-based Config**: Organized sections for easy maintenance
- **Date Override**: Test with specific dates using `cur_date` setting
- **Environment Flexibility**: Works with Gmail, internal SMTP servers, etc.
- **Section Organization**: Logical grouping of global, email, and report settings
- **Future-ready**: Sections prepared for daily/monthly reports
### Chart Features
- **Value Annotations**: Attack counts displayed on chart bars
- **Annotation Stems**: Connecting lines for clarity  
- **Dual Chart Layout**: Daily and weekly charts in single HTML file
- **Responsive Design**: Adapts to different screen sizes
- **Interactive Tooltips**: Hover information for data points
## Installation & Setup
### Prerequisites
- Python 3.9+ (required for modern type hints and tuple annotations)
- Required Python libraries: `smtplib`, `configparser`, `datetime`, `sqlite3`, `csv`, `pandas`
### Directory Structure
```
ea_weekly_reports/
├── script_files/
│   ├── main_weekly.py              # Main orchestrator with INI support
│   ├── weekly_reports.py           # Enhanced report generation with integrated charts  
│   └── email_send_weekly.py        # Email with multiple attachments
├── config_files/
│   ├── weekly_config.ini           # INI configuration file
│   ├── weekly_config.ini.example   # Configuration template
│   └── customers.json              # Customer definitions
├── database_files/
│   └── EA/
│       └── database_EA_*.sqlite    # Monthly attack databases
├── report_files/
│   └── EA/
│       ├── weekly_trends_*.csv         # Weekly summary data
│       ├── weekly_day_trends_*.csv     # Daily attack breakdown
│       └── weekly_trends_chart_*.html  # Interactive charts
└── Weekly_README.md
```
## Configuration
### INI Configuration File (`config_files/weekly_config.ini`)
```ini
[global]
# Override current date for testing (format: YYYY-MM-DD)
# Leave empty or comment out to use current date
cur_date = 
# cur_date = 2025-01-15
top_n = 10
abuseipdb = false

[email]
smtp_server = smtp.gmail.com
smtp_port = 587
sender_email = your_email@gmail.com
sender_password = your_app_password
# Comma-separated list of recipient emails
recipient_emails = recipient1@example.com,recipient2@example.com

[weekly_reports]
enabled = true
# Week end day: 0=Monday, 1=Tuesday, ..., 6=Sunday
week_end_day = 6

[daily_reports]
enabled = false

[monthly_reports]
enabled = false
```
### Configuration Sections
#### [global] Section
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `cur_date` | string | empty | Override current date for testing (YYYY-MM-DD format) |
| `top_n` | integer | 10 | Number of top entries to include in reports |
| `abuseipdb` | boolean | false | Enable/disable AbuseIPDB integration |

#### [email] Section  
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `smtp_server` | string | "smtp.gmail.com" | SMTP server hostname |
| `smtp_port` | integer | 587 | SMTP server port |
| `sender_email` | string | "" | Sender email address |
| `sender_password` | string | "" | SMTP password/app password |
| `recipient_emails` | string | "" | Comma-separated list of recipient emails |

#### [weekly_reports] Section
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | boolean | true | Enable/disable weekly report generation |
| `week_end_day` | integer | 6 | Day of week for week ending (0=Monday, 6=Sunday) |

#### [daily_reports] & [monthly_reports] Sections
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enabled` | boolean | false | Enable/disable report type (future feature) |
## Usage
### Basic Execution
```bash
cd /path/to/ea_weekly_reports
python3 script_files/main_weekly.py [CUSTOMER_ID]
```
Example:
```bash
python3 script_files/main_weekly.py EA
```

### Date Override Testing
To test with a specific date, edit the INI configuration:
```ini
[global]
cur_date = 2025-01-15
```
This allows testing report generation for historical dates without changing system time.

### Execution from Any Directory
The system uses dynamic path resolution and can be run from anywhere:
```bash
python3 /path/to/ea_weekly_reports/script_files/main_weekly.py EA
```
### Output
```
============================================================
WEEKLY ATTACK TRENDS REPORT - INI-BASED CONFIGURATION
============================================================
Project root directory: /path/to/ea_weekly_reports
Current working directory: /current/directory
✓ Configuration loaded from: config_files/weekly_config.ini
Configuration:
  Customer ID: EA
  Week End Day: 6 (Sunday=6)
  Current Date: 2025-09-28 15:30:12
  Date Override: None (using current date)
  Email Enabled: True
Step 1: Generating weekly and daily attack reports...
Found 16258 attacks in database_EA_09_2025.sqlite
Daily attacks breakdown:
  Monday: 2,456 attacks
  Tuesday: 1,987 attacks  
  Wednesday: 2,123 attacks
  Thursday: 1,834 attacks
  Friday: 2,001 attacks
  Saturday: 1,512 attacks
  Sunday: 4,225 attacks
Daily total: 16,138 attacks
Weekly total: 16,138 attacks
✓ Sanity check passed: Daily and weekly totals match!
Daily CSV saved to: /path/to/ea_weekly_reports/report_files/EA/weekly_day_trends_2025-09-28.csv
Weekly CSV saved to: /path/to/ea_weekly_reports/report_files/EA/weekly_trends_2025-09-28.csv  
Combined HTML chart saved to: /path/to/ea_weekly_reports/report_files/EA/weekly_trends_chart_2025-09-28.html
✓ Reports generated successfully!
Step 2: Sending email with attachments...
Connecting to SMTP server: smtp.gmail.com:587
Enabling TLS...
Authenticating with SMTP server...
Attaching: weekly_day_trends_2025-09-28.csv (Daily Attack Data)
Attaching: weekly_trends_2025-09-28.csv (Weekly Trends Data)
Attaching: weekly_trends_chart_2025-09-28.html (Interactive Charts)
Email sent successfully to: recipient1@example.com, recipient2@example.com
✓ Email sent successfully!
============================================================
WEEKLY REPORTING PROCESS COMPLETED SUCCESSFULLY!
============================================================
```
## Email Server Configurations
### Gmail Configuration
```ini
[email]
smtp_server = smtp.gmail.com
smtp_port = 587
sender_email = your_email@gmail.com
sender_password = your_app_password
recipient_emails = recipient1@example.com,recipient2@example.com
```

### Internal SMTP Server (No Authentication)
```ini
[email]  
smtp_server = internal-smtp.company.com
smtp_port = 25
sender_email = reports@company.com
sender_password = 
recipient_emails = team@company.com
```

### Office 365 Configuration
```ini
[email]
smtp_server = smtp.office365.com
smtp_port = 587
sender_email = your_email@company.com
sender_password = your_password
recipient_emails = team@company.com
```
## File Outputs
### Daily Attack Trends CSV (`weekly_day_trends_YYYY-MM-DD.csv`)
- Day-by-day attack breakdown for the past week
- Columns: Day, Date, Attack_Count, Attack_Annotation
- Contains data for chart annotations and stems
- Compatible with Excel and data analysis tools

### Weekly Trends CSV (`weekly_trends_YYYY-MM-DD.csv`)  
- Traditional weekly attack summary data
- Weekly aggregated statistics and trends
- Historical week-over-week comparisons
- Compatible with existing analysis workflows

### Combined HTML Charts (`weekly_trends_chart_YYYY-MM-DD.html`)
- **Dual Chart Display**: Daily and weekly charts in single file
- **Interactive Google Charts**: Professional visualization with hover tooltips  
- **Value Annotations**: Attack counts displayed on chart bars with stems
- **Responsive Design**: Adapts to different screen sizes
- **Self-contained**: No external dependencies, easy sharing

#### Chart Features
- Daily chart with "Day of the week" x-axis title
- Weekly chart with traditional time-based trends
- Value annotations with connecting stems for clarity
- Consistent color scheme across both charts
- Mouse-over tooltips with detailed information
## Troubleshooting
### Common Issues
#### Configuration File Not Found
```
ERROR: Configuration file not found: /path/to/config_files/weekly_config.ini
```
**Solution**: Verify INI file exists and has proper section headers with square brackets

#### INI Syntax Errors  
```
Error parsing configuration: No section: 'email'
```
**Solution**: Ensure section headers use square brackets `[section_name]` and proper key=value pairs

#### Email Authentication Errors
```
Error sending email: (535, '5.7.8 Username and Password not accepted')
```
**Solution**: Verify `sender_email` and `sender_password` in [email] section

#### Email Format Errors
```
Error: Invalid email format in recipient_emails
```  
**Solution**: Use comma-separated emails without spaces: `email1@domain.com,email2@domain.com`

#### Database Connection Errors
```
No database found for customer EA in month 09
```
**Solution**: Ensure database files follow naming pattern: `database_EA_MM_YYYY.sqlite`

#### Chart Display Issues
```
Charts not rendering properly in HTML file
```
**Solution**: Verify Google Charts JavaScript is loading, check browser console for errors

#### Daily/Weekly Total Mismatch
```
WARNING: Daily total (15,456) doesn't match weekly total (15,789)
```
**Solution**: Check database integrity, review attack counting logic for date ranges
### Debug Mode
Add debug logging to troubleshoot issues:
- Check log files in `report_files/[CUSTOMER]/weekly_report.log`
- Use the `cur_date` override to test specific dates
- Examine CSV outputs for data validation
- Review HTML chart source for JavaScript errors

### INI Configuration Validation
Ensure your INI file follows proper syntax:
- Section headers: `[section_name]`  
- Key-value pairs: `key = value`
- Boolean values: `true`, `false` (case-insensitive)
- Comments: Use `#` at the beginning of lines
- No quotes needed around string values

### Cache Issues
If configuration changes aren't reflected:
```bash
# Clear Python cache
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null
find . -name "*.pyc" -delete
```
## Security Considerations
### Email Credentials
- Use app-specific passwords for Gmail
- Store credentials securely in INI file
- Consider environment variables for sensitive data
- Restrict file permissions on config files: `chmod 600 weekly_config.ini`
### Network Security
- Use TLS encryption when possible (port 587 for most providers)  
- Verify SMTP server certificates
- Use internal SMTP servers when available
- Test email configuration before production deployment
## Daily Attacks Feature Details
### New Functionality
The system now generates comprehensive daily attack analysis:
- **Daily CSV Generation**: `weekly_day_trends_[DATE].csv` with day-by-day breakdown
- **Sanity Check Validation**: Ensures daily attack sum matches weekly total
- **Enhanced Charts**: Combined daily and weekly visualizations in single HTML
- **Value Annotations**: Attack counts displayed on chart bars with connecting stems

### Data Structure
Daily CSV contains:
```
Day,Date,Attack_Count,Attack_Annotation
Monday,2025-09-22,2456,2456
Tuesday,2025-09-23,1987,1987
Wednesday,2025-09-24,2123,2123
...
```

### Chart Enhancements
- Google Charts with professional annotations
- "Day of the week" x-axis labeling
- Responsive design for multiple screen sizes
- Interactive hover tooltips
- Dual chart layout (daily + weekly in same HTML)

## Future Enhancements  
The INI configuration system supports additional report types:
```ini
[daily_reports]
enabled = false
# Future: Individual daily report generation

[monthly_reports] 
enabled = false
# Future: Monthly summary report generation

[global]
# Future: Additional AbuseIP integration
# Future: Custom date range selection
# Future: Multiple customer batch processing
```
## Support
For issues or questions:
1. Check the troubleshooting section
2. Verify configuration file syntax
3. Review log output for specific error messages
4. Test email configuration with simple SMTP tools
## Version History
- **v3.0**: INI-based configuration with daily attacks feature, interactive charts with annotations
- **v2.5**: Added daily attack breakdown, sanity check validation, enhanced HTML charts
- **v2.0**: JSON-based configuration system with TLS/authentication control  
- **v1.5**: Import-based architecture with centralized configuration
- **v1.0**: Initial subprocess-based implementation

## Key New Features in v3.0
- **INI Configuration**: Organized sections replace JSON configuration
- **Daily Attack Analysis**: Day-by-day breakdown with dedicated CSV files
- **Enhanced Charts**: Google Charts with value annotations and stems
- **Data Validation**: Sanity checks ensure data integrity
- **Multiple Attachments**: Email includes both daily and weekly CSV files
- **Date Override**: Test functionality with specific dates
- **Improved Error Handling**: Better diagnostics and troubleshooting
---
