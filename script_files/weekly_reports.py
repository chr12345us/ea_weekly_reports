from datetime import datetime, timedelta
import sqlite3
import os
import csv


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


def get_one_week_behind(dt: datetime, week_end_day: int = 6) -> tuple[datetime, datetime]:
    """
    Get the start and end dates of the week that ended most recently before the given date.
    
    Args:
        dt: The reference date
        week_end_day: Day of the week that ends the week (0=Monday, 6=Sunday)
        
    Returns:
        Tuple of (week_start, week_end) datetime objects
    """
    # Normalize input to midnight
    dt_normalized = dt.replace(hour=0, minute=0, second=0, microsecond=0)
    
    # Calculate how many days to go back to reach the most recent week_end_day
    days_since_end = (dt_normalized.weekday() - week_end_day) % 7

    # Go back to the most recent week end day
    week_end = dt_normalized - timedelta(days=days_since_end)
    
    # If that week end is today or in the future, go back one more week
    if week_end >= dt_normalized:
        week_end -= timedelta(days=7)
    
    # Calculate week start (6 days before end, so the week has 7 days total)
    week_start = week_end - timedelta(days=6)
    
    return week_start, week_end


def get_n_weeks_intervals(start_date: datetime, weeks_no: int, week_end_day: int = 6) -> list[tuple[datetime, datetime]]:
    """
    Generate n weeks of intervals starting from the given date.
    Each interval represents one week (week_start, week_end).
    
    Args:
        start_date: The date to start generating weeks from
        weeks_no: Number of weeks to generate
        week_end_day: Day of the week that ends the week (0=Monday, 6=Sunday)
        
    Returns:
        List of tuples containing (week_start, week_end) for n weeks
    """
    weeks = []
    
    for i in range(weeks_no):
        # Calculate the date for this iteration (going backwards in time)
        current_date = start_date - timedelta(weeks=i)
        week_start, week_end = get_one_week_behind(current_date, week_end_day)
        weeks.append((week_start, week_end))
    
    # Reverse to get chronological order (oldest to newest)
    weeks.reverse()
    
    return weeks


def get_attacks_count_for_week(week_start: datetime, week_end: datetime, cust_id: str) -> int:
    """
    Get the total number of attacks for a given week interval from the appropriate SQLite databases.
    
    Args:
        week_start: Start of the week (inclusive)
        week_end: End of the week (inclusive)
        cust_id: Customer identifier for database path
        
    Returns:
        Total count of attacks in the specified week
    """
    total_count = 0
    project_root = get_project_root()
    
    # Determine which months we need to check
    current_date = week_start
    months_to_check = set()
    
    while current_date <= week_end:
        months_to_check.add((current_date.year, current_date.month))
        # Move to next day
        current_date += timedelta(days=1)
    
    # Query each relevant database
    for year, month in months_to_check:
        db_filename = f"database_{cust_id}_{month:02d}_{year}.sqlite"
        db_path = os.path.join(project_root, "database_files", cust_id, db_filename)
        
        if os.path.exists(db_path):
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                
                # Query attacks table for the date range
                query = """
                SELECT COUNT(*) FROM attacks 
                WHERE DATE(startDate) >= ? AND DATE(startDate) <= ?
                """
                cursor.execute(query, (week_start.strftime('%Y-%m-%d'), week_end.strftime('%Y-%m-%d')))
                
                count = cursor.fetchone()[0]
                total_count += count
                
                print(f"Found {count} attacks in {db_filename}")
                
                conn.close()
                
            except sqlite3.Error as e:
                print(f"Error querying {db_filename}: {e}")
            except Exception as e:
                print(f"Unexpected error with {db_filename}: {e}")
        else:
            print(f"Database not found: {db_path}")
    
    return total_count


def save_weekly_results_to_csv(week_start: datetime, week_end: datetime, attacks_count: int, cust_id: str, csv_filename: str = None):
    """
    Save weekly attack results to CSV file.
    
    Args:
        week_start: Start of the week
        week_end: End of the week  
        attacks_count: Total attacks for the week
        cust_id: Customer identifier for file path
        csv_filename: Optional custom filename, defaults to weekly_trends.csv
    """
    project_root = get_project_root()
    
    # Create the report directory path
    report_dir = os.path.join(project_root, "report_files", cust_id)
    os.makedirs(report_dir, exist_ok=True)
    
    # CSV file path - use custom filename if provided
    if csv_filename is None:
        csv_filename = "weekly_trends.csv"
    csv_path = os.path.join(report_dir, csv_filename)
    
    # Check if file exists to determine if we need headers
    file_exists = os.path.exists(csv_path)
    
    # Append the new row to CSV
    with open(csv_path, 'a', newline='') as csvfile:
        fieldnames = ['week_start', 'week_end', 'attacks_count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        # Write header if file is new
        if not file_exists:
            writer.writeheader()
        
        # Write the data row
        writer.writerow({
            'week_start': week_start.strftime('%Y-%m-%d'),
            'week_end': week_end.strftime('%Y-%m-%d'),
            'attacks_count': attacks_count
        })
    
    print(f"Results saved to: {csv_path}")


def check_week_exists_in_csv(week_start: datetime, week_end: datetime, cust_id: str, csv_filename: str = None) -> bool:
    """
    Check if a specific week already exists in the CSV file.
    
    Args:
        week_start: Start of the week
        week_end: End of the week
        cust_id: Customer identifier for file path
        csv_filename: Optional custom filename, defaults to weekly_trends.csv
        
    Returns:
        True if the week exists in CSV, False otherwise
    """
    project_root = get_project_root()
    
    if csv_filename is None:
        csv_filename = "weekly_trends.csv"
    csv_path = os.path.join(project_root, "report_files", cust_id, csv_filename)
    
    if not os.path.exists(csv_path):
        return False
    
    week_start_str = week_start.strftime('%Y-%m-%d')
    week_end_str = week_end.strftime('%Y-%m-%d')
    
    with open(csv_path, 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if row['week_start'] == week_start_str and row['week_end'] == week_end_str:
                return True
    
    return False


def trim_csv_to_n_weeks(cust_id: str, weeks_no: int, csv_filename: str = None) -> None:
    """
    Trim the CSV file to keep only the most recent n weeks of data.
    Removes older weeks if there are more than weeks_no entries.
    
    Args:
        cust_id: Customer identifier for file path
        weeks_no: Number of weeks to keep
        csv_filename: Optional custom filename, defaults to weekly_trends.csv
    """
    project_root = get_project_root()
    
    if csv_filename is None:
        csv_filename = "weekly_trends.csv"
    csv_path = os.path.join(project_root, "report_files", cust_id, csv_filename)
    
    if not os.path.exists(csv_path):
        return
    
    # Read all rows from CSV
    rows = []
    with open(csv_path, 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        rows = list(reader)
    
    # Sort by week_start date to ensure chronological order
    rows.sort(key=lambda x: datetime.strptime(x['week_start'], '%Y-%m-%d'))
    
    # Keep only the most recent weeks_no entries
    if len(rows) > weeks_no:
        rows = rows[-weeks_no:]  # Keep the last weeks_no rows
        
        # Rewrite the CSV file with trimmed data
        with open(csv_path, 'w', newline='') as csvfile:
            fieldnames = ['week_start', 'week_end', 'attacks_count']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        
        print(f"CSV trimmed to keep most recent {weeks_no} weeks")


def generate_google_chart(cust_id: str, csv_filename: str = None, html_filename: str = None) -> str:
    """
    Generate HTML with Google Chart using data from the CSV file.
    Uses the last day of each week (week_end) on X-axis and attack count on Y-axis.
    
    Args:
        cust_id: Customer identifier for file path
        csv_filename: Optional custom CSV filename, defaults to weekly_trends.csv
        html_filename: Optional custom HTML filename, defaults to weekly_trends_chart.html
        
    Returns:
        HTML content with Google Chart
    """
    project_root = get_project_root()
    
    if csv_filename is None:
        csv_filename = "weekly_trends.csv"
    if html_filename is None:
        html_filename = "weekly_trends_chart.html"
        
    csv_path = os.path.join(project_root, "report_files", cust_id, csv_filename)
    
    if not os.path.exists(csv_path):
        return "<html><body><h1>Error: CSV file not found</h1></body></html>"
    
    # Read CSV data
    chart_data = []
    with open(csv_path, 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            week_end = datetime.strptime(row['week_end'], '%Y-%m-%d')
            attacks_count = int(row['attacks_count'])
            chart_data.append((week_end, attacks_count))
    
    # Sort by date to ensure proper order
    chart_data.sort(key=lambda x: x[0])
    
    # Generate JavaScript data array
    js_data_rows = []
    for week_end, attacks_count in chart_data:
        # Format date as MM/DD/YY for better readability
        date_formatted = week_end.strftime('%m/%d/%y')
        js_data_rows.append(f"['{date_formatted}', {attacks_count}]")
    
    js_data = ",\n          ".join(js_data_rows)
    
    # HTML template with Google Chart
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Weekly Attack Trends</title>
    <script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>
    <script type="text/javascript">
      google.charts.load('current', {{'packages':['corechart']}});
      google.charts.setOnLoadCallback(drawChart);

      function drawChart() {{
        var data = google.visualization.arrayToDataTable([
          ['Week End Date', 'Attacks'],
          {js_data}
        ]);

        var options = {{
          title: 'Weekly Attack Trends',
          titleTextStyle: {{
            fontSize: 18,
            bold: true
          }},
          hAxis: {{
            title: 'Week End-Date',
            titleTextStyle: {{
              fontSize: 14,
              bold: true
            }},
            textStyle: {{
              fontSize: 12
            }}
          }},
          vAxis: {{
            title: 'Number of Attacks',
            titleTextStyle: {{
              fontSize: 14,
              bold: true
            }},
            format: '#,###'
          }},
          legend: {{
            position: 'none'
          }},
          backgroundColor: '#f8f9fa',
          chartArea: {{
            left: 80,
            top: 80,
            width: '75%',
            height: '70%'
          }},
          colors: ['#007bff'],
          bar: {{
            groupWidth: '60%'
          }}
        }};

        var chart = new google.visualization.ColumnChart(document.getElementById('weekly_chart'));
        chart.draw(data, options);
      }}
    </script>
</head>
<body>
    <div style="text-align: center; margin: 20px;">
        <div id="weekly_chart" style="width: 100%; height: 500px;"></div>
    </div>
</body>
</html>"""
    
    # Save HTML file
    html_path = os.path.join(project_root, "report_files", cust_id, html_filename)
    with open(html_path, 'w') as htmlfile:
        htmlfile.write(html_content)
    
    print(f"Google Chart HTML saved to: {html_path}")
    return html_content


def generate_weekly_reports(cust_id: str, week_end_day: int, weeks_no: int, current_date: datetime) -> bool:
    """
    Main function to generate weekly attack reports.
    This is the function that will be called from main_weekly.py
    
    Args:
        cust_id: Customer identifier (e.g., "EA")
        week_end_day: Day of the week that ends the week (0=Monday, 6=Sunday)
        weeks_no: Number of weeks to generate
        current_date: Current date for report generation
        
    Returns:
        True if successful, False otherwise
    """
    try:
        print(f"Generating weekly reports for customer: {cust_id}")
        print(f"Week end day: {week_end_day} (Sunday=6)")
        print(f"Number of weeks: {weeks_no}")
        print(f"Current date: {current_date.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Project root: {get_project_root()}")
        print()
        
        # Generate CSV file with smart handling
        last_week_start, last_week_end = get_one_week_behind(current_date, week_end_day)
        week_end_str = last_week_end.strftime('%Y-%m-%d')
        
        # Generate filenames with week end date
        csv_filename = f"weekly_trends_{week_end_str}.csv"
        html_filename = f"weekly_trends_chart_{week_end_str}.html"
        
        project_root = get_project_root()
        csv_path = os.path.join(project_root, "report_files", cust_id, csv_filename)
        n_weeks = get_n_weeks_intervals(current_date, weeks_no, week_end_day)
        
        if not os.path.exists(csv_path):
            # CSV doesn't exist - create it with all n weeks
            print(f"CSV file doesn't exist. Creating new file with {weeks_no} weeks of data...")
            for i, (week_start, week_end) in enumerate(n_weeks, 1):
                print(f"Processing week {i}: {week_start.strftime('%Y-%m-%d')} to {week_end.strftime('%Y-%m-%d')}")
                attacks_count = get_attacks_count_for_week(week_start, week_end, cust_id)
                save_weekly_results_to_csv(week_start, week_end, attacks_count, cust_id, csv_filename)
                print(f"Week {i} completed: {attacks_count} attacks")
            print(f"CSV file created with {weeks_no} weeks of data!")
            
            # Generate Google Chart
            print("Generating Google Chart...")
            generate_google_chart(cust_id, csv_filename, html_filename)
        else:
            # CSV exists - always update the last week to ensure current data
            print("CSV file exists. Updating last week data...")
            
            if check_week_exists_in_csv(last_week_start, last_week_end, cust_id, csv_filename):
                print(f"Last week ({last_week_start.strftime('%Y-%m-%d')} to {last_week_end.strftime('%Y-%m-%d')}) exists in CSV. Overwriting with current data...")
                
                # Remove the existing last week entry and add updated data
                csv_path = os.path.join(project_root, "report_files", cust_id, csv_filename)
                rows = []
                with open(csv_path, 'r', newline='') as csvfile:
                    reader = csv.DictReader(csvfile)
                    rows = list(reader)
                
                # Remove the last week entry if it exists
                week_start_str = last_week_start.strftime('%Y-%m-%d')
                week_end_str = last_week_end.strftime('%Y-%m-%d')
                rows = [row for row in rows if not (row['week_start'] == week_start_str and row['week_end'] == week_end_str)]
                
                # Rewrite CSV without the last week entry
                with open(csv_path, 'w', newline='') as csvfile:
                    fieldnames = ['week_start', 'week_end', 'attacks_count']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(rows)
                
                # Add the updated last week data
                attacks_count = get_attacks_count_for_week(last_week_start, last_week_end, cust_id)
                save_weekly_results_to_csv(last_week_start, last_week_end, attacks_count, cust_id, csv_filename)
                print(f"Last week updated: {attacks_count} attacks")
            else:
                print(f"Last week ({last_week_start.strftime('%Y-%m-%d')} to {last_week_end.strftime('%Y-%m-%d')}) not found in CSV.")
                print("Adding last week...")
                attacks_count = get_attacks_count_for_week(last_week_start, last_week_end, cust_id)
                save_weekly_results_to_csv(last_week_start, last_week_end, attacks_count, cust_id, csv_filename)
                print(f"Last week added: {attacks_count} attacks")
            
            # Trim CSV to maintain only weeks_no weeks
            trim_csv_to_n_weeks(cust_id, weeks_no, csv_filename)
            print("CSV file updated!")
            
            # Generate Google Chart
            print("Generating Google Chart...")
            generate_google_chart(cust_id, csv_filename, html_filename)
        
        print("Weekly trends report completed!")
        return True
        
    except Exception as e:
        print(f"Error generating weekly reports: {e}")
        return False


# For backward compatibility when run directly
if __name__ == '__main__':
    # Default configuration for direct execution
    CUST_ID = "EA"
    WEEK_END_DAY = 6
    WEEKS_NO = 6
    cur_date = datetime.now()
    
    success = generate_weekly_reports(CUST_ID, WEEK_END_DAY, WEEKS_NO, cur_date)
    if not success:
        exit(1)
