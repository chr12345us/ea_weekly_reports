#!/usr/bin/env python3
"""
Attack Table Statistics Script
Analyzes attack data and generates Excel reports with multiple sheets.
"""

import pandas as pd
import os
from pathlib import Path
from datetime import datetime, timedelta
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils.dataframe import dataframe_to_rows

# =============================================================================
# CONFIGURATION PARAMETERS - MODIFY THESE AS NEEDED
# =============================================================================

# Input filename (should be placed in ./input folder)
INPUT_FILENAME = "Generic_forensics_2025-10-17_19-46-58.csv"

# Column names in the CSV file
ATTACK_COLUMN = "Attack Name"
DATE_COLUMN = "Start Time"  # Adjust this to match your actual date column name

# Output filename (will be saved in ./output folder)
OUTPUT_FILENAME = "attack_statistics.xlsx"

# Number of days to look back for analysis
DAYS_TO_ANALYZE = 7

# Number of top attacks to show per day
TOP_ATTACKS_COUNT = 5

# =============================================================================
# SCRIPT IMPLEMENTATION
# =============================================================================

def parse_date_column(df, date_column):
    """
    Parse the date column and handle various date formats.
    Specifically handles mm.dd.yyyy hh:mm:ss format.
    """
    try:
        # First try the specific format: mm.dd.yyyy hh:mm:ss
        df[date_column] = pd.to_datetime(df[date_column], format='%m.%d.%Y %H:%M:%S', errors='coerce')
        
        # Check if any dates were successfully parsed
        parsed_count = df[date_column].notna().sum()
        total_count = len(df)
        
        print(f"Date parsing results: {parsed_count}/{total_count} dates successfully parsed")
        
        if parsed_count == 0:
            print("No dates could be parsed with format 'mm.dd.yyyy hh:mm:ss'")
            print("Trying alternative date parsing...")
            # Fallback to pandas auto-detection
            df[date_column] = pd.to_datetime(df[date_column], errors='coerce')
            parsed_count = df[date_column].notna().sum()
            print(f"Alternative parsing results: {parsed_count}/{total_count} dates successfully parsed")
        
        return df
    except Exception as e:
        print(f"Error parsing date column '{date_column}': {str(e)}")
        return None

def get_last_n_days_data(df, date_column, n_days):
    """
    Filter data to include only the last n days.
    """
    # Get the latest date in the dataset
    latest_date = df[date_column].max()
    
    # Calculate the cutoff date
    cutoff_date = latest_date - timedelta(days=n_days-1)
    
    # Filter the data
    filtered_df = df[df[date_column] >= cutoff_date].copy()
    
    print(f"Date range for analysis: {cutoff_date.date()} to {latest_date.date()}")
    print(f"Total records in date range: {len(filtered_df)}")
    
    return filtered_df

def get_top_attacks_by_day(df, attack_column, date_column, top_n):
    """
    Get top N attacks for each day in the dataset.
    Returns a pivot table with attacks as rows and dates as columns.
    """
    # Create a date-only column for grouping
    df['date_only'] = df[date_column].dt.date
    
    # Group by date and attack, count occurrences
    daily_attacks = df.groupby(['date_only', attack_column]).size().reset_index(name='count')
    
    # Get all unique attacks across all days and their total counts
    total_attacks = df.groupby(attack_column).size().reset_index(name='total_count')
    
    # Get the overall top N attacks by total count
    top_attacks = total_attacks.nlargest(top_n, 'total_count')[attack_column].tolist()
    
    # Filter daily attacks to only include the top N attacks
    filtered_daily_attacks = daily_attacks[daily_attacks[attack_column].isin(top_attacks)]
    
    # Create pivot table: attacks as rows, dates as columns, counts as values
    pivot_table = filtered_daily_attacks.pivot_table(
        index=attack_column, 
        columns='date_only', 
        values='count', 
        fill_value=0
    )
    
    # Sort the rows by the total count (descending)
    row_totals = pivot_table.sum(axis=1).sort_values(ascending=False)
    pivot_table = pivot_table.reindex(row_totals.index)
    
    # Sort columns (dates) chronologically
    pivot_table = pivot_table.reindex(sorted(pivot_table.columns), axis=1)
    
    # Reset index to make attack names a regular column
    pivot_table = pivot_table.reset_index()
    
    # Rename the attack column for clarity
    pivot_table = pivot_table.rename(columns={attack_column: 'Attack Name'})
    
    return pivot_table

def format_excel_sheet(ws, title):
    """
    Apply formatting to an Excel worksheet.
    """
    # Set title
    ws['A1'] = title
    ws['A1'].font = Font(bold=True, size=14)
    ws['A1'].fill = PatternFill(start_color="366092", end_color="366092", fill_type="solid")
    ws['A1'].font = Font(bold=True, size=14, color="FFFFFF")
    
    # Format headers (assuming they start at row 3)
    if ws.max_row > 2:
        for cell in ws[3]:
            if cell.value:
                cell.font = Font(bold=True)
                cell.fill = PatternFill(start_color="D9E1F2", end_color="D9E1F2", fill_type="solid")
                cell.alignment = Alignment(horizontal="center")
    
    # Auto-adjust column widths
    for column in ws.columns:
        max_length = 0
        column_letter = column[0].column_letter
        
        for cell in column:
            try:
                if len(str(cell.value)) > max_length:
                    max_length = len(str(cell.value))
            except:
                pass
        
        adjusted_width = min(max_length + 2, 50)
        ws.column_dimensions[column_letter].width = adjusted_width

def main():
    """Main function to generate attack statistics."""
    
    # Generate timestamp for output filename
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    # Get the script directory
    script_dir = Path(__file__).parent
    
    # Define input and output paths
    input_dir = script_dir / "input"
    output_dir = script_dir / "output"
    
    input_path = input_dir / INPUT_FILENAME
    
    # Add timestamp to output filename
    output_name_parts = OUTPUT_FILENAME.rsplit('.', 1)
    if len(output_name_parts) == 2:
        timestamped_filename = f"{output_name_parts[0]}_{timestamp}.{output_name_parts[1]}"
    else:
        timestamped_filename = f"{OUTPUT_FILENAME}_{timestamp}"
    
    output_path = output_dir / timestamped_filename
    
    # Check if input file exists
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        print(f"Please place your CSV file in the 'input' folder with the name: {INPUT_FILENAME}")
        return
    
    # Ensure output directory exists
    output_dir.mkdir(exist_ok=True)
    
    try:
        # Read the CSV file
        print(f"Reading CSV file: {input_path}")
        df = pd.read_csv(input_path)
        
        print(f"Original data shape: {df.shape}")
        print(f"Columns available: {list(df.columns)}")
        
        # Check if required columns exist
        if ATTACK_COLUMN not in df.columns:
            print(f"Error: Column '{ATTACK_COLUMN}' not found in the CSV file.")
            print(f"Available columns: {list(df.columns)}")
            return
        
        if DATE_COLUMN not in df.columns:
            print(f"Error: Column '{DATE_COLUMN}' not found in the CSV file.")
            print(f"Available columns: {list(df.columns)}")
            return
        
        # Parse date column
        df = parse_date_column(df, DATE_COLUMN)
        if df is None:
            return
        
        # Remove rows with invalid dates
        df = df.dropna(subset=[DATE_COLUMN])
        print(f"Data shape after removing invalid dates: {df.shape}")
        
        # Get data for the last N days
        recent_data = get_last_n_days_data(df, DATE_COLUMN, DAYS_TO_ANALYZE)
        
        if recent_data.empty:
            print("No data found for the specified date range.")
            return
        
        # Generate top attacks by day
        print(f"\nGenerating top {TOP_ATTACKS_COUNT} attacks by day...")
        top_attacks_pivot = get_top_attacks_by_day(recent_data, ATTACK_COLUMN, DATE_COLUMN, TOP_ATTACKS_COUNT)
        
        print(f"Pivot table shape: {top_attacks_pivot.shape}")
        print(f"Top attacks identified: {list(top_attacks_pivot['Attack Name'])}")
        
        # Create Excel file with multiple sheets
        print(f"\nCreating Excel file: {output_path}")
        
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            # Sheet 1: Top attacks by day (pivot format)
            top_attacks_pivot.to_excel(writer, sheet_name='Top Attacks by Day', index=False, startrow=2)
            
            # Format the sheets
            wb = writer.book
            
            # Format Sheet 1
            ws1 = wb['Top Attacks by Day']
            format_excel_sheet(ws1, f"Top {TOP_ATTACKS_COUNT} Attacks by Day - Last {DAYS_TO_ANALYZE} Days")
        
        print("Excel file created successfully!")
        print(f"File saved as: {output_path}")
        
        # Display summary
        print(f"\nSummary:")
        print(f"- Date range analyzed: {DAYS_TO_ANALYZE} days")
        print(f"- Total records analyzed: {len(recent_data)}")
        print(f"- Unique attack types: {recent_data[ATTACK_COLUMN].nunique()}")
        print(f"- Unique dates: {recent_data[DATE_COLUMN].dt.date.nunique()}")
        
    except Exception as e:
        print(f"Error processing the data: {str(e)}")
        import traceback
        traceback.print_exc()
        return

if __name__ == "__main__":
    main()