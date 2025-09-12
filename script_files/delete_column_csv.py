import csv
import os
import sys

cust_id = sys.argv[1]

# Specify the directory path and column name
directory_path = f'./tmp_files/{cust_id}/'  # Replace with the actual directory path

attacks_to_remove_list = ['Memcached Server Reflect']
devices_to_remove_list = []

def remove_column(csv_file_path, column_name):
    # Read the CSV file into a list of dictionaries
    with open(csv_file_path, 'r', newline='') as file:
        reader = csv.DictReader(file)
        rows = list(reader)

    # Check if the column exists
    if column_name in rows[0]:
        # Remove the column from the header
        header = reader.fieldnames
        header.remove(column_name)

        # Remove the entire column from each row
        for row in rows:
            del row[column_name]

        # Write the modified data (with updated header) back to the CSV file
        with open(csv_file_path, 'w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=header)
            writer.writeheader()
            writer.writerows(rows)

        print(f"Column '{column_name}' removed in {csv_file_path}, including the header, and file updated.")
    else:
        print(f"Column '{column_name}' not found in the {csv_file_path} file.")



def remove_line(csv_file_path, line_to_remove):
    # Read the CSV file into a list of lists (not dictionaries for this task)
    with open(csv_file_path, 'r', newline='') as file:
        reader = csv.reader(file)
        rows = list(reader)

    # Filter out rows where the first cell matches line_to_remove
    filtered_rows = [row for row in rows if row[0] != line_to_remove]
    # Write the filtered rows back to the CSV file
    with open(csv_file_path, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(filtered_rows)

    print(f"Line starting with '{line_to_remove}' removed from {csv_file_path}, and file updated.")


for device_to_remove in devices_to_remove_list:    
    for filename in os.listdir(directory_path):
        if filename.endswith('.csv') and (filename == 'device_bpm_chart_lm.csv' or filename == 'device_epm_chart_lm.csv' or filename == 'device_ppm_chart_lm.csv'):
            file_path = directory_path+filename
            remove_column(file_path, device_to_remove)

        if filename.endswith('.csv') and (filename == 'device_bpm_table_lm.csv' or filename == 'device_epm_table_lm.csv' or filename == 'device_ppm_table_lm.csv'):
            file_path = directory_path+filename
            remove_line(file_path, device_to_remove)

for attack_to_remove in attacks_to_remove_list:    
    for filename in os.listdir(directory_path):
        if filename.endswith('.csv') and (filename == 'epm_chart_alltimehigh.csv' or filename == 'epm_chart_lm.csv' or filename == 'events_per_day_chart_alltimehigh.csv'):
            file_path = directory_path+filename
            remove_column(file_path, attack_to_remove)

    
