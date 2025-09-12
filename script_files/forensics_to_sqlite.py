import pandas as pd
import sqlite3
import sys
import os


cust_id = sys.argv[1]
print(cust_id)

db_path = f"./database_files/{cust_id}/"
run_file = 'run.sh'

with open (run_file) as f:
	for line in f:
	#find line starting with top_n
		if line.startswith('forensics_file_name'):
			#print value after = sign
			forensics_file_name = str(line.split('=')[1].replace('\n','').replace('"',''))
			continue

		if line.startswith('converted_sqlite_file_name'):
			converted_sqlite_file_name = str(line.split('=')[1].replace('\n','').replace('"',''))
			continue

		if line.startswith('forensics_date_format'):
			forensics_date_format = str(line.split('=')[1].replace('\n','').replace('"',''))
			continue
        

# Function to convert CSV to SQLite
def csv_to_sqlite(csv_file_path, sqlite_file_path):
    # Read CSV file into a Pandas DataFrame
    df = pd.read_csv(csv_file_path)

    # Define the columns to keep and their corresponding names
    columns_to_keep = ['Attack Name', 'Attack ID', 'Action', 'Start Time', 'End Time', 'Device IP Address', 'Source IP Address', 'Source Port', 'Destination IP Address', 'Destination Port', 'Protocol', 'Total Mbits Dropped', 'Total Packets Dropped', 'Direction', 'Policy Name', 'Threat Category', 'Duration', 'Max pps', 'Max bps']
    new_column_names = ['name', 'attackIpsId', 'actionType', 'startDate', 'endDate', 'deviceIp', 'sourceAddress', 'sourcePort', 'destAddress', 'destPort', 'protocol', 'packetBandwidth', 'packetCount', 'direction', 'ruleName', 'category', 'duration', 'maxAttackPacketRatePps', 'maxAttackRateBps']
    # Select only the specified columns
    df_selected = df[columns_to_keep]

    # Rename columns
    df_selected.columns = new_column_names
    
	# Multiply values in 'packetBandwidth' column by 1000
    df_selected = df_selected.copy()  # Create a copy to avoid SettingWithCopyWarning
    df_selected['packetBandwidth'] *= 1000

    # Create 'startDate' column
    
    df_selected['startDate'] = pd.to_datetime(df_selected['startDate'], format=forensics_date_format)
    print(f'Creating startDate column using date format {forensics_date_format}')


    df_selected['month'] = df_selected['startDate'].dt.month
    df_selected['year'] = df_selected['startDate'].dt.year
    df_selected['startDayOfMonth'] = df_selected['startDate'].dt.day
    
    

    # Create new columns 'startTime' and 'endTime' with values in epoch format
    df_selected['startTime'] = pd.to_datetime(df_selected['startDate']).dt.floor('us').view('int64') // 10**6
    df_selected['endTime'] = pd.to_datetime(df_selected['endDate']).dt.floor('us').view('int64') // 10**6

    df_selected['deviceName'] =  df_selected['deviceIp']

    # Connect to SQLite database
    conn = sqlite3.connect(sqlite_file_path)

    # Extract table name from CSV file name
    table_name = "attacks"

    # Create a new SQLite table with the correct column names
    cursor = conn.cursor()
    cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS "{table_name}" (
            name TEXT,
            attackIpsId TEXT,
            actionType TEXT,
            startDate DATE,
            endDate DATE,
            deviceIp TEXT,
            deviceName TEXT,
            sourceAddress TEXT,
            sourcePort TEXT,
            destAddress TEXT,
            protocol TEXT,
            packetBandwidth INTEGER,
            packetCount INTEGER,
            direction TEXT,
            ruleName TEXT,
            category TEXT,
            durationRange TEXT,
            averageAttackPacketRatePps INTEGER,
            maxAttackPacketRatePps INTEGER,
            averageAttackRateBps INTEGER,
            maxAttackRateBps INTEGER,
            month INTEGER,
            startTime INTEGER,
            endTime INTEGER,
            year INTEGER

        )
    ''')
    conn.commit()

    # Write the DataFrame to the new table
    df_selected.to_sql(table_name, conn, index=False, if_exists='replace')

    # Close the SQLite connection
    conn.close()

# Example usage


csv_file_path = db_path + forensics_file_name
sqlite_file_path = db_path + converted_sqlite_file_name

csv_to_sqlite(csv_file_path, sqlite_file_path)