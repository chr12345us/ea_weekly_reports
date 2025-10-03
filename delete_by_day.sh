#!/bin/bash

# Check usage
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <database_file> <start_day> <end_day>"
    echo "Example: $0 mydb.sqlite 05 20"
    exit 1
fi

DB="$1"
START_DAY=$(printf "%02d" $2)
END_DAY=$(printf "%02d" $3)

if [ ! -f "$DB" ]; then
    echo "Database file '$DB' not found!"
    exit 2
fi

# Try to get year and month from earliest date in 'attacks' or any table with 'DateTime'
DATE_SOURCE=$(sqlite3 "$DB" "SELECT startDate FROM attacks ORDER BY startDate LIMIT 1;")

# If not found, try to find DateTime in any other table
if [ -z "$DATE_SOURCE" ]; then
    for TABLE in $(sqlite3 "$DB" "SELECT name FROM sqlite_master WHERE type='table';"); do
        HAS_DATETIME=$(sqlite3 "$DB" "PRAGMA table_info($TABLE);" | awk -F'|' '$2 == "DateTime" {print $2}')
        if [ -n "$HAS_DATETIME" ]; then
            DATE_SOURCE=$(sqlite3 "$DB" "SELECT DateTime FROM $TABLE ORDER BY DateTime LIMIT 1;")
            if [ -n "$DATE_SOURCE" ]; then
                break
            fi
        fi
    done
fi

# Still no date?
if [ -z "$DATE_SOURCE" ]; then
    echo "Could not find a sample date to extract year/month."
    exit 3
fi
# Extract year and month (assumes format YYYY-MM-DD HH:MM:SS)
YEAR=$(echo "$DATE_SOURCE" | cut -d'-' -f1)
MONTH=$(echo "$DATE_SOURCE" | cut -d'-' -f2)

START_DATE="${YEAR}-${MONTH}-${START_DAY} 00:00:00"
END_DATE="${YEAR}-${MONTH}-${END_DAY} 23:59:59"

# Generate SQL
SQL_CMDS=""
TABLES=$(sqlite3 "$DB" "SELECT name FROM sqlite_master WHERE type='table';")

for TABLE in $TABLES; do
    if [ "$TABLE" == "attacks" ]; then
        COL_NAME="startDate"
    else
        HAS_DATETIME=$(sqlite3 "$DB" "PRAGMA table_info($TABLE);" | awk -F'|' '$2 == "DateTime" {print $2}')
        if [ -z "$HAS_DATETIME" ]; then
            continue
        fi
        COL_NAME="DateTime"
    fi

    SQL_CMDS+="DELETE FROM $TABLE WHERE $COL_NAME < '$START_DATE' OR $COL_NAME > '$END_DATE';\n"
done

# Print results
echo -e "Auto-detected date range: $START_DATE to $END_DATE"
echo -e "\nPlanned SQL deletion commands:\n"
echo -e "$SQL_CMDS"

# Uncomment to execute
echo -e "$SQL_CMDS" | sqlite3 "$DB"
#echo -e "\nNOTE: SQL NOT EXECUTED. Uncomment the execution line to apply deletions."

# Uncomment to compact the database after deletions
sqlite3 "$DB" "VACUUM;"

