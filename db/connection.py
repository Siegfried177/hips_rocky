import psycopg2
from dotenv import load_dotenv
import os

load_dotenv() # Take environment variables from '.env' file like the password for the database connection

# Database configuration using environment variables with default values
DB_CONFIG = {
    "dbname": os.getenv("DB_NAME", "hips_db"),
    "user": os.getenv("DB_USER", "hips_admin"),
    "password": os.getenv("DB_PASSWORD", ""),
    "host": os.getenv("DB_HOST", "localhost"),
    "port": os.getenv("DB_PORT", "5432"),
}

# Function to get a connection to the PostgreSQL database using the configuration defined above
def get_connection():
    return psycopg2.connect(**DB_CONFIG)