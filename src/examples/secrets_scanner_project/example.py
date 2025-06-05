import os

def connect_to_db():
    host = "localhost"
    port = 5432
    username = "appuser"
    password = "hunter2" 
    service_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" 

def main():
    print("Starting app...")
    connect_to_db()

if __name__ == "__main__":
    main()
