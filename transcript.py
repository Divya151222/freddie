from azure.communication.email import EmailClient
import sqlite3
from datetime import datetime

# Azure Email Communication Service connection string
connection_string = "endpoint=https://freddie-email.india.communication.azure.com/;accesskey=Czr5YUAXaL6ngxsZRg8K0TJ04MA6OOc7xIJNJ4HIXYtgKVqnogqbJQQJ99AHACULyCppJDEQAAAAAZCSvvrg"
client = EmailClient.from_connection_string(connection_string)

# Database and topic details
db_path = "path_to_your_database.db"  # Update with the path to your SQLite database
topic = "Enhancing Communication Skills for BBA Graduates: A Comprehensive Guide to Excelling in Job Interviews"
to_email = "korameghu16@gmail.com"
subject = "Transcript for Your Topic"

# Fetch transcript from the database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

query = """
SELECT user_message, bot_response, created_at 
FROM conversation 
WHERE topic = ?
"""
cursor.execute(query, (topic,))
rows = cursor.fetchall()

conn.close()

# Generate email content
plain_text_body = f"Transcript for Topic: {topic}\n\n"
html_body = f"<h1>Transcript for Topic: {topic}</h1><ul>"

for idx, (user_message, bot_response, created_at) in enumerate(rows, start=1):
    created_at_str = created_at if created_at else "Unknown"
    plain_text_body += f"\n{idx}. User: {user_message}\n   Bot: {bot_response}\n   Time: {created_at_str}\n"
    html_body += f"<li><b>User:</b> {user_message}<br><b>Bot:</b> {bot_response}<br><b>Time:</b> {created_at_str}</li>"

html_body += "</ul>"

# Initialize the email message
message = {
    "senderAddress": "DoNotReply@eduvitz.co.in",  # Update with your domain
    "recipients": {
        "to": [{"address": to_email}],
        "cc": []  # Initialize CC as an empty list
    },
    "content": {
        "subject": subject,
        "plainText": plain_text_body,
        "html": html_body
    },
}

# Send the email
try:
    response = client.send(message)
    print(f"Email sent successfully! Message ID: {response['messageId']}")
except Exception as e:
    print(f"Failed to send email: {str(e)}")
//home//sumaiya//freddie//freddie_chatbot//instance//users.db