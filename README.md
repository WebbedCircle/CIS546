Yousef Ahmed

##  Image Metadata Analysis Web Application  ##
I'll save the overview for the report, and stick to functionality in this README.

I used a Virtual Environment (Venv) to run my assignment application in a completely contained space, so hopefully there are no issues in the isolated directory you use for it.

## Prerequisites
Please ensure you have the following installed in your system
- Python 3.8+ (for running the Flask app)
- Flask (for the web framework)
- Flask-Login (for user authentication)
- SQLite (chosen database backend)
- Pillow (for metadata extraction)

1. If you've set up a virtual environment; For example by typing
   
'python -m venv venv'

into your bash command prompt; you'll have to activate the virtual environment with 

.\venv\Scripts\activate

2. To set up the database and schema;
   SQLite is localized to use everything in schema.sql
   In your command window (Virtual environment with all dependent pre-requisites installed)
   Navigate to the flaskr directory from the github source code, and then run command

   flask initdb

   If successful, you should receive a message confirming that it was initialized. (If this doesn't work, try placing a dash between for init-db)

3. Use the command

   flask run

   to begin the process, and activate the Flash development server on your localhost IP.
   This IP should be http://127.0.0.1:5000/
   
   
4. Enter the localhost IP (shown above) into your web browser's URL. You should now be viewing the web application!

5. (TROUBLESHOOTING): When testing, I've had to run command

   set FLASK_APP=flaskr.flaskr

   (Change "set" to "export" if not on Windows.)
   If you have trouble running the program, try this and then run it again.
