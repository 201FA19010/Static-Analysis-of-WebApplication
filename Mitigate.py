import re
sql_injection_mit="""
 def get_user_by_username(username):
    # Safe from SQL Injection
    query = "SELECT * FROM users WHERE username = ?"
    print(f"Executing query: {query} with parameter {username}")
    cursor.execute(query, (username,))
    return cursor.fetchall()
"""
sql_fileExtension_mit="""
import os
def is_safe_extension(file_name):
    safe_extensions = ['.txt', '.log', '.csv']
    ext = os.path.splitext(file_name)[1].lower()
    return ext in safe_extensions
def create_file_with_extension(file_name):
    if not is_safe_extension(file_name):
        print(f"Error: '{file_name}' has an unsafe extension.")
        return
    try:
        with open(file_name, 'w') as file:
            file.write("This is a test file.")
        print(f"File '{file_name}' created successfully.")
    except Exception as e:
        print(f"Error creating file '{file_name}': {e}")
if __name__ == "__main__":
    dangerous_files = ["malicious.exe", "dangerous.bat", "harmful.scr", "risky.ps1", "safe_file.txt"]
    print("Creating files with extensions:")
    for file in dangerous_files:
        create_file_with_extension(file)

"""
xss_script_mit="""
from flask import Flask, request, render_template

app = Flask(__name__)
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        user_input = request.form['user_input']
        return render_template('index.html', user_input=user_input)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)

"""
def detect_security_vulnerabilities(code):
    vulnerabilities = []
    
    # Patterns to detect SQL Injection vulnerabilities
    sql_patterns = [
        r'\bselect\b.*\bfrom\b.*\bwhere\b.*[\'"]\b.*[\'"]',  # Direct user input in WHERE clause
        r'\binsert\b.*\binto\b.*[\'"]\b.*[\'"]',  # Direct user input in INSERT statement
        r'\bupdate\b.*\bset\b.*[\'"]\b.*[\'"]',  # Direct user input in UPDATE statement
        r'\bdelete\b.*\bfrom\b.*[\'"]\b.*[\'"]',  # Direct user input in DELETE statement
        r'\bor\b.*\b1=1\b',  # Common SQL injection pattern
        r'\band\b.*\b1=1\b',  # Common SQL injection pattern
        r'\bunion\b.*\bselect\b.*[\'"]\b.*[\'"]',  # Direct user input in UNION SELECT statement
        r'\bexec\b.*\b(?:s|x)p_cmdshell\b'  # EXEC xp_cmdshell statement
    ]
    
    for pattern in sql_patterns:
        if re.search(pattern, code, re.IGNORECASE):
            vulnerabilities.append(f'Possible SQL Injection: {pattern}')
    #to detect dangerous file extensions
    disallowed_extensions = [".exe", ".bat", ".scr", ".ps1"]
    if any(code.lower().endswith(ext) for ext in disallowed_extensions):
        vulnerabilities.append("Potential File Extension Attack (Disallowed Extension)")

    #to detect XSS vulnerabilities
    xss_patterns = [
        r'<\s*script\s*>',
        r'on\w+\s*=\s*".*?"',
        r'on\w+\s*=\s*\'.*?\'',
        r'on\w+\s*=\s*[^>\s]*'
    ]

    # Only check XSS patterns if the code contains HTML
    if '<html' in code or '<body' in code or '<script' in code:
        for pattern in xss_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                vulnerabilities.append(f'Possible XSS Vulnerability: {pattern}')

    # Patterns to detect Path Traversal vulnerabilities
    path_traversal_pattern = r'\.\./|\.\.\\'
    if re.search(path_traversal_pattern, code):
        vulnerabilities.append('Possible Path Traversal Vulnerability')

    # Patterns to detect Command Injection vulnerabilities
    command_injection_pattern = r'[`|;&]'
    if re.search(command_injection_pattern, code):
        vulnerabilities.append('Possible Command Injection Vulnerability')

    return vulnerabilities

# Example usage of the improved detection function
if __name__ == "__main__":
    test_codes = [
        sql_injection_mit,
        sql_fileExtension_mit,
        xss_script_mit

    ]

    for code in test_codes:
        vulnerabilities = detect_security_vulnerabilities(code)
        print(f"Code: {code}")
        if vulnerabilities:
            print("Potential vulnerabilities found:")
            for vulnerability in vulnerabilities:
                print(f" - {vulnerability}")
        else:
            print("No vulnerabilities found.")
        print("\n")
        if(len(vulnerabilities)>4):
          print("security level: 1 out 5")
        elif(len(vulnerabilities)==3):
          print("security level: 2 out 5")
        elif(len(vulnerabilities)==2):
          print("security level: 3 out 5")
        elif(len(vulnerabilities)==1):
          print("security level: 4 out 5")
        elif(len(vulnerabilities)==0):
          print("security level: 5 out 5")

