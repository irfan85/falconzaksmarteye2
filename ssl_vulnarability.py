import os
import subprocess
import time
import sys
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init()

def run_testssl_script(url):
    try:
        # Construct the command to run testssl with the URL
        command = ["testssl", url]
        
        # Print the message
        print(f"\n{Fore.YELLOW}Falconzak Smart Eye is scanning SSL Vulnerabilities for {url}. This may take a few minutes, stay calm!{Style.RESET_ALL}\n")
        
        # Start the timer
        start_time = time.time()
        
        # Run the command and capture the output
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Sequentially output the scan results and elapsed time
        full_output = ""
        while True:
            elapsed_time = time.time() - start_time
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                full_output += output
                print(output.strip())
        
        # Ensure all remaining output is printed
        remaining_output, _ = process.communicate()
        full_output += remaining_output
        print(remaining_output)
        
        vulnerabilities_found = False
        
        # Extracting and printing vulnerability information
        if "Testing vulnerabilities" in full_output:
            vulnerabilities_found = True
            full_output += "\n\nFollowing Vulnerabilities have been found by Falconzak Smart Eye:\n"
            print("\n\u001b[4m\u001b[1mFollowing Vulnerabilities have been found by Falconzak Smart Eye:\u001b[0m\n")
            vuln_lines = [line.strip() for line in full_output.split('\n') if "VULNERABLE" in line]
            if vuln_lines:
                for vuln_line in vuln_lines:
                    full_output += vuln_line + "\n"
                    print(vuln_line)
            else:
                full_output += "No Vulnerabilities found\n"
                print("No Vulnerabilities found")
        
        # Extracting and printing grade information
        if "Rating (experimental)" in full_output:
            full_output += "\nGrade information:\n"
            print("\nGrade information:")
            grade_lines = [line.strip() for line in full_output.split('\n') if "Overall Grade" in line]
            for grade_line in grade_lines:
                grade = grade_line.split(":")[-1].strip()
                full_output += "Overall Grade: " + grade + "\n"
                print("Overall Grade:", grade)
            
            # Print Grade cap reasons
            grade_cap_reasons = [line.strip() for line in full_output.split('\n') if "Grade cap reasons" in line]
            if grade_cap_reasons:
                full_output += "\nGrade cap reasons:\n"
                print("\nGrade cap reasons:")
                for reason in grade_cap_reasons:
                    full_output += reason + "\n"
                    print(reason)

        # Print the explanation of grades
        full_output += "\nOverall grade stats:\n" + grades_explanation()
        print_grades_explanation()

        # Determine and print the score based on the presence of vulnerabilities
        score = 0 if vulnerabilities_found else 1
        full_output += f"\nScore: {score}\n"
        print_score(score)

        # Print the elapsed time
        elapsed_time = time.time() - start_time
        full_output += f"\nTime taken: {round(elapsed_time, 2)} seconds\n"
        print(f"\nTime taken: {round(elapsed_time, 2)} seconds")

        # Add the note regarding the scoring system
        note = "\nNOTE: Falconzak SmartEye Pro provides a score of 1 if there are no SSL vulnerabilities found, otherwise 0.\n"
        full_output += note
        print(note)

        # Ask the user if they want to save the report
        while True:
            save_report = input("\nDo you want to save the report? (Y/N): ").strip().upper()
            if save_report in ['Y', 'N']:
                break
            print(f"{Fore.RED}Invalid input! Please enter 'Y' or 'N'.{Style.RESET_ALL}")

        if save_report == 'Y':
            save_report_to_file(url, full_output)

            # Ask the user what they want to do next
            print("\nWhat would you like to do next?")
            print("1. Go to Main Menu")
            print("2. Exit")
            while True:
                next_choice = input("\nEnter your choice (1/2): ").strip()
                if next_choice in ['1', '2']:
                    break
                print(f"{Fore.RED}Invalid input! Please enter '1' or '2'.{Style.RESET_ALL}")

            if next_choice == '1':
                os.system('python3 /home/kali/Documents/capstone2_codes/main_menu.py')
            elif next_choice == '2':
                print(f"{Fore.GREEN}Exiting Falconzak SmartEye. Goodbye!{Style.RESET_ALL}")
                sys.exit(0)

    except subprocess.CalledProcessError as e:
        # If there's an error running the command, print the error message
        print("Error:", e)

def print_grades_explanation():
    print("\n\u001b[4m\u001b[1mOverall grade stats:\u001b[0m")
    print(grades_explanation())

def grades_explanation():
    return """
A+: Excellent security, top-grade.
A: Very good security.
B: Acceptable security, with room for improvement.
C: Average security.
D: Below average security.
E: Indicates errors or critical issues.
F: Failing grade, significant security issues.
T: Trusted, indicating trustworthiness.
Secure/Insecure: Binary security indication.
Not Rated: No specific grade assigned.
    """

def print_score(score):
    if score == 0:
        print(f"{Fore.RED}Score: {score}{Style.RESET_ALL}\n")
    else:
        print(f"{Fore.GREEN}Score: {score}{Style.RESET_ALL}\n")

def save_report_to_file(url, report_content):
    directory = "/home/kali/capstone2/ssl_vulnarability_scan_result/"
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_url = url.replace("://", "_").replace("/", "_")
    filename = f"SSL_Scan_{safe_url}_{timestamp}.txt"
    filepath = os.path.join(directory, filename)

    try:
        with open(filepath, 'w') as file:
            file.write(report_content)
        print(f"{Fore.BLUE}Report saved to: {filepath}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error saving report: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    url = input("Enter the URL: ")
    run_testssl_script(url)
