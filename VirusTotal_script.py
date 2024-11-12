import os
import requests
import tkinter as tk
from tkinter import filedialog, messagebox
import sys


API_KEY = 'a09411762289a71323ee317c746e9a6d42664d98bb90afd5c770b2e7fd0a44bb'
VT_URL = 'https://www.virustotal.com/api/v3/files'

headers = {
    "x-apikey": API_KEY
}


virus_count = 0



def process_file(file_path):
    global virus_count
    print(f"Uploading file: {file_path}")
    response = upload_file(file_path)
    if not is_malware(response):
        print(f"{file_path} is safe")
    else:
        print(f"{file_path} is malicious")
        virus_count += 1  
        update_virus_counter()  


def upload_file(file_path):   
    with open(file_path, 'rb') as file:
        return requests.post(VT_URL, headers=headers, files={"file": file})


def is_malware(response_json):
    response_data = response_json.json()    
    stats = response_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})   
    malicious_count = stats.get('malicious', 0)
    if malicious_count > 0:
        return True
    else:
        return False


def process_files_in_folder(folder_path):
    
    try:
        for file_name in os.listdir(folder_path):
            file_path = os.path.join(folder_path, file_name)

            if os.path.isfile(file_path):  
                process_file(file_path)
            else:
                print(f"{file_name} is a directory, skipping.")
    except Exception as e:
        display_error(f"Error processing folder: {e}")

""""GUI RELATED"""
def select_folder():  
    folder_path = filedialog.askdirectory()
    if folder_path:
        process_files_in_folder(folder_path)
    else:
        display_error("No folder selected.")


def display_error(message):   
    error_text.insert(tk.END, message + "\n")
    error_text.yview(tk.END)


def update_virus_counter():   
    virus_counter_label.config(text=f"Malicious Files: {virus_count}")



class OutputRedirector:
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, message):       
        self.text_widget.insert(tk.END, message)
        self.text_widget.yview(tk.END)

    def flush(self):
        pass  


def clear_chat():    
    error_text.delete(1.0, tk.END)  



root = tk.Tk()
root.title("VirusTotal File Checker")


select_button = tk.Button(root, text="Select Folder", command=select_folder)
select_button.pack(pady=10)


clear_button = tk.Button(root, text="Clear Chat", command=clear_chat)
clear_button.pack(pady=10)


error_text = tk.Text(root, height=10, width=50)
error_text.pack(pady=20)


virus_counter_label = tk.Label(root, text="Malicious Files: 0", font=('Arial', 14))
virus_counter_label.pack(pady=10)


sys.stdout = OutputRedirector(error_text)


root.mainloop()
