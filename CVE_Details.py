import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import pandas as pd
import requests
import webbrowser

class CVEGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CVE Dropdown Viewer")
        self.root.geometry("800x400")

        self.upload_btn = tk.Button(root, text="Upload CVE CSV File", command=self.load_csv)
        self.upload_btn.pack(pady=10)

        self.dropdown_frame = tk.Frame(root)
        self.dropdown_frame.pack(pady=10)

        self.combo = ttk.Combobox(self.dropdown_frame, width=80, state="readonly")
        self.combo.pack(side='left', padx=10)

        self.show_btn = tk.Button(self.dropdown_frame, text="Show Details", command=self.show_details)
        self.show_btn.pack(side='left')

        self.df = None

    def load_csv(self):
        file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if not file_path:
            return
        try:
            self.df = pd.read_csv(file_path)
            self.combo['values'] = [f"{row['cve']} - {row['title'][:60]}..." for _, row in self.df.iterrows()]
            self.combo.current(0)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {str(e)}")

    def is_url_alive(self, url):
        try:
            r = requests.head(url, allow_redirects=True, timeout=5)
            return r.status_code == 200
        except:
            return False

    def get_mitigation_info(self, cve_id):
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                items = data.get('vulnerabilities', [])
                if not items:
                    return []
                references = items[0]['cve'].get('references', [])

                links = []
                for ref in references:
                    url = ref['url']
                    label = url.lower()
                    if any(keyword in label for keyword in ['advisory', 'patch', 'mitigation', 'update', 'productcert', 'cert', 'siemens', 'exploit', 'github.com/exploit', 'exploit-db', 'packetstorm', 'metasploit']):
                        if self.is_url_alive(url):
                            links.append(url)
                return links
            else:
                return []
        except Exception as e:
            return []

    def show_details(self):
        if self.df is None or self.df.empty or self.combo.current() == -1:
            return
        row = self.df.iloc[self.combo.current()]

        popup = tk.Toplevel(self.root)
        popup.title(f"Details: {row['cve']}")
        popup.geometry("600x500")

        close_btn = tk.Button(popup, text="X", command=popup.destroy)
        close_btn.pack(anchor='ne', padx=5, pady=5)

        text_area = scrolledtext.ScrolledText(popup, wrap='word')
        text_area.pack(fill='both', expand=True, padx=10, pady=10)

        detail_text = (
            f"Component: {row['component']}\n"
            f"CVE: {row['cve']}\n"
            f"Score: {row['score']}\n"
            f"Severity: {row['severity']}\n"
            f"Title: {row['title']}\n"
            f"Link: {row['link']}"
        )
        text_area.insert('1.0', detail_text)
        text_area.configure(state='disabled')

        def show_mitigation():
            links = self.get_mitigation_info(row['cve'])
            if links:
                link_window = tk.Toplevel(popup)
                link_window.title("Mitigation and Exploit Links")
                link_window.geometry("600x400")

                info_label = tk.Label(link_window, text="Click a link to open in browser:", font=("Arial", 10, "bold"))
                info_label.pack(pady=10)

                for link in links:
                    link_btn = tk.Button(link_window, text=link, wraplength=550, anchor='w', justify='left', relief='groove', command=lambda url=link: webbrowser.open(url))
                    link_btn.pack(fill='x', padx=10, pady=2)
            else:
                messagebox.showinfo("No Info", "No mitigation or exploit links found.")

        mitigation_btn = tk.Button(popup, text="Get Mitigation Info", command=show_mitigation)
        mitigation_btn.pack(pady=5)

if __name__ == '__main__':
    root = tk.Tk()
    app = CVEGUI(root)
    root.mainloop()
