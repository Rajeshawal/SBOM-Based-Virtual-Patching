import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import tkinter.scrolledtext as scrolledtext
import json
import requests
import ast

def extract_cpe(comp):
    cpe = comp.get("cpe", "")
    if isinstance(cpe, dict):
        return cpe.get("cpeName", "")
    if isinstance(cpe, str):
        cpe_str = cpe.strip()
        if cpe_str.startswith("{") and "cpeName" in cpe_str:
            try:
                cpe_dict = ast.literal_eval(cpe_str)
                return cpe_dict.get("cpeName", "")
            except Exception:
                return ""
        else:
            return cpe
    if isinstance(cpe, list):
        for item in cpe:
            if isinstance(item, str):
                return item
            if isinstance(item, dict) and "cpeName" in item:
                return item["cpeName"]
    return ""

class NVDCheckerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SBOM NVD Vulnerability Checker")
        self.sbom_file = ""

        # --- Top frame for SBOM and CVE tables ---
        top_frame = tk.Frame(root)
        top_frame.pack(side="top", fill="both", expand=True, padx=10, pady=5)

        # --- SBOM Components Table (left) ---
        comp_frame = ttk.LabelFrame(top_frame, text="SBOM Components")
        comp_frame.grid(row=0, column=0, sticky="nsew", padx=3)
        comp_frame.rowconfigure(0, weight=1)
        comp_frame.columnconfigure(0, weight=1)
        comp_frame.grid_propagate(True)

        self.comp_tree = ttk.Treeview(
            comp_frame,
            columns=("type", "name", "version", "supplier", "cpe"),
            show="headings"
        )
        for col in ("type", "name", "version", "supplier", "cpe"):
            self.comp_tree.heading(col, text=col.capitalize())
            self.comp_tree.column(col, anchor="center", stretch=True)
        self.comp_tree.grid(row=0, column=0, sticky="nsew")

        comp_vscroll = ttk.Scrollbar(comp_frame, orient="vertical", command=self.comp_tree.yview)
        comp_hscroll = ttk.Scrollbar(comp_frame, orient="horizontal", command=self.comp_tree.xview)
        self.comp_tree.configure(yscroll=comp_vscroll.set, xscroll=comp_hscroll.set)
        comp_vscroll.grid(row=0, column=1, sticky="ns")
        comp_hscroll.grid(row=1, column=0, sticky="ew")

        # --- CVE Results Table (right) ---
        res_frame = ttk.LabelFrame(top_frame, text="CVE Results")
        res_frame.grid(row=0, column=1, sticky="nsew", padx=3)
        res_frame.rowconfigure(0, weight=1)
        res_frame.columnconfigure(0, weight=1)
        res_frame.grid_propagate(True)

        self.res_tree = ttk.Treeview(
            res_frame,
            columns=("component", "cve", "score", "severity", "title", "link"),
            show="headings"
        )
        for col in ("component", "cve", "score", "severity", "title", "link"):
            self.res_tree.heading(col, text=col.capitalize())
            self.res_tree.column(col, anchor="center", stretch=True)
        self.res_tree.grid(row=0, column=0, sticky="nsew")

        res_vscroll = ttk.Scrollbar(res_frame, orient="vertical", command=self.res_tree.yview)
        res_hscroll = ttk.Scrollbar(res_frame, orient="horizontal", command=self.res_tree.xview)
        self.res_tree.configure(yscroll=res_vscroll.set, xscroll=res_hscroll.set)
        res_vscroll.grid(row=0, column=1, sticky="ns")
        res_hscroll.grid(row=1, column=0, sticky="ew")

        # Make both tables expand
        top_frame.columnconfigure(0, weight=1)
        top_frame.columnconfigure(1, weight=1)
        top_frame.rowconfigure(0, weight=1)

        # --- Details Text Area ---
        self.details_text = scrolledtext.ScrolledText(root, height=10, font=("Consolas", 12), state="disabled", wrap="word")
        self.details_text.pack(fill="both", expand=True, padx=10, pady=3)

        # --- Buttons and Status ---
        btn_frame = tk.Frame(root)
        btn_frame.pack(fill="x", padx=10, pady=2)
        ttk.Button(btn_frame, text="Browse SBOM JSON", command=self.browse_sbom).pack(side="left")
        ttk.Button(btn_frame, text="Check Vulnerabilities (NVD)", command=self.check_vulns).pack(side="left", padx=5)
        self.file_label = ttk.Label(btn_frame, text="No SBOM file selected")
        self.file_label.pack(side="left", padx=15)
        self.status_label = ttk.Label(root, text="Ready")
        self.status_label.pack(pady=2)

        self.res_tree.bind("<<TreeviewSelect>>", self.on_result_select)
        self.components = []

    def browse_sbom(self):
        path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if path:
            self.sbom_file = path
            self.file_label.config(text=path)
            self.load_sbom()

    def load_sbom(self):
        self.comp_tree.delete(*self.comp_tree.get_children())
        try:
            with open(self.sbom_file, "r") as f:
                data = json.load(f)
            comps = data.get("components", [])
            self.components = comps
            for comp in comps:
                supplier = comp.get("supplier", {}).get("name", "")
                cpe = extract_cpe(comp)
                self.comp_tree.insert("", "end", values=(
                    comp.get("type", ""),
                    comp.get("name", ""),
                    comp.get("version", ""),
                    supplier,
                    cpe,
                ))
            self.status_label.config(text=f"Loaded {len(comps)} components.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load SBOM:\n{e}")

    def check_vulns(self):
        self.res_tree.delete(*self.res_tree.get_children())
        self.status_label.config(text="Checking vulnerabilities...")
        self.root.update()
        summary_lines = []

        for comp in self.components:
            cpe = extract_cpe(comp)
            name = comp.get("name", "")
            version = comp.get("version", "")
            supplier = comp.get("supplier", {}).get("name", "")
            display_name = f"{name} {version} ({supplier})"
            try:
                if cpe:
                    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
                    params = {"cpeName": cpe, "resultsPerPage": 5}
                else:
                    search_kw = f"{supplier} {name} {version}".strip()
                    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
                    params = {"keywordSearch": search_kw, "resultsPerPage": 5}

                r = requests.get(url, params=params, timeout=15)
                r.raise_for_status()
                results = r.json().get("vulnerabilities", [])
                if not results:
                    self.res_tree.insert("", "end", values=(display_name, "None", "-", "-", "No CVEs found", "-"))
                    summary_lines.append(f"{display_name}\n  No CVEs found.")
                else:
                    for vuln in results:
                        cve_id = vuln.get("cve", {}).get("id", "")
                        desc = vuln.get("cve", {}).get("descriptions", [{}])[0].get("value", "")
                        metrics = vuln.get("cve", {}).get("metrics", {})
                        cvss = "-"
                        severity = "-"
                        if "cvssMetricV31" in metrics:
                            cvssData = metrics["cvssMetricV31"][0]["cvssData"]
                            cvss = cvssData.get("baseScore", "-")
                            severity = cvssData.get("baseSeverity", "-")
                        elif "cvssMetricV30" in metrics:
                            cvssData = metrics["cvssMetricV30"][0]["cvssData"]
                            cvss = cvssData.get("baseScore", "-")
                            severity = cvssData.get("baseSeverity", "-")
                        elif "cvssMetricV2" in metrics:
                            cvssData = metrics["cvssMetricV2"][0]["cvssData"]
                            cvss = cvssData.get("baseScore", "-")
                            severity = metrics["cvssMetricV2"][0].get("baseSeverity", cvssData.get("baseSeverity", "-"))
                        link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                        self.res_tree.insert("", "end", values=(
                            display_name, cve_id, cvss, severity, desc, link
                        ))
                        summary_lines.append(
                            f"{display_name}\n  CVE: {cve_id}\n    Score: {cvss}  Severity: {severity}\n    Desc: {desc[:200]}...\n    Link: {link}\n"
                        )
                self.status_label.config(text=f"Checked {display_name} ({len(results)} CVEs found)")
            except Exception as e:
                self.res_tree.insert("", "end", values=(display_name, "ERROR", "-", "-", str(e), "-"))
                self.status_label.config(text=f"Error for {display_name}: {e}")
                summary_lines.append(f"{display_name}\n  ERROR: {e}")

        self.status_label.config(text="Done.")
        alert_text = "\n\n".join(summary_lines)
        if not alert_text:
            alert_text = "No components were processed."
        if len(alert_text) > 5000:
            alert_text = alert_text[:5000] + "\n\n...Truncated. Export table for full details."
        messagebox.showinfo("NVD Vulnerability Scan Summary", alert_text)

    def on_result_select(self, event):
        selected = self.res_tree.selection()
        if selected:
            row = self.res_tree.item(selected[0])["values"]
            columns = self.res_tree["columns"]
            details = ""
            for col, val in zip(columns, row):
                details += f"{col.capitalize()}:\n{val}\n\n"
            self.details_text.config(state="normal")
            self.details_text.delete("1.0", tk.END)
            self.details_text.insert(tk.END, details)
            self.details_text.config(state="disabled")


if __name__ == "__main__":
    root = tk.Tk()

    # Responsive window size
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    root.geometry(f"{int(screen_width * 0.9)}x{int(screen_height * 0.85)}")
    root.minsize(800, 600)
    root.update_idletasks()

    app = NVDCheckerApp(root)
    root.mainloop()
