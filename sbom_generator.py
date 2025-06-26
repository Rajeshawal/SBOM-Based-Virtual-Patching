import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import uuid
from datetime import datetime
import requests

def get_cyclonedx_sbom(components):
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tools": [{
                "vendor": "Custom ICS SBOM Generator",
                "name": "ICS SBOM GUI",
                "version": "1.0"
            }]
        },
        "components": components
    }
    return sbom

class SBOMApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ICS Device SBOM Generator - CycloneDX")
        self.components = []

        self.mainframe = ttk.Frame(root, padding="12 12 12 12")
        self.mainframe.grid(column=0, row=0, sticky=(tk.N, tk.W, tk.E, tk.S))
        self.fields = {}

        # Fields for a component
        entries = [
            ("Name", "name"),
            ("Version", "version"),
            ("Type", "type"),    # application, firmware, library, device, etc.
            ("Supplier", "supplier"),
            ("Description", "description"),
            ("CPE", "cpe")
        ]
        for i, (label, key) in enumerate(entries):
            ttk.Label(self.mainframe, text=label).grid(column=0, row=i, sticky=tk.W)
            entry = ttk.Entry(self.mainframe, width=44)
            entry.grid(column=1, row=i, sticky=(tk.W, tk.E))
            self.fields[key] = entry

        ttk.Label(self.mainframe, text="Type (application, device, library, firmware, etc.)").grid(column=2, row=2, sticky=tk.W)

        # Buttons
        ttk.Button(self.mainframe, text="Find CPE", command=self.find_cpe).grid(column=2, row=0, pady=8)
        ttk.Button(self.mainframe, text="Add Component", command=self.add_component).grid(column=0, row=7, pady=8)
        ttk.Button(self.mainframe, text="Generate SBOM (JSON)", command=self.save_sbom).grid(column=1, row=7, pady=8)

        # Listbox to show added components
        self.comp_list = tk.Listbox(self.mainframe, width=90)
        self.comp_list.grid(column=0, row=8, columnspan=3, pady=6)

    def find_cpe(self):
        name = self.fields["name"].get().strip()
        version = self.fields["version"].get().strip()
        supplier = self.fields["supplier"].get().strip()

        if not name or not supplier:
            messagebox.showwarning("Missing Info", "Please fill both Supplier and Name fields for CPE search.")
            return

        try:
            url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
            params = {
                "keywordSearch": f"{supplier} {name}",
                "resultsPerPage": 20
            }
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            cpe_matches = response.json().get("products", [])

            found_cpe = ""
            for product in cpe_matches:
                cpe = product.get("cpe", "")
                if version and f":{version}:" in cpe:
                    found_cpe = cpe
                    break
            if not found_cpe and cpe_matches:
                found_cpe = cpe_matches[0].get("cpe", "")

            self.fields["cpe"].delete(0, tk.END)
            if found_cpe:
                self.fields["cpe"].insert(0, found_cpe)
                messagebox.showinfo("CPE Found", f"Found CPE:\n{found_cpe}")
            else:
                messagebox.showinfo("No CPE Found", "No CPE found for this component.")
        except Exception as e:
            messagebox.showerror("CPE Lookup Error", f"Error contacting NVD CPE API:\n{e}")

    def add_component(self):
        # Clear previous components
        self.components.clear()
        self.comp_list.delete(0, tk.END)

        comp = {}
        missing = []
        for key, entry in self.fields.items():
            value = entry.get().strip()
            if key in ["name", "version", "type"] and not value:
                missing.append(key)
            comp[key] = value
        if missing:
            messagebox.showwarning("Missing Info", f"Please fill: {', '.join(missing)}")
            return

        # Prepare component dict for CycloneDX
        comp_cdx = {
            "type": comp["type"],
            "name": comp["name"],
            "version": comp["version"]
        }
        if comp["supplier"]:
            comp_cdx["supplier"] = {"name": comp["supplier"]}
        if comp["description"]:
            comp_cdx["description"] = comp["description"]
        if comp["cpe"]:
            comp_cdx["cpe"] = comp["cpe"]

        self.components.append(comp_cdx)
        self.comp_list.insert(tk.END, f'{comp["type"]}: {comp["name"]} v{comp["version"]} ({comp["supplier"]}) | CPE: {comp["cpe"]}')

        for entry in self.fields.values():
            entry.delete(0, tk.END)

    def save_sbom(self):
        if not self.components:
            messagebox.showwarning("No Components", "Add at least one component first.")
            return
        sbom = get_cyclonedx_sbom(self.components)
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if not file_path:
            return
        with open(file_path, "w") as f:
            json.dump(sbom, f, indent=2)
        messagebox.showinfo("SBOM Saved", f"SBOM saved to {file_path}")

if __name__ == "__main__":
    root = tk.Tk()
    SBOMApp(root)
    root.mainloop()