import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk
import requests
import pandas as pd
from io import BytesIO

API_KEY = "c1a55456-1dcb-4e48-b6c6-8b5fabb5a859"


def search_part():
    part_number = entry_part.get().strip()
    if not part_number:
        messagebox.showerror("Ошибка", "Введите Part Number")
        return

    url = f"https://api.mouser.com/api/v1/search/partnumber?apiKey={API_KEY}"
    payload = {"SearchByPartRequest": {"mouserPartNumber": part_number}}

    try:
        r = requests.post(url, json=payload)
        data = r.json()

        parts = data.get("SearchResults", {}).get("Parts", [])
        if not parts:
            messagebox.showinfo("Результат", "Компонент не найден")
            return

        item = parts[0]
        result = {
            "Product Category": item.get("Category"),
            "Stock": item.get("Availability"),
            "Factory Lead Time": item.get("LeadTime"),
            "Unit Price (1)": item.get("PriceBreaks", [{}])[0].get("Price"),
            "Description": item.get("Description"),
            "Product Link": item.get("ProductDetailUrl")
        }

        global df
        df = pd.DataFrame([result])

        for i in table.get_children():
            table.delete(i)
        for key, value in result.items():
            table.insert("", tk.END, values=(key, value))

    except Exception as e:
        messagebox.showerror("Ошибка", f"Произошла ошибка: {e}")


def save_to_excel():
    if 'df' not in globals():
        messagebox.showerror("Ошибка", "Сначала выполните поиск")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".xlsx",
                                             filetypes=[("Excel files", "*.xlsx")])
    if file_path:
        df.to_excel(file_path, index=False)
        messagebox.showinfo("Сохранено", f"Данные сохранены в {file_path}")



root = tk.Tk()
root.title("Mouser Part Search")
root.geometry("800x400")
root.configure(bg="#f0f0f0")


frame_top = tk.Frame(root, bg="#f0f0f0")
frame_top.pack(fill="x", pady=10)

tk.Label(frame_top, text="Введите Part Number:", bg="#f0f0f0", font=("Segoe UI", 10)).pack(side="left", padx=5)
entry_part = tk.Entry(frame_top, width=40, font=("Segoe UI", 10))
entry_part.pack(side="left", padx=5)

btn_search = tk.Button(frame_top, text="🔍 Найти", command=search_part, bg="#4CAF50", fg="white", font=("Segoe UI", 10))
btn_search.pack(side="left", padx=5)

btn_save = tk.Button(frame_top, text="💾 Сохранить в Excel", command=save_to_excel, bg="#2196F3", fg="white", font=("Segoe UI", 10))
btn_save.pack(side="left", padx=5)


frame_main = tk.Frame(root, bg="#f0f0f0")
frame_main.pack(fill="both", expand=True, padx=10, pady=10)


style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview", font=("Segoe UI", 10), rowheight=25)
style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

table = ttk.Treeview(frame_main, columns=("Характеристика", "Значение"), show="headings", height=10)
table.heading("Характеристика", text="Характеристика")
table.heading("Значение", text="Значение")
table.column("Характеристика", width=200)
table.column("Значение", width=400)
table.pack(side="left", fill="both", expand=True)


scrollbar = ttk.Scrollbar(frame_main, orient="vertical", command=table.yview)
table.configure(yscrollcommand=scrollbar.set)
scrollbar.pack(side="right", fill="y")

root.mainloop()
