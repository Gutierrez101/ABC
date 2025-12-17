import tkinter as tk
from tkinter import ttk
import joblib
import numpy as np
from urllib.parse import urlparse
import re
import pandas as pd

# =================== CARGA DEL MODELO ===================
try:
    modelo = joblib.load("modelo_random_forest_proyecto.pkl")
except:
    modelo = None
    print("❌ Error: No se pudo cargar el modelo .pkl")

# =================== EXTRACCIÓN DE FEATURES ===================
def extraer_features(url):
    parsed = urlparse(url)
    hostname = parsed.netloc
    path = parsed.path

    # ---- Features reales (basadas en el dataset) ----
    UsingIP = 1 if re.match(r"\d+\.\d+\.\d+\.\d+", hostname) else 0
    LongURL = 1 if len(url) > 75 else 0
    ShortURL = 1 if len(url) < 15 else 0
    SymbolAt = 1 if "@" in url else 0
    Redirecting = 1 if "//" in path else 0
    PrefixSuffix = 1 if "-" in hostname else 0
    SubDomains = hostname.count(".") - 1
    HTTPS = 1 if url.startswith("https") else 0

    # ---- Features externas / avanzadas → NEUTRAS ----
    neutral = 0

    features = [
        0,                  # Index
        UsingIP,            # UsingIP
        LongURL,            # LongURL
        ShortURL,           # ShortURL
        SymbolAt,           # Symbol@
        Redirecting,        # Redirecting//
        PrefixSuffix,       # PrefixSuffix-
        SubDomains,         # SubDomains
        HTTPS,              # HTTPS
        neutral,            # DomainRegLen
        neutral,            # Favicon
        neutral,            # NonStdPort
        neutral,            # HTTPSDomainURL
        neutral,            # RequestURL
        neutral,            # AnchorURL
        neutral,            # LinksInScriptTags
        neutral,            # ServerFormHandler
        neutral,            # InfoEmail
        neutral,            # AbnormalURL
        neutral,            # WebsiteForwarding
        neutral,            # StatusBarCust
        neutral,            # DisableRightClick
        neutral,            # UsingPopupWindow
        neutral,            # IframeRedirection
        neutral,            # AgeofDomain
        neutral,            # DNSRecording
        neutral,            # WebsiteTraffic
        neutral,            # PageRank
        neutral,            # GoogleIndex
        neutral,            # LinksPointingToPage
        neutral             # StatsReport
    ]

    return np.array(features).reshape(1, -1)

# =================== FUNCIÓN DE ANÁLISIS ===================
def analizar_url():
    url = entry_url.get().strip()

    if not url:
        resultado_label.config(text="⚠ Ingresa una URL", foreground="#f39c12")
        return

    if modelo is None:
        resultado_label.config(text="❌ Modelo no cargado", foreground="#e74c3c")
        return

    try:
        features = extraer_features(url)
        # Convertimos a DataFrame para eliminar el warning de feature names
        X = pd.DataFrame(features, columns=modelo.feature_names_in_)
        pred = modelo.predict(X)[0]

        if pred == -1:
            resultado_label.config(text="⚠ PHISHING", foreground="#e74c3c")
        else:
            resultado_label.config(text="✓ SEGURO", foreground="#2ecc71")

    except Exception as e:
        resultado_label.config(text="❌ Error en análisis", foreground="#e67e22")
        print("Detalle:", e)

# =================== UI ===================
root = tk.Tk()
root.title("PhishGuard")
root.geometry("450x240")
root.resizable(False, False)
root.configure(bg="#1e1e1e")

frame = tk.Frame(root, bg="#1e1e1e")
frame.pack(expand=True)

title = tk.Label(
    frame,
    text="Detector de Phishing",
    font=("Segoe UI Semibold", 16),
    bg="#1e1e1e",
    fg="white"
)
title.pack(pady=(0, 15))

entry_url = ttk.Entry(frame, width=50)
entry_url.pack(pady=5)
entry_url.insert(0, "https://")

btn = ttk.Button(frame, text="Analizar URL", command=analizar_url)
btn.pack(pady=12)

resultado_label = tk.Label(
    frame,
    text="",
    font=("Segoe UI Semibold", 14),
    bg="#1e1e1e"
)
resultado_label.pack(pady=10)

root.mainloop()
