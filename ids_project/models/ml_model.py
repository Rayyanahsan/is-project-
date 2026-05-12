"""
ml_model.py  —  Scikit-learn Random Forest IDS classifier.
Trains on network_traffic.csv and saves model artifacts.
"""

import os, pickle, warnings
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (accuracy_score, f1_score,
                             classification_report, confusion_matrix)
warnings.filterwarnings("ignore")

FEATURE_COLS  = ["src_port","dst_port","packet_count","byte_count",
                 "duration_ms","packets_per_sec","avg_packet_size"]
PROTOCOL_MAP  = {"TCP":0,"UDP":1,"ICMP":2}
FLAG_MAP      = {"SYN":0,"ACK":1,"SYN-ACK":2,"FIN":3,"RST":4,"PSH-ACK":5}

MODEL_DIR     = "models"
MODEL_PATH    = f"{MODEL_DIR}/ids_model.pkl"
SCALER_PATH   = f"{MODEL_DIR}/scaler.pkl"
ENCODER_PATH  = f"{MODEL_DIR}/label_encoder.pkl"


# ── helpers ─────────────────────────────────────────────────────────────────

def _encode(df: pd.DataFrame) -> pd.DataFrame:
    d = df.copy()
    d["protocol_enc"] = d["protocol"].map(PROTOCOL_MAP).fillna(0).astype(int)
    d["flag_enc"]      = d["flag"].map(FLAG_MAP).fillna(0).astype(int)
    return d[FEATURE_COLS + ["protocol_enc","flag_enc"]].fillna(0)


# ── train ────────────────────────────────────────────────────────────────────

def train_model(data_path: str = "data/network_traffic.csv") -> dict:
    print("📊 Loading dataset …")
    df = pd.read_csv(data_path)

    X  = _encode(df)
    le = LabelEncoder()
    y  = le.fit_transform(df["label"])

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y)

    sc = StandardScaler()
    X_tr_s = sc.fit_transform(X_tr)
    X_te_s  = sc.transform(X_te)

    print("🤖 Training Random Forest (100 trees) …")
    clf = RandomForestClassifier(n_estimators=100, max_depth=15,
                                 min_samples_split=5, random_state=42, n_jobs=-1)
    clf.fit(X_tr_s, y_tr)

    y_pred   = clf.predict(X_te_s)
    accuracy = accuracy_score(y_te, y_pred)
    f1       = f1_score(y_te, y_pred, average="weighted")

    print(f"\n✅  Accuracy : {accuracy:.4f}   F1 : {f1:.4f}")
    print(classification_report(y_te, y_pred, target_names=le.classes_))

    os.makedirs(MODEL_DIR, exist_ok=True)
    for obj, path in [(clf, MODEL_PATH),(sc, SCALER_PATH),(le, ENCODER_PATH)]:
        with open(path,"wb") as fh: pickle.dump(obj, fh)
    print(f"💾 Saved → {MODEL_DIR}/")

    return dict(
        accuracy      = accuracy,
        f1_score      = f1,
        classes       = list(le.classes_),
        feature_importance = dict(zip(X.columns, clf.feature_importances_.round(4))),
        confusion_matrix   = confusion_matrix(y_te, y_pred).tolist(),
        class_names        = list(le.classes_),
    )


# ── load ─────────────────────────────────────────────────────────────────────

def _load():
    with open(MODEL_PATH,"rb")  as f: clf = pickle.load(f)
    with open(SCALER_PATH,"rb") as f: sc  = pickle.load(f)
    with open(ENCODER_PATH,"rb")as f: le  = pickle.load(f)
    return clf, sc, le

def model_ready() -> bool:
    return all(os.path.exists(p) for p in [MODEL_PATH,SCALER_PATH,ENCODER_PATH])


# ── predict ──────────────────────────────────────────────────────────────────

def predict_single(record: dict) -> dict:
    clf, sc, le = _load()
    df  = pd.DataFrame([record])
    X   = _encode(df)
    Xs  = sc.transform(X)
    idx = clf.predict(Xs)[0]
    proba = clf.predict_proba(Xs)[0]
    label = le.inverse_transform([idx])[0]
    return dict(
        prediction        = label,
        confidence        = round(float(proba.max())*100, 2),
        all_probabilities = {c: round(float(p)*100,2) for c,p in zip(le.classes_, proba)},
        is_threat         = label != "Benign",
    )


if __name__ == "__main__":
    train_model("data/network_traffic.csv")
