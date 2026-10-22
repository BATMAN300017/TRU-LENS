import sys
import os
# Automatically add the root project folder to Python's path so it can find 'backend'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from backend.redact import redact_text

import pandas as pd
import os
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from backend.redact import redact_text

def train_with_full_csv_dataset(csv_path: str):
    print(f"=== Tru-lens 95k CSV Dataset Training Pipeline ===")
    if not os.path.exists(csv_path):
        print(f"Error: Could not find CSV file at {csv_path}")
        print("Tip: Make sure your CSV file is placed inside the 't-hacks-90-parallax/' root folder.")
        return

    print(f"Loading CSV file from {csv_path} (this will take just a couple of seconds)...")
    
    # Read CSV safely with low_memory=False to handle mixed types across 95k rows
    df = pd.read_csv(csv_path, low_memory=False)
    
    # Auto-detect text column name
    possible_cols = ['text', 'message', 'sms', 'content', 'body', 'Message', 'Text']
    text_col = next((col for col in possible_cols if col in df.columns), df.columns[0])
    print(f"Found text column: '{text_col}'. Total rows in CSV: {len(df)}")

    df = df.dropna(subset=[text_col])
    
    print("Scrubbing PII from messages in batches (protecting user privacy)...")
    cleaned_scam_texts = []
    batch_size = 5000
    total_rows = len(df)
    
    for i in range(0, total_rows, batch_size):
        batch = df[text_col].iloc[i:i+batch_size]
        batch_cleaned = [redact_text(str(text))["masked_text"] for text in batch]
        cleaned_scam_texts.extend(batch_cleaned)
        print(f"Processed batch {i//batch_size + 1} / {(total_rows // batch_size) + 1}...")

    # Build Scam DataFrame (Label 1)
    scam_df = pd.DataFrame({
        "text": cleaned_scam_texts,
        "label": 1
    })

    # Legitimate (Ham) samples to balance the model and prevent false alarms
    legit_samples = [
        "Hey, are we still meeting for lunch at 2 PM today?",
        "Your Amazon order #402-123 shipped successfully via BlueDart.",
        "Dear SBI Customer, your A/C ending 4321 credited by Rs 5,000.00 on 22-Oct-26.",
        "Your OTP for Swiggy login is 883211. Valid for 10 minutes.",
        "Reminder: Doctor appointment scheduled for tomorrow at 10 AM.",
        "Your electricity bill for consumer ID 98765 is generated. View on official portal.",
        "Thanks for shopping with Flipkart! Your invoice is attached.",
        "Your Zomato order has been delivered. Enjoy your meal!",
        "OTP for UPI transaction of Rs 250 is 4412. Do not share with anyone.",
        "Hi mom, I will reach home by 7 PM today, don't wait for dinner."
    ]
    ham_df = pd.DataFrame({
        "text": legit_samples * (len(scam_df) // len(legit_samples)),
        "label": 0
    })

    # Combine and shuffle
    full_df = pd.concat([scam_df, ham_df], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"Training dataset ready! Total training samples: {len(full_df)} ({len(scam_df)} scams, {len(ham_df)} legit)")

    # Train Hybrid TF-IDF + Logistic Regression Model
    print("Training TF-IDF Vectorizer and Logistic Regression classifier...")
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=40000,
        sublinear_tf=True,
        strip_accents="unicode"
    )
    
    X = vectorizer.fit_transform(full_df["text"])
    y = full_df["label"]

    clf = LogisticRegression(max_iter=1500, class_weight="balanced", C=2.0)
    clf.fit(X, y)

    # Save trained model weights to models/ folder
    os.makedirs("models", exist_ok=True)
    model_path = "models/spam_model.pkl"
    joblib.dump((vectorizer, clf), model_path)
    print(f"Success! Full 95k CSV-trained model saved securely to {model_path}")

if __name__ == "__main__":
    # Change 'scams.csv' to the exact name of your CSV file if it's different
    csv_file = "scams.csv"
    train_with_full_csv_dataset(csv_file)