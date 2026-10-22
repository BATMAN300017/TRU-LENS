import pandas as pd
import os
from backend.redact import redact_text

def process_excel_scams(excel_path: str, output_csv: str, sample_size: int = 1000):
    print(f"Loading Excel file from {excel_path}...")
    if not os.path.exists(excel_path):
        print(f"Error: Could not find file at {excel_path}")
        return

    # Read Excel file (works for .xlsx and .xls)
    df = pd.read_excel(excel_path)
    
    # Auto-detect text column (change 'text' or 'message' if your column has a different name)
    possible_cols = ['text', 'message', 'sms', 'content', 'body']
    text_col = next((col for col in possible_cols if col in df.columns), df.columns[0])
    print(f"Using column '{text_col}' for message content.")

    # Drop empty rows and sample 1,000 rows
    df = df.dropna(subset=[text_col])
    if len(df) > sample_size:
        df_sample = df.sample(n=sample_size, random_state=42)
    else:
        df_sample = df
        print(f"Warning: Excel only has {len(df)} rows, using all of them.")

    print("Scrubbing PII using Tru-lens redaction layer...")
    cleaned_texts = []
    for text in df_sample[text_col]:
        # Redact PII first so model learns scam patterns, not raw phone numbers
        redacted = redact_text(str(text))["masked_text"]
        cleaned_texts.append(redacted)

    # Create new training dataframe (Label 1 = Scam)
    train_df = pd.DataFrame({
        "text": cleaned_texts,
        "label": 1 
    })

    os.path.dirname(output_csv)
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    train_df.to_csv(output_csv, index=False, encoding='utf-8')
    print(f"Successfully processed and saved {len(train_df)} scam messages to {output_csv}!")

if __name__ == "__main__":
    # Change 'scams_dataset.xlsx' to the actual name/path of your Excel file
    excel_file = "scams_dataset.xlsx" 
    output_file = "eval/training_sample.csv"
    process_excel_scams(excel_file, output_file, sample_size=1000)