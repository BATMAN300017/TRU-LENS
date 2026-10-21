import csv
import os
import requests

def run_evaluation():
    csv_path = os.path.join(os.path.dirname(__file__), "test_set.csv")
    if not os.path.exists(csv_path):
        print("Test set CSV not found.")
        return

    correct = 0
    total = 0

    with open(csv_path, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            total += 1
            text = row['text']
            expected_label = row['label'] # 'scam' or 'legit'
            
            # Call local FastAPI endpoint or test functions directly
            # For simplicity in testing: check if score > 30 is flagged as scam
            from backend.text_rules import analyze_message_text
            res = analyze_message_text(text)
            predicted_is_scam = res['rule_score'] >= 30
            
            actual_is_scam = (expected_label == 'scam')
            if predicted_is_scam == actual_is_scam:
                correct += 1

    accuracy = (correct / total) * 100 if total > 0 else 0
    print(f"=== Tru-lens Evaluation Results ===")
    print(f"Total Test Samples: {total}")
    print(f"Accuracy: {accuracy:.2f}%")

if __name__ == "__main__":
    run_evaluation()
