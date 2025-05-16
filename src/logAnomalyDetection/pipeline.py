import torch
import torch.nn as nn
import torch.nn.functional as F
import json
import re
import csv
import os
from datetime import datetime

# Device setup
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# Load vocab
with open("CNN-LSTM/vocab.json", "r") as f:
    vocab = json.load(f)

MAX_LEN = 50

def tokenize(text):
    text = text.lower()
    text = re.sub(r"[()\',]", "", text)
    return text.split()

def encode_sequence(tokens, vocab, max_len=MAX_LEN):
    encoded = [vocab.get(token, vocab.get('<UNK>', 1)) for token in tokens]
    if len(encoded) < max_len:
        encoded += [vocab.get('<PAD>', 0)] * (max_len - len(encoded))
    else:
        encoded = encoded[:max_len]
    return torch.tensor(encoded).unsqueeze(0)

class CNNLSTM(nn.Module):
    def __init__(self, vocab_size, embed_dim, num_classes):
        super(CNNLSTM, self).__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.conv1 = nn.Conv1d(embed_dim, 128, kernel_size=3, padding=1)
        self.lstm = nn.LSTM(128, 64, batch_first=True)
        self.fc = nn.Linear(64, num_classes)

    def forward(self, x):
        x = self.embedding(x)
        x = x.permute(0, 2, 1)
        x = F.relu(self.conv1(x))
        x = x.permute(0, 2, 1)
        _, (hn, _) = self.lstm(x)
        return self.fc(hn.squeeze(0))

# Model setup
num_classes = 6
embed_dim = 100
model = CNNLSTM(vocab_size=len(vocab), embed_dim=embed_dim, num_classes=num_classes)
model.load_state_dict(torch.load("CNN-LSTM/best_cnn_lstm_multiclass.pth", map_location=device))
model.to(device)
model.eval()

anomaly_classes = [
    'Normal',
    'Memory Error',
    'Authentication Error',
    'File System Error',
    'Network Error',
    'Permission Error'
]

import requests

def predict_and_send(event_template: str, raw_content: str, timestamp: str = None):
    tokens = tokenize(event_template)
    input_tensor = encode_sequence(tokens, vocab).to(device)

    with torch.no_grad():
        output = model(input_tensor)
        probs = torch.softmax(output, dim=1)
        pred_class = torch.argmax(probs, dim=1).item()

    label = anomaly_classes[pred_class]

    result = {
        "log": raw_content,
        "classification": label,
        "timestamp": timestamp if timestamp else datetime.utcnow().isoformat() + "Z"
    }

    try:
        # Send POST request to your Express backend
        response = requests.post("http://localhost:5000/api/logs", json=result)
        if response.status_code == 200:
            print(f"✅ Log sent successfully: {result}")
        else:
            print(f"❌ Failed to send log: {response.status_code}, {response.text}")
    except Exception as e:
        print(f"❌ Exception during sending log: {e}")

    return result


def process_logs_from_csv(csv_path, event_template_col='EventTemplate', content_col='Content', timestamp_col='Time'):
    if not os.path.isfile(csv_path):
        print(f"CSV file not found: {csv_path}")
        return

    print(f"Processing logs from CSV: {csv_path}")

    with open(csv_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        print("CSV headers:", reader.fieldnames)  # Debug headers

        count = 0
        for row in reader:
            event_template = row.get(event_template_col)
            raw_content = row.get(content_col)
            timestamp = row.get(timestamp_col)

            if not event_template or not raw_content:
                print(f"Skipping row {count+1} due to missing data")
                continue

            predict_and_send(event_template, raw_content, timestamp)
            count += 1
        print(f"Processed {count} log entries.")

if __name__ == "__main__":
    test_csv = "Linux_test.log_structured.csv"
    process_logs_from_csv(test_csv)
