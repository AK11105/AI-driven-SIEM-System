import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from collections import Counter
from tqdm import tqdm
import json

# 1. Data Loading and Preprocessing
df = pd.read_csv("data/logs/processed/Linux.log_structured.csv")
texts = df["EventTemplate"].str.replace("<*>", "[WILDCARD]").tolist()

# Define your multi-class labels
anomaly_classes = [
    'Normal',
    'Memory Error',
    'Authentication Error',
    'File System Error',
    'Network Error',
    'Permission Error'
]

def classify_multiclass(event_template):
    et = event_template.lower()
    if any(k in et for k in ['out of memory', 'page allocation failure', 'dma timeout']):
        return 1  # Memory Error
    elif any(k in et for k in ['authentication failure', 'invalid username', 'kerberos']):
        return 2  # Auth Error
    elif any(k in et for k in ['no such file', 'failed command', 'status timeout', 'drive not ready']):
        return 3  # File System Error
    elif any(k in et for k in ['connection timed out', 'connection from', 'peer died']):
        return 4  # Network Error
    elif any(k in et for k in ['permission denied', 'operation not supported', 'selinux']):
        return 5  # Permission Error
    else:
        return 0  # Normal

labels = df["EventTemplate"].apply(classify_multiclass).tolist()
encoded_labels = torch.tensor(labels, dtype=torch.long)

# Tokenization
def tokenize(text):
    return text.lower().replace("(", "").replace(")", "").replace("'", "").replace(",", "").split()

tokenized = [tokenize(text) for text in texts]
counter = Counter(token for seq in tokenized for token in seq)
vocab = {'<PAD>': 0, '<UNK>': 1}
for word, _ in counter.most_common(10000):
    vocab[word] = len(vocab)

with open("vocabulary.json", "w") as f:
    json.dump(vocab, f)
print("Vocabulary saved to vocab.json")

MAX_LEN = 50
def encode_sequence(tokens):
    encoded = [vocab.get(token, vocab['<UNK>']) for token in tokens]
    return encoded[:MAX_LEN] + [0]*(MAX_LEN - len(encoded)) if len(encoded) < MAX_LEN else encoded[:MAX_LEN]

encoded_texts = [encode_sequence(seq) for seq in tokenized]
padded_texts = torch.tensor(encoded_texts)

# 2. Dataset
class LogDataset(Dataset):
    def __init__(self, inputs, labels):
        self.inputs = inputs
        self.labels = labels
    def __len__(self): return len(self.inputs)
    def __getitem__(self, idx): return self.inputs[idx], self.labels[idx]

X_train, X_test, y_train, y_test = train_test_split(
    padded_texts, encoded_labels, test_size=0.2, stratify=labels, random_state=42
)

train_dataset = LogDataset(X_train, y_train)
test_dataset = LogDataset(X_test, y_test)

def collate_fn(batch):
    inputs, labels = zip(*batch)
    return torch.stack(inputs), torch.tensor(labels)

train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True, collate_fn=collate_fn)
test_loader = DataLoader(test_dataset, batch_size=64, collate_fn=collate_fn)

# 3. CNN-LSTM Model for Multi-Class
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
        return self.fc(hn.squeeze(0))  # shape: (batch_size, num_classes)

# 4. Training Setup
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = CNNLSTM(vocab_size=len(vocab), embed_dim=100, num_classes=len(anomaly_classes)).to(device)
optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
criterion = nn.CrossEntropyLoss()

# 5. Training Loop
best_val_loss = float('inf')
best_model_path = "best_cnn_lstm_multiclass-try.pth"
print("Training...")
for epoch in range(10):
    model.train()
    total_loss = 0
    pbar = tqdm(train_loader, desc=f"Epoch {epoch+1}")
    for batch_x, batch_y in pbar:
        batch_x, batch_y = batch_x.to(device), batch_y.to(device)
        optimizer.zero_grad()
        outputs = model(batch_x)
        loss = criterion(outputs, batch_y)
        loss.backward()
        optimizer.step()
        total_loss += loss.item()
        pbar.set_postfix(loss=total_loss / (pbar.n+1))
    
    avg_train_loss = total_loss / len(train_loader)

    # Validation
    model.eval()
    val_loss = 0
    with torch.no_grad():
        for batch_x, batch_y in test_loader:
            batch_x, batch_y = batch_x.to(device), batch_y.to(device)
            outputs = model(batch_x)
            loss = criterion(outputs, batch_y)
            val_loss += loss.item()
    avg_val_loss = val_loss / len(test_loader)
    
    print(f"Epoch {epoch+1} - Train Loss: {avg_train_loss:.4f} | Val Loss: {avg_val_loss:.4f}")
    if avg_val_loss < best_val_loss:
        best_val_loss = avg_val_loss
        torch.save(model.state_dict(), best_model_path)
        print(f"Best model saved at epoch {epoch+1} with val loss {best_val_loss:.4f}")

# 6. Evaluation
model.load_state_dict(torch.load(best_model_path))
model.eval()

all_preds = []
all_targets = []

with torch.no_grad():
    for batch_x, batch_y in test_loader:
        batch_x = batch_x.to(device)
        outputs = model(batch_x)
        preds = torch.argmax(outputs, dim=1)
        all_preds.extend(preds.cpu().numpy())
        all_targets.extend(batch_y.numpy())

print("\nClassification Report:")
print(classification_report(all_targets, all_preds, target_names=anomaly_classes))
