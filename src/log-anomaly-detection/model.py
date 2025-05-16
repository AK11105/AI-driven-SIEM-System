import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from collections import Counter
from tqdm import tqdm

# ---------------------
# Step 1: Load CSV Logs
# ---------------------
df = pd.read_csv("data/logs/processed/Linux.log_structured.csv")
texts = df['Content'].astype(str).tolist()
labels = df['Level'].map(lambda x: 0 if x == 'log' else 1).tolist()

# ---------------------
# Step 2: Build Vocabulary
# ---------------------
def tokenize(text):
    return text.lower().split()

tokenized_texts = [tokenize(text) for text in texts]
word_counts = Counter(token for sentence in tokenized_texts for token in sentence)
vocab = {word: idx + 2 for idx, (word, _) in enumerate(word_counts.items())}
vocab['<PAD>'] = 0
vocab['<UNK>'] = 1

def encode(text, vocab):
    return [vocab.get(word, vocab['<UNK>']) for word in tokenize(text)]

encoded_sequences = [encode(text, vocab) for text in texts]

# ---------------------
# Step 3: Create Sliding Windows
# ---------------------
def create_windows(sequences, labels, window_size=6, max_len=20):
    X, y = [], []
    for i in range(len(sequences) - window_size + 1):
        window = sequences[i:i + window_size]
        padded = [seq[:max_len] + [0] * (max_len - len(seq[:max_len])) for seq in window]
        X.append(padded)
        y.append(labels[i + window_size - 1])
    return np.array(X), np.array(y)

window_size = 6
max_len = 20
X, y = create_windows(encoded_sequences, labels, window_size, max_len)

# ---------------------
# Step 4: Dataset and DataLoader
# ---------------------
class LogDataset(Dataset):
    def __init__(self, X, y):
        self.X = torch.tensor(X, dtype=torch.long)
        self.y = torch.tensor(y, dtype=torch.float32)

    def __len__(self):
        return len(self.X)

    def __getitem__(self, idx):
        return self.X[idx], self.y[idx]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

train_dataset = LogDataset(X_train, y_train)
test_dataset = LogDataset(X_test, y_test)

train_loader = DataLoader(train_dataset, batch_size=32, shuffle=True)
test_loader = DataLoader(test_dataset, batch_size=32)

# ---------------------
# Step 5: Model Definition (CNN + BiLSTM + Dropout + BatchNorm)
# ---------------------
class CNN_BiLSTM(nn.Module):
    def __init__(self, vocab_size, embed_dim=128, cnn_out=64, lstm_hidden=64):
        super(CNN_BiLSTM, self).__init__()
        self.embed = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.cnn = nn.Conv1d(embed_dim, cnn_out, kernel_size=3, padding=1)
        self.bn_cnn = nn.BatchNorm1d(cnn_out)
        self.pool = nn.AdaptiveMaxPool1d(1)
        self.lstm = nn.LSTM(input_size=cnn_out, hidden_size=lstm_hidden, batch_first=True, bidirectional=True)
        self.fc1 = nn.Linear(lstm_hidden * 2, 64)
        self.bn_fc1 = nn.BatchNorm1d(64)
        self.dropout = nn.Dropout(0.5)
        self.fc2 = nn.Linear(64, 1)
        # NO sigmoid here because we use BCEWithLogitsLoss

    def forward(self, x):  # x: (B, T, L)
        B, T, L = x.shape
        x = self.embed(x.view(-1, L))        # (B*T, L, D)
        x = x.permute(0, 2, 1)               # (B*T, D, L)
        x = self.cnn(x)                      # (B*T, C, L)
        x = self.bn_cnn(x)
        x = torch.relu(x)
        x = self.pool(x).squeeze(-1)         # (B*T, C)
        x = x.view(B, T, -1)                 # (B, T, C)
        _, (h, _) = self.lstm(x)             # h: (num_layers*2, B, H)
        h = torch.cat((h[-2], h[-1]), dim=1) # (B, 2*H)
        h = torch.relu(self.fc1(h))
        h = self.bn_fc1(h)
        h = self.dropout(h)
        out = self.fc2(h).squeeze(1)         # (B,)
        return out

# ---------------------
# Step 6: Setup device, model, loss, optimizer, scheduler
# ---------------------
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

# Compute pos_weight for imbalance
class_weights = compute_class_weight('balanced', classes=np.unique(y_train), y=y_train)
pos_weight = torch.tensor([class_weights[1]/class_weights[0]], dtype=torch.float32).to(device)

model = CNN_BiLSTM(vocab_size=len(vocab)).to(device)
criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
optimizer = optim.AdamW(model.parameters(), lr=1e-4, weight_decay=1e-5)
scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', patience=2, factor=0.5)

# ---------------------
# Step 7: Training with Early Stopping
# ---------------------
best_val_loss = float('inf')
patience, trials = 5, 0
num_epochs = 30

for epoch in range(1, num_epochs + 1):
    model.train()
    total_loss = 0
    for X_batch, y_batch in tqdm(train_loader, desc=f"Epoch {epoch}"):
        X_batch, y_batch = X_batch.to(device), y_batch.to(device)
        optimizer.zero_grad()
        preds = model(X_batch)
        loss = criterion(preds, y_batch)
        loss.backward()
        optimizer.step()
        total_loss += loss.item()

    avg_train_loss = total_loss / len(train_loader)
    print(f"Epoch {epoch}, Train Loss: {avg_train_loss:.4f}")

    # Validation
    model.eval()
    val_loss = 0
    with torch.no_grad():
        for X_batch, y_batch in test_loader:
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)
            preds = model(X_batch)
            loss = criterion(preds, y_batch)
            val_loss += loss.item()
    val_loss /= len(test_loader)
    print(f"Epoch {epoch}, Validation Loss: {val_loss:.4f}")

    scheduler.step(val_loss)

    # Early stopping check
    if val_loss < best_val_loss:
        best_val_loss = val_loss
        trials = 0
        torch.save(model.state_dict(), "best_cnn_bilstm_model.pth")
        print("Model saved.")
    else:
        trials += 1
        if trials >= patience:
            print("Early stopping triggered.")
            break

# ---------------------
# Step 8: Evaluation (Load best model)
# ---------------------
model.load_state_dict(torch.load("best_cnn_bilstm_model.pth"))
model.eval()
correct = 0
total = 0
with torch.no_grad():
    for X_batch, y_batch in test_loader:
        X_batch, y_batch = X_batch.to(device), y_batch.to(device)
        preds = torch.sigmoid(model(X_batch))
        preds = (preds > 0.5).float()
        correct += (preds == y_batch).sum().item()
        total += y_batch.size(0)

print(f"\nTest Accuracy: {correct / total:.4f}")
