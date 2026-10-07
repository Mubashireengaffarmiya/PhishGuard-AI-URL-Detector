"""
Generates clean, fully executable Jupyter Notebooks (.ipynb) for PhishGuard AI:
1. notebooks/01_eda.ipynb
2. notebooks/02_feature_engineering.ipynb
3. notebooks/03_model_training.ipynb
4. notebooks/04_model_evaluation.ipynb
"""

import json
from pathlib import Path

NOTEBOOKS_DIR = Path(__file__).resolve().parent.parent / "notebooks"
NOTEBOOKS_DIR.mkdir(parents=True, exist_ok=True)


def make_notebook(cells):
    return {
        "cells": cells,
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3"
            },
            "language_info": {
                "codemirror_mode": {"name": "ipython", "version": 3},
                "file_extension": ".py",
                "mimetype": "text/x-python",
                "name": "python",
                "nbconvert_exporter": "python",
                "pygments_lexer": "ipython3",
                "version": "3.10.0"
            }
        },
        "nbformat": 4,
        "nbformat_minor": 4
    }


def markdown_cell(source):
    lines = [f"{line}\n" for line in source.strip().split("\n")]
    if lines:
        lines[-1] = lines[-1].rstrip("\n")
    return {"cell_type": "markdown", "metadata": {}, "source": lines}


def code_cell(source):
    lines = [f"{line}\n" for line in source.strip().split("\n")]
    if lines:
        lines[-1] = lines[-1].rstrip("\n")
    return {"cell_type": "code", "execution_count": None, "metadata": {}, "outputs": [], "source": lines}


# Notebook 1: EDA
eda_cells = [
    markdown_cell("""# PhishGuard AI - 01 Exploratory Data Analysis (EDA)
**Explainable AI-Based Phishing URL Detection and Risk Analysis System**

This notebook performs exploratory data analysis on the raw phishing and legitimate URL dataset.
We inspect shapes, missing values, duplicates, class distributions, and feature correlations."""),
    code_cell("""import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path("..").resolve()
sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

from src.config import DEFAULT_RAW_DATASET_CSV
from src.data_loader import DatasetLoader
from src.preprocessing import DataPreprocessor

# Set visual styling
sns.set_theme(style="whitegrid")
plt.rcParams["figure.figsize"] = (10, 6)"""),
    markdown_cell("## 1. Load Dataset and Inspect Schema"),
    code_cell("""loader = DatasetLoader(filepath=DEFAULT_RAW_DATASET_CSV)
df = loader.load()
print(f"Dataset Shape: {df.shape}")
print(f"Detected URL Column: {loader.url_col}")
print(f"Detected Label Column: {loader.label_col}")
df.head(10)"""),
    markdown_cell("## 2. Summary Statistics, Missing Data, and Duplicates"),
    code_cell("""print("Dataset Info:")
df.info()
print("\\nMissing Values:\\n", df.isna().sum())
duplicates = df.duplicated(subset=[loader.url_col]).sum()
print(f"\\nDuplicate URLs: {duplicates} ({duplicates / len(df) * 100:.2f}%)")"""),
    markdown_cell("## 3. Class Balance and Label Normalization"),
    code_cell("""preprocessor = DataPreprocessor()
df_clean = preprocessor.clean_dataset(df, url_col=loader.url_col, label_col=loader.label_col)
class_counts = df_clean['label_normalized'].value_counts()
print("Cleaned Class Distribution:\\n", class_counts)

fig, ax = plt.subplots(figsize=(7, 4))
sns.barplot(x=["Legitimate (0)", "Phishing (1)"], y=class_counts.values, palette=["#10B981", "#EF4444"], ax=ax)
ax.set_title("Distribution of URL Classes in Cleaned Dataset", fontsize=14, fontweight="bold")
ax.set_ylabel("Count")
plt.show()"""),
    markdown_cell("## 4. Lexical Feature Distributions: URL Length & Dot Counts"),
    code_cell("""df_clean['url_length'] = df_clean[loader.url_col].apply(len)
df_clean['qty_dot'] = df_clean[loader.url_col].apply(lambda u: u.count('.'))
df_clean['is_https'] = df_clean[loader.url_col].apply(lambda u: 1 if u.startswith('https') else 0)

fig, axes = plt.subplots(1, 3, figsize=(18, 5))

# URL Length
sns.boxplot(x='label_normalized', y='url_length', data=df_clean, palette=["#10B981", "#EF4444"], ax=axes[0])
axes[0].set_title("URL Length by Class", fontweight="bold")
axes[0].set_xticklabels(["Legitimate", "Phishing"])
axes[0].set_yscale('log')

# Dot Count
sns.boxplot(x='label_normalized', y='qty_dot', data=df_clean, palette=["#10B981", "#EF4444"], ax=axes[1])
axes[1].set_title("Number of Dots by Class", fontweight="bold")
axes[1].set_xticklabels(["Legitimate", "Phishing"])

# HTTPS Usage
sns.barplot(x='label_normalized', y='is_https', data=df_clean, palette=["#10B981", "#EF4444"], ax=axes[2])
axes[2].set_title("Proportion of HTTPS URLs", fontweight="bold")
axes[2].set_xticklabels(["Legitimate", "Phishing"])
axes[2].set_ylabel("HTTPS Rate (0.0 - 1.0)")

plt.tight_layout()
plt.show()""")
]

# Notebook 2: Feature Engineering
fe_cells = [
    markdown_cell("""# PhishGuard AI - 02 Feature Engineering
**Deterministic Extraction of 42 URL Features**

Extracts structural, lexical, statistical, security, keyword, and domain characteristics from URLs."""),
    code_cell("""import sys
from pathlib import Path
PROJECT_ROOT = Path("..").resolve()
sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
from src.config import DEFAULT_RAW_DATASET_CSV, DEFAULT_PROCESSED_DATASET_CSV
from src.data_loader import DatasetLoader
from src.preprocessing import DataPreprocessor
from src.feature_extraction import (
    FEATURE_NAMES,
    extract_features_from_url,
    extract_features_dataframe,
    get_feature_metadata
)

print(f"Total features configured: {len(FEATURE_NAMES)}")"""),
    markdown_cell("## 1. Single URL Feature Extraction Demonstration"),
    code_cell("""sample_phish = "http://paypal.com.account-verification-service.tk/login.php?session=98214"
sample_legit = "https://github.com/scikit-learn/scikit-learn"

feat_phish = extract_features_from_url(sample_phish)
feat_legit = extract_features_from_url(sample_legit)

comparison_df = pd.DataFrame([feat_legit, feat_phish], index=["Legitimate (GitHub)", "Phishing (PayPal Spoof)"]).T
comparison_df.head(25)"""),
    markdown_cell("## 2. Batch Extraction Across Entire Dataset"),
    code_cell("""loader = DatasetLoader(filepath=DEFAULT_RAW_DATASET_CSV)
df = loader.load()
preprocessor = DataPreprocessor()
df_clean = preprocessor.clean_dataset(df, url_col=loader.url_col, label_col=loader.label_col)

# Extract features
X_features = extract_features_dataframe(df_clean[loader.url_col])
X_features['target_label'] = df_clean['label_normalized'].values

# Save to processed directory
X_features.to_csv(DEFAULT_PROCESSED_DATASET_CSV, index=False)
print(f"Saved processed features to: {DEFAULT_PROCESSED_DATASET_CSV}")
print("Feature Dataframe Shape:", X_features.shape)
X_features.head()""")
]

# Notebook 3: Model Training
train_cells = [
    markdown_cell("""# PhishGuard AI - 03 Model Training Pipeline
**Training Logistic Regression, Decision Tree, and Random Forest Models**

Includes reproducible random states, feature scaling for linear models, and artifact serialization."""),
    code_cell("""import sys
from pathlib import Path
PROJECT_ROOT = Path("..").resolve()
sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

from src.config import (
    DEFAULT_PROCESSED_DATASET_CSV,
    LOGISTIC_REGRESSION_PATH,
    DECISION_TREE_PATH,
    RANDOM_FOREST_PATH,
    SCALER_PATH,
    FEATURE_METADATA_PATH
)
from src.feature_extraction import FEATURE_NAMES, get_feature_metadata"""),
    markdown_cell("## 1. Load Processed Dataset & Train/Test Split"),
    code_cell("""df = pd.read_csv(DEFAULT_PROCESSED_DATASET_CSV)
X = df[FEATURE_NAMES].values
y = df['target_label'].values

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)
print(f"Train samples: {len(X_train)}, Test samples: {len(X_test)}")"""),
    markdown_cell("## 2. Train Models"),
    code_cell("""# 1. Feature Scaler for Logistic Regression
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Model 1: Logistic Regression
lr = LogisticRegression(C=1.0, solver='lbfgs', max_iter=1000, random_state=42)
lr.fit(X_train_scaled, y_train)

# Model 2: Decision Tree
dt = DecisionTreeClassifier(max_depth=10, min_samples_split=5, random_state=42)
dt.fit(X_train, y_train)

# Model 3: Random Forest
rf = RandomForestClassifier(n_estimators=100, max_depth=12, min_samples_split=4, random_state=42, n_jobs=-1)
rf.fit(X_train, y_train)

print("All 3 models trained successfully.")"""),
    markdown_cell("## 3. Save Model Artifacts"),
    code_cell("""joblib.dump(lr, LOGISTIC_REGRESSION_PATH)
joblib.dump(dt, DECISION_TREE_PATH)
joblib.dump(rf, RANDOM_FOREST_PATH)
joblib.dump(scaler, SCALER_PATH)
joblib.dump(get_feature_metadata(), FEATURE_METADATA_PATH)
print("Artifacts successfully saved to disk.")""")
]

# Notebook 4: Model Evaluation
eval_cells = [
    markdown_cell("""# PhishGuard AI - 04 Model Evaluation & Interpretability
**Comparative Analysis: Accuracy, Precision, Recall, F1, ROC-AUC, and Feature Importances**"""),
    code_cell("""import sys
from pathlib import Path
PROJECT_ROOT = Path("..").resolve()
sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, roc_curve
)

from src.config import (
    DEFAULT_PROCESSED_DATASET_CSV,
    LOGISTIC_REGRESSION_PATH,
    DECISION_TREE_PATH,
    RANDOM_FOREST_PATH,
    SCALER_PATH
)
from src.feature_extraction import FEATURE_NAMES

# Load artifacts
lr = joblib.load(LOGISTIC_REGRESSION_PATH)
dt = joblib.load(DECISION_TREE_PATH)
rf = joblib.load(RANDOM_FOREST_PATH)
scaler = joblib.load(SCALER_PATH)

df = pd.read_csv(DEFAULT_PROCESSED_DATASET_CSV)
from sklearn.model_selection import train_test_split
_, X_test, _, y_test = train_test_split(
    df[FEATURE_NAMES].values, df['target_label'].values, test_size=0.20, random_state=42, stratify=df['target_label'].values
)
X_test_scaled = scaler.transform(X_test)"""),
    markdown_cell("## 1. Metrics Comparison Table"),
    code_cell("""models = {
    "Logistic Regression": (lr, X_test_scaled),
    "Decision Tree": (dt, X_test),
    "Random Forest": (rf, X_test)
}

rows = []
for name, (m, data) in models.items():
    preds = m.predict(data)
    proba = m.predict_proba(data)[:, 1] if hasattr(m, "predict_proba") else preds
    rows.append({
        "Model": name,
        "Accuracy": round(accuracy_score(y_test, preds), 4),
        "Precision": round(precision_score(y_test, preds), 4),
        "Recall": round(recall_score(y_test, preds), 4),
        "F1-Score": round(f1_score(y_test, preds), 4),
        "ROC-AUC": round(roc_auc_score(y_test, proba), 4)
    })

results_df = pd.DataFrame(rows)
display(results_df)"""),
    markdown_cell("## 2. Confusion Matrices"),
    code_cell("""fig, axes = plt.subplots(1, 3, figsize=(18, 5))
for idx, (name, (m, data)) in enumerate(models.items()):
    preds = m.predict(data)
    cm = confusion_matrix(y_test, preds)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[idx],
                xticklabels=["Legit (0)", "Phish (1)"], yticklabels=["Legit (0)", "Phish (1)"])
    axes[idx].set_title(f"{name} Confusion Matrix", fontweight="bold")
    axes[idx].set_xlabel("Predicted")
    axes[idx].set_ylabel("Actual")
plt.tight_layout()
plt.show()"""),
    markdown_cell("## 3. Random Forest Feature Importance"),
    code_cell("""rf_importances = pd.Series(rf.feature_importances_, index=FEATURE_NAMES).sort_values(ascending=False)
plt.figure(figsize=(10, 8))
sns.barplot(x=rf_importances.head(15).values, y=rf_importances.head(15).index, palette="viridis")
plt.title("Top 15 Most Important Features (Random Forest)", fontsize=14, fontweight="bold")
plt.xlabel("Gini Feature Importance")
plt.show()""")
]

# Write all 4 notebooks
for path, cells in [
    (NOTEBOOKS_DIR / "01_eda.ipynb", eda_cells),
    (NOTEBOOKS_DIR / "02_feature_engineering.ipynb", fe_cells),
    (NOTEBOOKS_DIR / "03_model_training.ipynb", train_cells),
    (NOTEBOOKS_DIR / "04_model_evaluation.ipynb", eval_cells)
]:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(make_notebook(cells), f, indent=2)
    print(f"Generated notebook: {path.name}")
