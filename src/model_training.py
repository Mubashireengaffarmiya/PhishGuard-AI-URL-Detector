"""
Model training pipeline for PhishGuard AI.
Orchestrates data loading, feature extraction, train/test splitting,
model training (Logistic Regression, Decision Tree, Random Forest),
evaluation, and artifact persistence.
"""

import sys
from pathlib import Path
from typing import Dict, Any

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import joblib
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from src.config import (
    DEFAULT_RAW_DATASET_CSV,
    DEFAULT_PROCESSED_DATASET_CSV,
    LOGISTIC_REGRESSION_PATH,
    DECISION_TREE_PATH,
    RANDOM_FOREST_PATH,
    SCALER_PATH,
    FEATURE_METADATA_PATH,
    EVALUATION_METRICS_PATH,
    MODELS_DIR,
)
from src.data_loader import DatasetLoader
from src.preprocessing import DataPreprocessor
from src.feature_extraction import (
    FEATURE_NAMES,
    extract_features_dataframe,
    get_feature_metadata,
)
from src.model_evaluation import compare_models, extract_feature_importances
from src.utils import setup_logger

logger = setup_logger("ModelTraining")


def run_training_pipeline(
    raw_csv_path: Path = DEFAULT_RAW_DATASET_CSV,
    random_state: int = 42,
    test_size: float = 0.20
) -> Dict[str, Any]:
    """
    Executes the end-to-end training and evaluation pipeline.
    """
    logger.info("==================================================")
    logger.info("   Starting PhishGuard AI ML Training Pipeline   ")
    logger.info("==================================================")

    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Load Raw Dataset
    loader = DatasetLoader(filepath=raw_csv_path)
    df_raw = loader.load()
    url_col = loader.url_col
    label_col = loader.label_col
    assert url_col is not None and label_col is not None

    # 2. Preprocess & Clean Dataset
    preprocessor = DataPreprocessor(random_state=random_state, test_size=test_size)
    df_clean = preprocessor.clean_dataset(df_raw, url_col=url_col, label_col=label_col)

    # 3. Stratified Train / Test Split on URLs
    X_train_urls, X_test_urls, y_train, y_test = preprocessor.split_data(
        df_clean, url_col=url_col, label_col="label_normalized"
    )

    # 4. Feature Extraction
    logger.info("Extracting features for Training Set...")
    X_train_feats = extract_features_dataframe(X_train_urls)

    logger.info("Extracting features for Testing Set...")
    X_test_feats = extract_features_dataframe(X_test_urls)

    # Save processed features CSV for EDA and verification
    processed_df = pd.concat([X_train_feats, X_test_feats], axis=0).copy()
    processed_df["target_label"] = pd.concat([y_train, y_test], axis=0).values
    DEFAULT_PROCESSED_DATASET_CSV.parent.mkdir(parents=True, exist_ok=True)
    processed_df.to_csv(DEFAULT_PROCESSED_DATASET_CSV, index=False)
    logger.info(f"Saved processed feature dataset ({len(processed_df)} records) to {DEFAULT_PROCESSED_DATASET_CSV}")

    # Convert to NumPy arrays for scikit-learn
    X_train_arr = X_train_feats.values
    X_test_arr = X_test_feats.values
    y_train_arr = y_train.values
    y_test_arr = y_test.values

    # 5. Fit Feature Scaler (Used specifically for Logistic Regression)
    logger.info("Fitting StandardScaler on Training features...")
    scaler = StandardScaler()
    scaler.fit(X_train_arr)
    X_train_scaled = scaler.transform(X_train_arr)

    # 6. Train Models
    # Model 1: Logistic Regression (L2 regularized, scaled features)
    logger.info("Training Model 1: Logistic Regression...")
    lr_model = LogisticRegression(
        C=1.0,
        solver="lbfgs",
        max_iter=1000,
        random_state=random_state
    )
    lr_model.fit(X_train_scaled, y_train_arr)
    logger.info("Logistic Regression training complete.")

    # Model 2: Decision Tree (interpretable, unscaled features)
    logger.info("Training Model 2: Decision Tree...")
    dt_model = DecisionTreeClassifier(
        criterion="gini",
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=random_state
    )
    dt_model.fit(X_train_arr, y_train_arr)
    logger.info("Decision Tree training complete.")

    # Model 3: Random Forest (ensemble of trees, unscaled features)
    logger.info("Training Model 3: Random Forest...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        criterion="gini",
        max_depth=12,
        min_samples_split=4,
        min_samples_leaf=2,
        random_state=random_state,
        n_jobs=-1
    )
    rf_model.fit(X_train_arr, y_train_arr)
    logger.info("Random Forest training complete.")

    # 7. Model Evaluation on Test Data
    logger.info("Evaluating all models on Holdout Test Set...")
    models_dict = {
        "Logistic Regression": lr_model,
        "Decision Tree": dt_model,
        "Random Forest": rf_model,
    }
    eval_results = compare_models(
        models_dict=models_dict,
        X_test=X_test_arr,
        y_test=y_test_arr,
        scaler=scaler
    )

    # 8. Feature Importance & Coefficients Extraction
    feature_analysis = extract_feature_importances(
        rf_model=rf_model,
        dt_model=dt_model,
        lr_model=lr_model,
        feature_names=FEATURE_NAMES
    )

    # 9. Save All Model Artifacts
    logger.info("Persisting model artifacts to disk...")
    joblib.dump(lr_model, LOGISTIC_REGRESSION_PATH)
    logger.info(f"Saved: {LOGISTIC_REGRESSION_PATH}")

    joblib.dump(dt_model, DECISION_TREE_PATH)
    logger.info(f"Saved: {DECISION_TREE_PATH}")

    joblib.dump(rf_model, RANDOM_FOREST_PATH)
    logger.info(f"Saved: {RANDOM_FOREST_PATH}")

    joblib.dump(scaler, SCALER_PATH)
    logger.info(f"Saved: {SCALER_PATH}")

    feature_metadata = get_feature_metadata()
    joblib.dump(feature_metadata, FEATURE_METADATA_PATH)
    logger.info(f"Saved: {FEATURE_METADATA_PATH}")

    # Pack comprehensive evaluation metrics bundle for dashboard
    metrics_bundle = {
        "evaluation": eval_results,
        "feature_analysis": feature_analysis,
        "test_sample_count": len(y_test_arr),
        "train_sample_count": len(y_train_arr),
        "class_distribution": {
            "train_legitimate": int((y_train_arr == 0).sum()),
            "train_phishing": int((y_train_arr == 1).sum()),
            "test_legitimate": int((y_test_arr == 0).sum()),
            "test_phishing": int((y_test_arr == 1).sum()),
        }
    }
    joblib.dump(metrics_bundle, EVALUATION_METRICS_PATH)
    logger.info(f"Saved: {EVALUATION_METRICS_PATH}")

    logger.info("==================================================")
    logger.info("   Training Pipeline Completed Successfully!   ")
    logger.info("==================================================")

    return metrics_bundle


if __name__ == "__main__":
    run_training_pipeline()
