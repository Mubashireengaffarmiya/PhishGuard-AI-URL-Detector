"""
Model evaluation module for PhishGuard AI.
Calculates Accuracy, Precision, Recall, F1-Score, ROC-AUC, and Confusion Matrices.
Generates comparative visualizations and extracts feature importances and coefficients.
"""

from typing import Dict, Any, List, Tuple
import matplotlib
matplotlib.use("Agg")  # Non-interactive headless backend for server & scripts
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    roc_curve
)

from src.utils import setup_logger

logger = setup_logger("ModelEvaluation")


def evaluate_single_model(
    model: Any,
    X_test: np.ndarray,
    y_test: np.ndarray,
    model_name: str,
    needs_scaled: bool = False,
    scaler: Any = None
) -> Dict[str, Any]:
    """
    Evaluates a single trained model on test data and computes all core metrics.
    """
    X_eval = scaler.transform(X_test) if (needs_scaled and scaler is not None) else X_test

    y_pred = model.predict(X_eval)

    # Compute probabilities if supported
    y_prob = None
    roc_auc = 0.0
    if hasattr(model, "predict_proba"):
        try:
            proba = model.predict_proba(X_eval)
            y_prob = proba[:, 1]
            roc_auc = float(roc_auc_score(y_test, y_prob))
        except Exception as e:
            logger.warning(f"Could not calculate ROC-AUC for {model_name}: {e}")
            roc_auc = 0.0
    elif hasattr(model, "decision_function"):
        try:
            scores = model.decision_function(X_eval)
            roc_auc = float(roc_auc_score(y_test, scores))
        except Exception:
            roc_auc = 0.0

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    logger.info(
        f"[{model_name}] Accuracy: {acc:.4f} | Precision: {prec:.4f} | Recall: {rec:.4f} | F1: {f1:.4f} | AUC: {roc_auc:.4f}"
    )

    return {
        "model_name": model_name,
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "roc_auc": roc_auc,
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
            "matrix": cm.tolist()
        },
        "y_pred": y_pred.tolist(),
        "y_prob": y_prob.tolist() if y_prob is not None else None
    }


def compare_models(
    models_dict: Dict[str, Any],
    X_test: np.ndarray,
    y_test: np.ndarray,
    scaler: Any = None
) -> Dict[str, Any]:
    """
    Evaluates all 3 models and returns a consolidated performance comparison.
    """
    results: Dict[str, Any] = {}
    summary_rows = []

    for name, model in models_dict.items():
        needs_scale = (name == "Logistic Regression")
        eval_data = evaluate_single_model(
            model=model,
            X_test=X_test,
            y_test=y_test,
            model_name=name,
            needs_scaled=needs_scale,
            scaler=scaler
        )
        results[name] = eval_data
        summary_rows.append({
            "Model": name,
            "Accuracy": eval_data["accuracy"],
            "Precision": eval_data["precision"],
            "Recall": eval_data["recall"],
            "F1-Score": eval_data["f1"],
            "ROC-AUC": eval_data["roc_auc"]
        })

    summary_df = pd.DataFrame(summary_rows)
    return {
        "model_evaluations": results,
        "summary_table": summary_df.to_dict(orient="records")
    }


def extract_feature_importances(
    rf_model: Any,
    dt_model: Any,
    lr_model: Any,
    feature_names: List[str]
) -> Dict[str, Any]:
    """
    Extracts feature importances from tree models and normalized coefficients from Logistic Regression.
    """
    rf_importances = None
    if hasattr(rf_model, "feature_importances_"):
        rf_pairs = list(zip(feature_names, rf_model.feature_importances_))
        rf_pairs.sort(key=lambda x: x[1], reverse=True)
        rf_importances = [{"feature": f, "importance": float(round(imp, 5))} for f, imp in rf_pairs]

    dt_importances = None
    if hasattr(dt_model, "feature_importances_"):
        dt_pairs = list(zip(feature_names, dt_model.feature_importances_))
        dt_pairs.sort(key=lambda x: x[1], reverse=True)
        dt_importances = [{"feature": f, "importance": float(round(imp, 5))} for f, imp in dt_pairs]

    lr_coefficients = None
    if hasattr(lr_model, "coef_"):
        coefs = lr_model.coef_[0]
        lr_pairs = list(zip(feature_names, coefs))
        lr_pairs.sort(key=lambda x: abs(x[1]), reverse=True)
        lr_coefficients = [{"feature": f, "coefficient": float(round(c, 5)), "direction": "Phishing" if c > 0 else "Safe"} for f, c in lr_pairs]

    return {
        "random_forest_importance": rf_importances,
        "decision_tree_importance": dt_importances,
        "logistic_regression_coefficients": lr_coefficients
    }
