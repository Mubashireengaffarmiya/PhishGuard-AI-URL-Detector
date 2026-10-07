"""
Preprocessing module for PhishGuard AI.
Cleans raw URL datasets, removes invalid/duplicate rows, normalizes labels to binary (0/1),
checks for class imbalance, and executes stratified train/test splitting.
"""

from typing import Tuple, Dict, Any, Optional
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from src.utils import setup_logger, is_valid_url

logger = setup_logger("Preprocessing")

# Canonical label mapping
LABEL_MAPPING = {
    # Legitimate (0)
    "0": 0,
    0: 0,
    -1: 0,
    "-1": 0,
    "legitimate": 0,
    "benign": 0,
    "safe": 0,
    "good": 0,
    "normal": 0,
    "ham": 0,
    "clean": 0,
    # Phishing (1)
    "1": 1,
    1: 1,
    "phishing": 1,
    "malicious": 1,
    "bad": 1,
    "phish": 1,
    "spam": 1,
    "fraud": 1
}


class DataPreprocessor:
    """
    Cleans and prepares URL dataset for feature extraction and model training.
    """

    def __init__(self, random_state: int = 42, test_size: float = 0.20):
        self.random_state = random_state
        self.test_size = test_size

    def clean_dataset(
        self,
        df: pd.DataFrame,
        url_col: str,
        label_col: str,
        drop_duplicates: bool = True
    ) -> pd.DataFrame:
        """
        Cleans the DataFrame, handles missing values, normalizes labels to 0 and 1,
        and removes invalid URL strings.
        """
        logger.info(f"Initial raw rows: {len(df)}")
        cleaned_df = df.copy()

        # 1. Drop nulls in URL or label columns
        cleaned_df = cleaned_df.dropna(subset=[url_col, label_col])
        logger.info(f"Rows after dropping nulls in critical columns: {len(cleaned_df)}")

        # 2. Convert URL to string and trim
        cleaned_df[url_col] = cleaned_df[url_col].astype(str).str.strip()
        cleaned_df = cleaned_df[cleaned_df[url_col] != ""]

        # 3. Drop duplicate URLs
        if drop_duplicates:
            before_dedup = len(cleaned_df)
            cleaned_df = cleaned_df.drop_duplicates(subset=[url_col])
            logger.info(f"Dropped {before_dedup - len(cleaned_df)} duplicate URL rows. Remaining: {len(cleaned_df)}")

        # 4. Normalize labels to 0 (Legitimate) and 1 (Phishing)
        def map_label(val: Any) -> Optional[int]:
            if isinstance(val, (int, np.integer)):
                return LABEL_MAPPING.get(val, None)
            if isinstance(val, float):
                if np.isnan(val):
                    return None
                val = int(val)
                return LABEL_MAPPING.get(val, None)
            val_str = str(val).strip().lower()
            return LABEL_MAPPING.get(val_str, None)

        cleaned_df["label_normalized"] = cleaned_df[label_col].apply(map_label)
        unmapped_count = cleaned_df["label_normalized"].isna().sum()
        if unmapped_count > 0:
            logger.warning(f"Dropping {unmapped_count} rows with unrecognized label values.")
            cleaned_df = cleaned_df.dropna(subset=["label_normalized"])

        cleaned_df["label_normalized"] = cleaned_df["label_normalized"].astype(int)

        # 5. Filter out completely invalid URLs
        valid_mask = cleaned_df[url_col].apply(lambda u: is_valid_url(u)[0])
        invalid_count = (~valid_mask).sum()
        if invalid_count > 0:
            logger.info(f"Dropping {invalid_count} structurally unparseable URLs.")
            cleaned_df = cleaned_df[valid_mask]

        logger.info(f"Final cleaned dataset size: {len(cleaned_df)}")
        self._check_class_distribution(cleaned_df["label_normalized"])

        return cleaned_df.reset_index(drop=True)

    def _check_class_distribution(self, labels: pd.Series) -> Dict[str, Any]:
        """
        Inspects class distribution and logs warnings if severe imbalance exists.
        """
        counts = labels.value_counts().to_dict()
        legitimate_count = counts.get(0, 0)
        phishing_count = counts.get(1, 0)
        total = len(labels)

        if total == 0:
            raise ValueError("No valid records remain after cleaning.")

        legit_pct = (legitimate_count / total) * 100
        phish_pct = (phishing_count / total) * 100

        logger.info(
            f"Class Distribution -> Legitimate (0): {legitimate_count} ({legit_pct:.1f}%), "
            f"Phishing (1): {phishing_count} ({phish_pct:.1f}%)"
        )

        imbalance_ratio = max(legit_pct, phish_pct) / max(min(legit_pct, phish_pct), 0.001)
        if imbalance_ratio > 4.0:
            logger.warning(
                f"Severe class imbalance detected! Ratio is {imbalance_ratio:.2f}:1. "
                "Stratification will be strictly enforced."
            )

        return {
            "legitimate_count": legitimate_count,
            "phishing_count": phishing_count,
            "legitimate_pct": legit_pct,
            "phishing_pct": phish_pct,
            "imbalance_ratio": imbalance_ratio
        }

    def split_data(
        self,
        df: pd.DataFrame,
        url_col: str,
        label_col: str = "label_normalized"
    ) -> Tuple[pd.Series, pd.Series, pd.Series, pd.Series]:
        """
        Stratified train-test split.
        Returns: (X_train_urls, X_test_urls, y_train, y_test)
        """
        X = df[url_col]
        y = df[label_col]

        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=self.test_size,
            random_state=self.random_state,
            stratify=y
        )

        logger.info(
            f"Split into Train: {len(X_train)} samples, Test: {len(X_test)} samples (test_size={self.test_size})"
        )
        return X_train, X_test, y_train, y_test
