"""
Data loader module for PhishGuard AI.
Handles loading datasets from CSV, auto-detecting URL and label columns,
and performing initial dataset structural validation.
"""

from pathlib import Path
from typing import Optional, Tuple, Dict, Any
import pandas as pd

from src.config import DEFAULT_RAW_DATASET_CSV
from src.utils import setup_logger

logger = setup_logger("DataLoader")

CANDIDATE_URL_COLUMNS = ["url", "URL", "url_address", "link", "domain", "web_url", "uri"]
CANDIDATE_LABEL_COLUMNS = ["label", "Label", "class", "Class", "status", "target", "result", "type", "is_phishing"]


class DatasetLoader:
    """
    Robust loader for phishing and legitimate URL datasets with column detection.
    """

    def __init__(self, filepath: Optional[Path] = None, url_col: Optional[str] = None, label_col: Optional[str] = None):
        self.filepath = Path(filepath) if filepath else DEFAULT_RAW_DATASET_CSV
        self.url_col = url_col
        self.label_col = label_col
        self.df: Optional[pd.DataFrame] = None

    def load(self) -> pd.DataFrame:
        """
        Loads the CSV file into a pandas DataFrame.
        """
        if not self.filepath.exists():
            raise FileNotFoundError(f"Dataset file not found at: {self.filepath}")

        logger.info(f"Loading dataset from: {self.filepath}")
        try:
            self.df = pd.read_csv(self.filepath, low_memory=False)
        except Exception as e:
            logger.error(f"Failed to read CSV at {self.filepath}: {e}")
            raise

        logger.info(f"Dataset loaded successfully with shape: {self.df.shape}")
        self._detect_columns()
        return self.df

    def _detect_columns(self) -> None:
        """
        Detects or verifies the URL and Label columns.
        """
        if self.df is None or self.df.empty:
            raise ValueError("DataFrame is empty or not loaded.")

        cols = list(self.df.columns)

        # Detect URL column
        if not self.url_col or self.url_col not in cols:
            for candidate in CANDIDATE_URL_COLUMNS:
                for col in cols:
                    if col.strip().lower() == candidate.lower():
                        self.url_col = col
                        break
                if self.url_col:
                    break

        if not self.url_col:
            # Fallback: find first object/string column
            for col in cols:
                if self.df[col].dtype == object and self.df[col].astype(str).str.contains(r"\.", regex=True).mean() > 0.5:
                    self.url_col = col
                    break

        if not self.url_col:
            raise ValueError(f"Could not auto-detect URL column from columns: {cols}. Please specify url_col explicitly.")

        # Detect Label column
        if not self.label_col or self.label_col not in cols:
            for candidate in CANDIDATE_LABEL_COLUMNS:
                for col in cols:
                    if col.strip().lower() == candidate.lower():
                        self.label_col = col
                        break
                if self.label_col:
                    break

        if not self.label_col:
            # Fallback: check columns with 2-3 unique values
            for col in cols:
                if col != self.url_col and self.df[col].nunique() in (2, 3):
                    self.label_col = col
                    break

        if not self.label_col:
            raise ValueError(f"Could not auto-detect Label column from columns: {cols}. Please specify label_col explicitly.")

        logger.info(f"Detected URL column: '{self.url_col}', Label column: '{self.label_col}'")

    def get_summary(self) -> Dict[str, Any]:
        """
        Returns a descriptive summary of the raw dataset.
        """
        if self.df is None:
            self.load()

        assert self.df is not None
        missing_count = int(self.df.isna().sum().sum())
        total_rows = len(self.df)
        cols = list(self.df.columns)

        return {
            "total_rows": total_rows,
            "total_columns": len(cols),
            "columns": cols,
            "url_column": self.url_col,
            "label_column": self.label_col,
            "missing_values_count": missing_count,
            "memory_usage_mb": round(self.df.memory_usage(deep=True).sum() / (1024 * 1024), 2)
        }


def load_raw_dataset(filepath: Optional[Path] = None, url_col: Optional[str] = None, label_col: Optional[str] = None) -> Tuple[pd.DataFrame, str, str]:
    """
    Convenience function returning (df, url_column, label_column).
    """
    loader = DatasetLoader(filepath=filepath, url_col=url_col, label_col=label_col)
    df = loader.load()
    assert loader.url_col is not None and loader.label_col is not None
    return df, loader.url_col, loader.label_col
