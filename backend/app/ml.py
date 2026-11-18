from pathlib import Path


def require_dataset(path: str) -> Path:
    dataset = Path(path)
    if not dataset.is_dir() or not list(dataset.glob("*.csv")):
        raise FileNotFoundError("Expected a directory containing official CICIDS2017 CSV files.")
    return dataset
