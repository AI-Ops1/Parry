import pandas as pd

def accumulate_metrics(df: pd.DataFrame, new_row: dict) -> pd.DataFrame:
    new_df = pd.DataFrame([new_row])
    return pd.concat([df, new_df], ignore_index=True)
