import pandas as pd
import streamlit as st

FILE_PATH = 'data/test_data.csv'


@st.cache_data
def load_data():
    df = pd.read_csv(FILE_PATH)
    return df


@st.cache_data
def filter_data(df, filters):
    filtered_df = df.copy()
    
    for feature, value in filters.items():
        if value is not None:
            filtered_df = filtered_df[filtered_df[feature] == value]

    if filtered_df.empty:
        return "No data"
    else:
        return filtered_df