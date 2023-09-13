import pandas as pd
import streamlit as st

FILE_PATH = 'data/test_data.csv'


@st.cache_data
def load_data():
    df = pd.read_csv(FILE_PATH)
    return df


@st.cache_data
def filter_data(df, arp_opcode, arp_hw_size, icmp_checksum):
    filtered_df = df[df['arp.opcode'] == arp_opcode]
    filtered_df = filtered_df[filtered_df['arp.hw.size'] == arp_hw_size]
    filtered_df = filtered_df[filtered_df['icmp.checksum'] == icmp_checksum]

    if filtered_df.empty:
        return "No data"
    else:
        return filtered_df
