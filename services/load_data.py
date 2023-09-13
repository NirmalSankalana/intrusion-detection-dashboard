import pandas as pd
import streamlit as st

FILE_PATH = 'data/test_data.csv'


@st.cache_data
def load_data():
    df = pd.read_csv(FILE_PATH)
    return df


@st.cache_data
def filter_data(df, arp_opcode, arp_hw_size, icmp_checksum, icmp_seq_le, icmp_unused, http_content_length, http_request_method, http_referer, http_request_version, http_response, http_tls_port, tcp_ack, tcp_ack_raw, tcp_checksum, tcp_connection_fin, tcp_connection_rst):
    filtered_df = df[df['arp.opcode'] == arp_opcode]
    filtered_df = filtered_df[filtered_df['arp.hw.size'] == arp_hw_size]
    filtered_df = filtered_df[filtered_df['icmp.checksum'] == icmp_checksum]

    if filtered_df.empty:
        return "No data"
    else:
        return filtered_df
