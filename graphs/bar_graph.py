import streamlit as st
import pandas as pd
import plotly.express as px

@st.cache_data
def create_attact_count_dataframe(df):
    attack_type_counts = df['Attack_type'].value_counts().reset_index()
    attack_type_counts.columns = ['Attack_type', 'Count']
    return attack_type_counts

@st.cache_resource
def bar_graph(attack_type_counts):
    st.subheader("Attack Type Counts")
    fig = px.bar(attack_type_counts, x='Attack_type', y='Count')
    st.plotly_chart(fig)