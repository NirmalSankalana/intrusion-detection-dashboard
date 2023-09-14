import streamlit as st


def get_description(df):
    df_description = df.describe()
    # Display the description using st.text()
    st.subheader("Dataset Description")
    st.write(df_description)


