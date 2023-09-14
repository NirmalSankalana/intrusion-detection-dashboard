import streamlit as st
from sklearn.metrics import accuracy_score, confusion_matrix

@st.cache_data
def x_y_split(df):
    attack_type_mapping = {
    13: 'Vulnerability_scanner',
    6: 'Normal',
    4: 'DDOS_UDP',
    1: 'DDOS_HTTP',
    11: 'SQL_injection',
    8: 'Password',
    10: 'Ransomware',
    7: 'OS_Fingerprinting',
    0: 'Backdoor',
    14: 'XSS',
    12: 'Uploading',
    5: 'MITM',
    9: 'Port_Scanning',
    2: 'DDOS_ICMP',
    3: 'DDOS_TCP'
}

    # Reverse the encoding using the attack_type_mapping
    df['Attack_type'] = df['Attack_type'].map(attack_type_mapping)
    X = df.drop("Attack_type", axis=1)
    y = df['Attack_type']
    return X, y

@st.cache_data
def get_confusion_matrix(y, y_pred):
    accuracy = accuracy_score(y, y_pred)
    cm = confusion_matrix(y, y_pred)
    st.subheader("confusion_matrix")
    st.write(cm)