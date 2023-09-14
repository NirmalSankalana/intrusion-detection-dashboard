import streamlit as st
import joblib
import numpy as np

import random

MODEL_PATH = 'model/finalmodel.pkl'

@st.cache_resource
def load_model():
    model = joblib.load(MODEL_PATH)
    return model

def get_prediction(df):
    model = load_model()
    predictions = model.predict(df)
    return predictions


# fake_input = [random.uniform(0, 1) for _ in range(47)]
# get_prediction([fake_input])
