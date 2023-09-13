import joblib

MODEL_PATH = '../model/hybrid_model3.pkl'

model = joblib.load(MODEL_PATH)

def get_predictions(df):
    predictions = model.predict(df)
    return predictions