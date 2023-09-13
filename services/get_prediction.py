import joblib

MODEL_PATH = '../model/inceptiontime_model.pkl'

model = joblib.load(MODEL_PATH)


def get_predictions(df):
    predictions = model.predict(df)
    return predictions
