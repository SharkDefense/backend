# myapp/predictor.py

import numpy as np
from .feature import FeatureExtraction
from .model_loader import gbc

def predict(url):
    if gbc:
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1, 30)

        y_pred = gbc.predict(x)[0]

        prediction_message = "It is safe" if y_pred == 1 else "malicious from model"
        return prediction_message
    else:
        return {'message': 'Model not loaded.'}
