import azure.functions as func
import pandas as pd
import numpy as np
import joblib
import json
import logging
import os

# Configure logging
logging.getLogger('azure').setLevel(logging.INFO)

# Load the Random Forest model (global scope, but handle loading inside main for Azure)
rf_model = None

def main(req: func.HttpRequest) -> func.HttpResponse:
    global rf_model
    logging.info(f"Current working directory: {os.getcwd()}")

    # Load or reload model on each request for Azure Functions
    try:
        model_path = os.path.join(os.getcwd(), 'models', 'rf_model_v3.pkl')
        logging.info(f"Attempting to load model from: {model_path}")
        if not os.path.exists(model_path):
            logging.error(f"Model file does not exist at: {model_path}")
            return func.HttpResponse(f"Model file not found at {model_path}", status_code=500)
        rf_model = joblib.load(model_path)
        logging.info(f"Random Forest model loaded successfully from {model_path}")
    except Exception as e:
        logging.error(f"Error loading model: {str(e)}")
        return func.HttpResponse(f"Error loading model: {str(e)}", status_code=500)

    logging.info('Python HTTP trigger function processed a request.')
    try:
        req_body = req.get_json()
        logging.info(f"Received request body: {req_body}")
        if not req_body:
            logging.warning("No JSON data provided")
            return func.HttpResponse("No JSON data provided", status_code=400)

        expected_columns = ['dom_dga_prob', 'urlhaus_status', 'client_tls_ver',
                          'svr_tls_ver', 'svr_supported_ver', 'otx_status',
                          'ja3_urlhaus_status']
        if not all(col in req_body for col in expected_columns):
            missing = [col for col in expected_columns if col not in req_body]
            logging.warning(f"Missing columns: {missing}")
            return func.HttpResponse(f"Missing columns: {missing}", status_code=400)

        input_data = pd.DataFrame([req_body], columns=expected_columns)
        logging.info(f"Input data shape: {input_data.shape}")
        prediction = rf_model.predict(input_data)[0]
        probability = rf_model.predict_proba(input_data)[0][1]
        logging.info(f"Prediction: {prediction}, Probability: {probability}")
        label = "Malware" if prediction == 1 else "Benign"
        return func.HttpResponse(
            json.dumps({
                "prediction": label,
                "probability_malware": float(probability),
                "message": "Prediction successful"
            }),
            status_code=200,
            mimetype="application/json"
        )
    except Exception as e:
        logging.error(f"Error during prediction: {str(e)}", exc_info=True)
        return func.HttpResponse(f"Error during prediction: {str(e)}", status_code=500)