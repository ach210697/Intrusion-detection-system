from flask import Flask, render_template, request, jsonify
import joblib
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler

app = Flask(__name__)

# Load the saved models and scalers
ids_model = joblib.load('Models/IDS_Model_svc.pkl')
nsl_model = joblib.load('Models/NSL_KDD_rf.pkl')
scaler_ids = joblib.load('Models/scaler_ids.pkl')
scaler_nsl = joblib.load('Models/scaler_nsl.pkl')
label_encoder = joblib.load('Models/encodings.pkl')

# Define the required columns for each model
ids_columns = ['Dst Port', 'Protocol', 'Timestamp','Flow Duration', 'Tot Fwd Pkts',
       'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max',
       'Fwd Pkt Len Min', 'Fwd Pkt Len Mean', 'Fwd Pkt Len Std',
       'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean',
       'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean',
       'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot',
       'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
       'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max',
       'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags',
       'Bwd URG Flags', 'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s',
       'Bwd Pkts/s', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean',
       'Pkt Len Std', 'Pkt Len Var', 'FIN Flag Cnt', 'SYN Flag Cnt',
       'RST Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt', 'URG Flag Cnt',
       'CWE Flag Count', 'ECE Flag Cnt', 'Down/Up Ratio', 'Pkt Size Avg',
       'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Fwd Byts/b Avg',
       'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg',
       'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg', 'Subflow Fwd Pkts',
       'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts',
       'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts',
       'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max',
       'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']

nsl_columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes',
               'dst_bytes', 'wrong_fragment', 'hot', 'logged_in', 'num_compromised',
               'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
               'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
               'srv_diff_host_rate', 'dst_host_count']


@app.route('/')
def home():
    return render_template('public/index.html')


@app.route('/predict_ids', methods=['POST'])
def predict_ids():
    try:
        # Get data from request
        data = request.json

        # Convert to DataFrame
        df = pd.DataFrame([data])

        df = df.drop(columns = ['Timestamp'])
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)


        # Scale the features
        scaled_features = scaler_ids.transform(df)

        # Make prediction
        if (nsl_model.predict(scaled_features)[0]):
            prediction = 'normal'
        else:
            prediction = 'attack'

        return jsonify({
            'status': 'success',
            'prediction': prediction,
            'timestamp': pd.Timestamp.now().isoformat()
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/predict_nsl', methods=['POST'])
def predict_nsl():
    try:
        # Get data from request
        data = request.json

        # Convert categorical features
        for col in ['protocol_type', 'service', 'flag']:
            if col in data:
                try:
                    data[col] = label_encoder.transform([data[col]])[0]
                except ValueError:
                    data[col] = 0  # Assign a default value for unknown categories

        # Convert to DataFrame
        df = pd.DataFrame([data])

        # Scale the features
        scaled_features = scaler_nsl.transform(df[nsl_columns])

        # Make prediction
        if(nsl_model.predict(scaled_features)[0]):
            prediction = 'normal'
        else:
            prediction = 'attack'

        return jsonify({
            'status': 'success',
            'prediction': prediction,
            'timestamp': pd.Timestamp.now().isoformat()
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


if __name__ == '__main__':
    app.run(debug=True)