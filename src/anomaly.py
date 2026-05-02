import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest

def detect_anomalies(df):
    print("\n--- Checking for anomalies---")

    #Step 1 - Fill empty values with 0 
    #.fillna() is pandas - replaces NaN with 0
    df = df.fillna(0)

    #Step 2 - Select features for anomaly detection
    #list of column names we want
    features = ['protocol','size','src_port','dst_port']

    #Step 3 - Extract just those columns
    #PaNDAS - Creates a smaller table with only our features
    X = df[features]

    #Step 4 - Create and train the model
    #IsolationForest-scikit-learn
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(X)

    #Step 5 - Predict anomalies
    #-1 -anomaly, 1 - normal
    df['anomaly'] = model.predict(X)

    #Step 6 - filter only anomalies
    anomalies = df[df['anomaly'] == -1]

    print(f"Total packets analyzed: {len(df)}")
    print(f"Anomalies detected: {len(anomalies)}")
    print("\nSuspicious packets:")
    print(anomalies[['src_ip', 'dst_ip', 'dst_port', 'size', 'timestamp']].to_string())

    return anomalies



