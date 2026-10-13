import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt

# Step 1: Simulate normal and unusual network traffic data
np.random.seed(42)
n_samples = 1000

# Normal traffic: standard packet sizes and bytes transferred
normal_data = {
    'packet_size': np.random.normal(loc=500, scale=50, size=n_samples),
    'bytes_transferred': np.random.normal(loc=2000, scale=300, size=n_samples),
    'connection_duration': np.random.normal(loc=15, scale=3, size=n_samples)
}
df_normal = pd.DataFrame(normal_data)

# Anomalous traffic: sudden massive packet sizes, heavy bytes, or strange durations (e.g., DDoS or data exfiltration)
n_anomalies = 20
anomaly_data = {
    'packet_size': np.random.randint(1500, 3000, size=n_anomalies),
    'bytes_transferred': np.random.randint(10000, 50000, size=n_anomalies),
    'connection_duration': np.random.randint(60, 300, size=n_anomalies)
}
df_anomaly = pd.DataFrame(anomaly_data)

# Combine datasets and shuffle
df = pd.concat([df_normal, df_anomaly], ignore_index=True)
df = df.sample(frac=1).reset_index(drop=True)

# Step 2: Train the Isolation Forest Model
# contamination is the estimated proportion of outliers in the dataset (approx 2%)
model = IsolationForest(contamination=0.02, random_state=42)
df['anomaly_score'] = model.fit_predict(df[['packet_size', 'bytes_transferred', 'connection_duration']])

# Isolation Forest outputs: 1 for normal traffic, -1 for unusual/anomalous traffic
df['is_unusual'] = df['anomaly_score'].apply(lambda x: 'Yes' if x == -1 else 'No')

# Step 3: Filter and view detected unusual traffic
unusual_traffic = df[df['is_unusual'] == 'Yes']
print(f"Total traffic logs analyzed: {len(df)}")
print(f"Unusual traffic instances detected: {len(unusual_traffic)}")
print("\nSample of detected unusual traffic:")
print(unusual_traffic.head())

# Step 4: Visualize the results
plt.figure(figsize=(10, 6))
plt.scatter(df['packet_size'], df['bytes_transferred'], 
            c=df['anomaly_score'], cmap='coolwarm', edgecolor='k', alpha=0.7)
plt.title('Unusual Network Traffic Detection (Isolation Forest)')
plt.xlabel('Packet Size')
plt.ylabel('Bytes Transferred')
plt.grid(True)
plt.show()
