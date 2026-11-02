import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Step 1: Simulate normal and unusual network traffic data
np.random.seed(42)
n_samples = 1000

# Normal traffic: standard packet sizes and bytes transferred
normal_data = {
    'packet_size': np.random.normal(loc=500, scale=50, size=n_samples),
    'bytes_transferred': np.random.normal(loc=2000, scale=300, size=n_samples),
    'connection_duration': np.random.normal(loc=15, scale=3, size=n_samples),
}
df_normal = pd.DataFrame(normal_data)

# Anomalous traffic: sudden massive packet sizes, heavy bytes, or strange durations (e.g., DDoS or data exfiltration)
n_anomalies = 20
anomaly_data = {
    'packet_size': np.random.randint(1500, 3000, size=n_anomalies),
    'bytes_transferred': np.random.randint(10000, 50000, size=n_anomalies),
    'connection_duration': np.random.randint(60, 300, size=n_anomalies),
}
df_anomaly = pd.DataFrame(anomaly_data)

# Combine datasets and shuffle
df = pd.concat([df_normal, df_anomaly], ignore_index=True)
df = df.sample(frac=1).reset_index(drop=True)

# Step 2: Scale features (Recommended for Distance/Tree-based isolation metrics)
scaler = StandardScaler()
features = ['packet_size', 'bytes_transferred', 'connection_duration']
df_scaled = pd.DataFrame(scaler.fit_transform(df[features]), columns=features)

# Step 3: Train the Isolation Forest Model
# contamination is the estimated proportion of outliers in the dataset (approx 2%)
model = IsolationForest(contamination=0.02, random_state=42)

# Fit and predict (-1 for anomalies, 1 for normal)
df['prediction'] = model.fit_predict(df_scaled)
# Decision function: Negative scores represent outliers, positive represent inliers
df['anomaly_score'] = model.decision_function(df_scaled)

# Map predictions to readable labels
df['is_unusual'] = df['prediction'].apply(lambda x: 'Yes' if x == -1 else 'No')

# Step 4: Filter and view detected unusual traffic
unusual_traffic = df[df['is_unusual'] == 'Yes']
print(f'Total traffic logs analyzed: {len(df)}')
print(f'Unusual traffic instances detected: {len(unusual_traffic)}')
print('\nSample of detected unusual traffic:')
print(
    unusual_traffic[[
        'packet_size',
        'bytes_transferred',
        'connection_duration',
        'anomaly_score',
    ]].head()
)

# Step 5: Visualize the results with enhanced clarity
plt.figure(figsize=(11, 6))

# Plot normal traffic
normal_points = df[df['is_unusual'] == 'No']
plt.scatter(
    normal_points['packet_size'],
    normal_points['bytes_transferred'],
    c='dodgerblue',
    label='Normal Traffic',
    alpha=0.6,
    edgecolor='k',
    s=40,
)

# Plot anomalies distinctively
anomaly_points = df[df['is_unusual'] == 'Yes']
plt.scatter(
    anomaly_points['packet_size'],
    anomaly_points['bytes_transferred'],
    c='crimson',
    label='Anomalous Traffic (Threats)',
    alpha=0.9,
    marker='X',
    s=100,
    edgecolor='k',
)

plt.title(
    'Home Network Threat Detection - Isolation Forest',
    fontsize=14,
    fontweight='bold',
)
plt.xlabel('Packet Size (Bytes)', fontsize=12)
plt.ylabel('Bytes Transferred', fontsize=12)
plt.legend(loc='upper left', frameon=True)
plt.grid(True, linestyle='--', alpha=0.5)
plt.tight_layout()
plt.show()
