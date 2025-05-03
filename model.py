import pandas as pd
import numpy as np
import time
import os
import matplotlib.pyplot as plt
from scapy.all import sniff
from tensorflow.keras.models import Model, load_model
from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.losses import MeanSquaredError
from sklearn.preprocessing import StandardScaler
from fpdf import FPDF

# Step 1: Load packet.csv
print(" Loading packet.csv...")
df = pd.read_csv('packet.csv', encoding='latin1')

# Step 2: Preprocessing
print(" Scaling numerical features...")
if 'Length' not in df.columns:
    raise Exception("Error: 'Length' column not found in your packet.csv!")

X = df[['Length']]
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Step 3: Model Load or Train
model_path = 'autoencoder_model.h5'

if os.path.exists(model_path):
    choice = input("🛠 Model found. Do you want to train a new model? (Y/N): ").strip().lower()
else:
    print(" No existing model found. Training a new model automatically.")
    choice = 'y'

if choice == 'y':
    print(" Building and Training Autoencoder...")
    input_dim = X_scaled.shape[1]
    input_layer = Input(shape=(input_dim,))
    encoded = Dense(8, activation='relu')(input_layer)
    encoded = Dense(4, activation='relu')(encoded)
    decoded = Dense(8, activation='relu')(encoded)
    decoded = Dense(input_dim, activation='linear')(decoded)

    autoencoder = Model(inputs=input_layer, outputs=decoded)
    autoencoder.compile(optimizer=Adam(learning_rate=0.001), loss=MeanSquaredError())

    print(" Training Autoencoder...")
    autoencoder.fit(X_scaled, X_scaled, epochs=50, batch_size=32, shuffle=True, verbose=1)

    autoencoder.save(model_path)
    print(f" Model trained and saved as '{model_path}'.")
else:
    print(f" Loading existing model '{model_path}'...")
    autoencoder = load_model(model_path)

# Step 4: Threshold calculation
reconstructions = autoencoder.predict(X_scaled)
mse = np.mean(np.power(X_scaled - reconstructions, 2), axis=1)
threshold = np.percentile(mse, 99)

print(f" Model ready. Anomaly detection threshold set at {threshold:.6f}")

# Step 5: Initialize counters
normal_count = 0
anomaly_count = 0
anomaly_packets = []
times = []
cumulative_anomalies = []

# Step 6: Real-Time Detection
start_time = time.time()
capture_duration = 300  # 5 minutes


def process_packet(packet):
    global normal_count, anomaly_count, start_time

    current_time = time.time()
    if current_time - start_time > capture_duration:
        print("\n 5 minutes over. Stopping capture...")
        sniff_stop()
        return

    try:
        length = len(packet)
        live_data = pd.DataFrame([[length]], columns=['Length'])
        live_scaled = scaler.transform(live_data)

        reconstruction = autoencoder.predict(live_scaled)
        mse_live = np.mean(np.power(live_scaled - reconstruction, 2), axis=1)

        if mse_live > threshold:
            print(f"\033[91m️ Anomaly detected! Packet length={length}\033[0m")
            anomaly_count += 1
            anomaly_packets.append({'Length': length})
        else:
            print(f"\033[92m Normal packet length={length}\033[0m")
            normal_count += 1

        times.append(current_time - start_time)
        cumulative_anomalies.append(anomaly_count)

    except Exception as e:
        print(f"Error processing packet: {e}")


# Step 7: Sniff-Stop Mechanism
sniffing = True


def sniff_stop():
    global sniffing
    sniffing = False


# Step 8: Start Packet Sniffing
print("🚀 Starting real-time packet sniffing for 5 minutes...")
try:
    sniff(prn=process_packet, store=0, stop_filter=lambda x: not sniffing)
except KeyboardInterrupt:
    print("\n Stopped sniffing manually.")


# Step 9: Generate Final Report
def generate_report():
    print("\n Detection Summary Report 📊")
    print(f"Total packets analyzed: {normal_count + anomaly_count}")
    print(f" Normal packets: {normal_count}")
    print(f" Anomaly packets: {anomaly_count}")

    if anomaly_packets:
        anomaly_df = pd.DataFrame(anomaly_packets)
        anomaly_df.to_csv('anomalies_detected_autoencoder.csv', index=False)
        print(" Anomaly packets saved to 'anomalies_detected_autoencoder.csv'.")

    # Plot and save live anomaly chart
    plt.figure(figsize=(10, 5))
    plt.plot(times, cumulative_anomalies, color='red', label='Cumulative Anomalies')
    plt.title('Real-Time Anomaly Detection')
    plt.xlabel('Time (seconds)')
    plt.ylabel('Cumulative Anomalies')
    plt.grid(True)
    plt.legend()
    plt.savefig('live_anomaly_chart.png')
    print(" Live anomaly chart saved as 'live_anomaly_chart.png'.")
    plt.close()


# Step 10: Generate PDF Report
def generate_pdf_report():
    pdf = FPDF()
    pdf.add_page()

    # Title
    pdf.set_font('Arial', 'B', 20)
    pdf.cell(0, 10, 'Anomaly Detection Report', ln=True, align='C')

    pdf.ln(10)

    # Packet Summary
    pdf.set_font('Arial', '', 14)
    pdf.cell(0, 10, f'Total Packets Analyzed: {normal_count + anomaly_count}', ln=True)
    pdf.cell(0, 10, f' Normal Packets: {normal_count}', ln=True)
    pdf.cell(0, 10, f' Anomaly Packets: {anomaly_count}', ln=True)

    pdf.ln(10)

    # Insert Graph
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, 'Anomaly Timeline Chart:', ln=True)

    pdf.image('live_anomaly_chart.png', x=10, y=None, w=190)

    # Save PDF
    pdf.output('Anomaly_Report.pdf')
    print(" PDF Report generated: 'Anomaly_Report.pdf'")


# Step 11: Run Reports
generate_report()
generate_pdf_report()