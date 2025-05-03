import pandas as pd
import numpy as np
import time
from scapy.all import sniff
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.optimizers import Adam
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import matplotlib.animation as animation

# Step 1: Load packet.csv
print("📂 Loading packet.csv...")
df = pd.read_csv('packet.csv', encoding='latin1')

# Step 2: Preprocessing
print("🛠 Scaling numerical features...")
if 'Length' not in df.columns:
    raise Exception("Error: 'Length' column not found in your packet.csv!")

X = df[['Length']]
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Step 3: Build Autoencoder
print("🤖 Building Autoencoder model...")
input_dim = X_scaled.shape[1]
input_layer = Input(shape=(input_dim,))
encoded = Dense(8, activation='relu')(input_layer)
encoded = Dense(4, activation='relu')(encoded)
decoded = Dense(8, activation='relu')(encoded)
decoded = Dense(input_dim, activation='linear')(decoded)

autoencoder = Model(inputs=input_layer, outputs=decoded)
autoencoder.compile(optimizer=Adam(learning_rate=0.001), loss='mse')

# Step 4: Train Autoencoder
print("🎯 Training Autoencoder...")
autoencoder.fit(X_scaled, X_scaled, epochs=50, batch_size=32, shuffle=True, verbose=1)

# Step 5: Calculate threshold
reconstructions = autoencoder.predict(X_scaled)
mse = np.mean(np.power(X_scaled - reconstructions, 2), axis=1)
threshold = np.percentile(mse, 99)

print(f"✅ Training completed. Anomaly threshold set at {threshold:.6f}")

# Step 6: Initialize counters and timestamps
normal_count = 0
anomaly_count = 0
anomaly_packets = []
anomaly_times = []    # Store times of anomalies
cumulative_anomalies = []  # Store cumulative anomaly count
time_stamps = []   # Store time axis for chart

# Step 7: Real-Time Detection
start_time = time.time()
capture_duration = 300  # 5 minutes

def process_packet(packet):
    global normal_count, anomaly_count, start_time

    current_time = time.time()
    if current_time - start_time > capture_duration:
        print("\n⏰ 5 minutes over. Stopping capture...")
        sniff_stop()
        return

    try:
        length = len(packet)

        live_data = pd.DataFrame([[length]], columns=['Length'])
        live_scaled = scaler.transform(live_data)

        reconstruction = autoencoder.predict(live_scaled)
        mse_live = np.mean(np.power(live_scaled - reconstruction, 2), axis=1)

        if mse_live > threshold:
            print(f"\033[91m⚠️ Anomaly detected! Packet length={length}\033[0m")
            anomaly_count += 1
            anomaly_packets.append({'Length': length})
            anomaly_times.append(current_time - start_time)
        else:
            print(f"\033[92m✅ Normal packet length={length}\033[0m")
            normal_count += 1

    except Exception as e:
        print(f"Error processing packet: {e}")

# Step 8: Sniff-Stop Mechanism
sniffing = True
def sniff_stop():
    global sniffing
    sniffing = False

# Step 9: Live Chart Setup
fig, ax = plt.subplots()
ax.set_xlim(0, capture_duration)
ax.set_ylim(0, 50)  # Max anomalies visible
line, = ax.plot([], [], lw=2, color='red')
ax.set_title('Real-Time Anomaly Detection')
ax.set_xlabel('Time (seconds)')
ax.set_ylabel('Cumulative Anomalies')
plt.grid(True)

def update_chart(frame):
    # Update chart every second
    current_elapsed = time.time() - start_time
    time_stamps.append(current_elapsed)
    cumulative_anomalies.append(len(anomaly_times))

    line.set_data(time_stamps, cumulative_anomalies)
    ax.relim()
    ax.autoscale_view()
    return line,

ani = animation.FuncAnimation(fig, update_chart, interval=1000)

# Step 10: Start Sniffing and Plot
print("🚀 Starting real-time packet sniffing and live chart...")
try:
    sniff(prn=process_packet, store=0, stop_filter=lambda x: not sniffing)
except KeyboardInterrupt:
    print("\n🛑 Stopped sniffing manually.")

generate_report_called = False

# Step 11: Generate Final Report
def generate_report():
    global generate_report_called
    if generate_report_called:
        return
    generate_report_called = True

    print("\n📊 Detection Summary Report 📊")
    print(f"Total packets analyzed: {normal_count + anomaly_count}")
    print(f"✅ Normal packets: {normal_count}")
    print(f"⚠️ Anomaly packets: {anomaly_count}")

    if anomaly_packets:
        anomaly_df = pd.DataFrame(anomaly_packets)
        anomaly_df.to_csv('anomalies_detected_autoencoder.csv', index=False)
        print("📝 Anomaly packets saved to 'anomalies_detected_autoencoder.csv'.")

    plt.savefig('live_anomaly_chart.png')
    print("📈 Live anomaly chart saved as 'live_anomaly_chart.png'.")

generate_report()
plt.show()