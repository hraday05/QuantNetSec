import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from flask import Flask, jsonify, send_file
import joblib
import numpy as np
from datetime import datetime
import threading
import time
import pandas as pd
from flask_socketio import SocketIO
from scapy.all import sniff
from scapy.layers.inet import TCP, IP, UDP

from quant.ema.ema_api import update_ema

# ---------------- INIT ----------------
app2 = Flask(__name__)
socketio = SocketIO(app2, cors_allowed_origins="*", async_mode='threading')

lock = threading.Lock()

latest_pkt = {
    "prediction": "Detecting...",
    "timestamp": "Start",
    "packet_size": 0,
    "src_ip": "-",
    "dst_ip": "-",
    "protocol": 0,
    "total_packets": 0,
    "tcp_count": 0,
    "udp_count": 0
}

tcp_count = 0
udp_count = 0
total_packets = 0
flows = {}

model = joblib.load('model.pkl')
scaler = joblib.load('scaler.pkl')
le = joblib.load('label_encoder.pkl')
feature_names = joblib.load('features.pkl')

last_emit_time = 0  # for throttling


# ---------------- PACKET SNIFFER ----------------
def packet_sniffer():

    def process_packet(pkt):
        global latest_pkt, tcp_count, udp_count, total_packets, flows, last_emit_time

        try:
            if not pkt.haslayer(IP):
                return

            ip_layer = pkt[IP]
            proto = ip_layer.proto

            # ---------- COUNTERS ----------
            with lock:
                total_packets += 1
                if proto == 6:
                    tcp_count += 1
                elif proto == 17:
                    udp_count += 1

            # ---------- FLOW LOGIC ----------
            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]

                key = (
                    ip_layer.src,
                    ip_layer.dst,
                    tcp_layer.sport,
                    tcp_layer.dport,
                    proto
                )

                with lock:
                    if key not in flows:
                        flows[key] = {
                            "packets": [],
                            "start_time": pkt.time,
                            "last_time": pkt.time,
                            "active_times": [],
                            "idle_times": [],
                            "last_active": pkt.time
                        }

                    flow = flows[key]
                    flow["packets"].append(pkt)

                    now = pkt.time

                    if now - flow["last_active"] > 1:
                        flow["idle_times"].append(now - flow["last_active"])
                    else:
                        flow["active_times"].append(now - flow["last_time"])

                    flow["last_active"] = now
                    flow["last_time"] = now

                # ---------- ML PREDICTION ----------
                if len(flow["packets"]) >= 20:
                      features = extract_features(flow, proto)

                      ml_label = predict(features)

                      duration = flow["last_time"] - flow["start_time"]
                      pps = len(flow["packets"]) / max(duration, 1)

                      if ml_label != "Benign":
                          final_label = ml_label
                      elif pps > 1000:
                          final_label = "DDoS"
                      else:
                          final_label = "Normal"

                      with lock:
                          latest_pkt["prediction"] = final_label
                          del flows[key]

            # ---------- UPDATE PACKET ----------
            with lock:
                latest_pkt.update({
                    "src_ip": ip_layer.src,
                    "dst_ip": ip_layer.dst,
                    "protocol": proto,
                    "packet_size": len(pkt),
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "total_packets": total_packets,
                    "tcp_count": tcp_count,
                    "udp_count": udp_count
                })

            # ---------- EMA ----------
            ema_result = update_ema(latest_pkt["packet_size"])
            latest_pkt["ema"] = ema_result["ema"]
            latest_pkt["trend"] = ema_result["trend"]
            latest_pkt["ema_history"] = ema_result["history"]

            # ---------- WEBSOCKET EMIT (THROTTLED) ----------
            if time.time() - last_emit_time > 0.2:
                socketio.emit('packet_update', dict(latest_pkt))  # send copy
                last_emit_time = time.time()

        except Exception as e:
            print("Error:", e)

    sniff(prn=process_packet, store=False)


# ---------------- FEATURE EXTRACTION ----------------
def extract_features(flow, proto):
    packets = flow["packets"]
    sizes = [len(p) for p in packets]
    times = [p.time for p in packets]

    src_ip = packets[0][IP].src

    fwd_sizes, bwd_sizes = [], []
    fwd = bwd = 0

    for p in packets:
        if p[IP].src == src_ip:
            fwd += 1
            fwd_sizes.append(len(p))
        else:
            bwd += 1
            bwd_sizes.append(len(p))

    duration = times[-1] - times[0] if len(times) > 1 else 0
    total_bytes = sum(sizes)
    iat = np.diff(times) if len(times) > 1 else [0]

    # TCP FLAGS
    syn = ack = rst = psh = 0
    for p in packets:
        if p.haslayer(TCP):
            flags = p[TCP].flags
            syn += int(flags & 0x02 != 0)
            ack += int(flags & 0x10 != 0)
            rst += int(flags & 0x04 != 0)
            psh += int(flags & 0x08 != 0)

    features = {
        "Flow Duration": duration,
        "Total Fwd Packets": fwd,
        "Total Backward Packets": bwd,
        "Fwd Packets Length Total": sum(fwd_sizes),
        "Bwd Packets Length Total": sum(bwd_sizes),

        "Fwd Packet Length Max": max(fwd_sizes) if fwd_sizes else 0,
        "Fwd Packet Length Mean": np.mean(fwd_sizes) if fwd_sizes else 0,
        "Fwd Packet Length Std": np.std(fwd_sizes) if fwd_sizes else 0,
        "Bwd Packet Length Max": max(bwd_sizes) if bwd_sizes else 0,
        "Bwd Packet Length Mean": np.mean(bwd_sizes) if bwd_sizes else 0,

        "Flow Bytes/s": total_bytes / duration if duration > 0 else 0,
        "Flow Packets/s": len(packets) / duration if duration > 0 else 0,

        "Flow IAT Mean": np.mean(iat),
        "Flow IAT Std": np.std(iat),
        "Flow IAT Max": np.max(iat),

        "Fwd IAT Mean": np.mean(iat),
        "Fwd IAT Std": np.std(iat),

        "SYN Flag Count": syn,
        "ACK Flag Count": ack,
        "RST Flag Count": rst,
        "PSH Flag Count": psh,

        "Down/Up Ratio": bwd / fwd if fwd > 0 else 0,

        "Avg Packet Size": np.mean(sizes),
        "Avg Fwd Segment Size": np.mean(fwd_sizes) if fwd_sizes else 0,
        "Avg Bwd Segment Size": np.mean(bwd_sizes) if bwd_sizes else 0
    }

    return features


# ---------------- PREDICTION ----------------
def prepare_input(features):
    df = pd.DataFrame([features])
    df = df.reindex(columns=feature_names, fill_value=0)
    return df


def predict(features):
    try:
        df = prepare_input(features)
        scaled = scaler.transform(df)
        pred = model.predict(scaled)
        return le.inverse_transform(pred)[0]
    except Exception as e:
        print("Prediction error:", e)
        return "Benign"


# ---------------- ROUTES ----------------
@app2.route("/")
def home():
    frontend_path = os.path.join(
        os.path.dirname(__file__),  # backend/
        "..",                       # go to QuantNetSec/
        "frontend",                 # go to frontend/
        "index.html"             # your file
    )
    return send_file(frontend_path)


@app2.route("/live_packet")
def get_pkt():
    return jsonify(latest_pkt)


# ---------------- MAIN ----------------
if __name__ == "__main__":
    threading.Thread(target=packet_sniffer, daemon=True).start()
    socketio.run(app2, debug=True, use_reloader=False)