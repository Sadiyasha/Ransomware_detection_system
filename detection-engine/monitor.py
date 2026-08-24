import os
import time
import csv
import joblib
import psutil
import numpy as np
import pandas as pd
import requests

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# ==========================================
# CONFIGURATION
# ==========================================

MODEL_PATH = "ransomware_model.pkl"
DATASET_PATH = "dataset.csv"

TIME_WINDOW = 15

API_URL = "http://127.0.0.1:8000/detection/update"

SUSPICIOUS_EXTENSIONS = [
    ".locked",
    ".encrypted",
    ".crypt",
    ".crypto",
    ".enc",
]


# ==========================================
# LOAD AI MODEL
# ==========================================

try:
    model = joblib.load(MODEL_PATH)

    print("AI model loaded successfully.")

except FileNotFoundError:

    print(f"ERROR: Model file '{MODEL_PATH}' not found.")
    print("Run: python train_model.py")

    raise SystemExit


# ==========================================
# ENTROPY CALCULATION
# ==========================================

def calculate_entropy(file_path):

    try:

        with open(file_path, "rb") as file:
            data = file.read()

        if len(data) == 0:
            return 0.0

        byte_counts = np.bincount(
            np.frombuffer(data, dtype=np.uint8),
            minlength=256
        )

        probabilities = (
            byte_counts[byte_counts > 0] / len(data)
        )

        entropy = -np.sum(
            probabilities * np.log2(probabilities)
        )

        return round(float(entropy), 4)

    except Exception as error:

        print("Entropy error:", error)

        return 0.0


# ==========================================
# CPU USAGE
# ==========================================

def get_cpu_usage():

    return round(
        psutil.cpu_percent(interval=None),
        2
    )


# ==========================================
# MEMORY USAGE
# ==========================================

def get_memory_usage():

    return round(
        psutil.virtual_memory().percent,
        2
    )


# ==========================================
# DATASET INITIALIZATION
# ==========================================

def initialize_dataset():

    if not os.path.exists(DATASET_PATH):

        with open(
            DATASET_PATH,
            "w",
            newline=""
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "Entropy",
                "Rename_Count",
                "Modification_Count",
                "CPU_Usage",
                "Memory_Usage",
                "File_Size",
                "Suspicious_Extension",
                "Time_Window",
                "Timestamp",
                "Label"
            ])

        print("Dataset created successfully.")


# ==========================================
# SAVE MONITORING DATA
# ==========================================

def save_data(features, label):

    try:

        with open(
            DATASET_PATH,
            "a",
            newline=""
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                features["Entropy"],
                features["Rename_Count"],
                features["Modification_Count"],
                features["CPU_Usage"],
                features["Memory_Usage"],
                features["File_Size"],
                features["Suspicious_Extension"],
                features["Time_Window"],
                time.strftime("%Y-%m-%d %H:%M:%S"),
                label
            ])

        print("Dataset row saved.")

    except Exception as error:

        print("Dataset save error:", error)


# ==========================================
# AI PREDICTION
# ==========================================

def predict_activity(features):

    feature_order = [
        "Entropy",
        "Rename_Count",
        "Modification_Count",
        "CPU_Usage",
        "Memory_Usage",
        "File_Size",
        "Suspicious_Extension",
        "Time_Window"
    ]

    input_data = pd.DataFrame(
        [
            [
                features[column]
                for column in feature_order
            ]
        ],
        columns=feature_order
    )

    prediction = model.predict(input_data)[0]

    probabilities = model.predict_proba(input_data)[0]

    probability_results = {}

    for class_name, probability in zip(
        model.classes_,
        probabilities
    ):

        probability_results[class_name] = round(
            float(probability),
            4
        )

    return prediction, probability_results


# ==========================================
# SEND DETECTION TO FASTAPI
# ==========================================

def send_detection_to_api(
    prediction,
    probabilities,
    suspicious_file=None
):

    payload = {
        "prediction": prediction,
        "probabilities": probabilities,
        "suspicious_file": suspicious_file
    }

    try:

        response = requests.post(
            API_URL,
            json=payload,
            timeout=5
        )

        if response.status_code == 200:

            print(
                "Detection sent to API successfully."
            )

        else:

            print(
                "API update failed:",
                response.status_code
            )

            print(
                "Response:",
                response.text
            )

    except requests.RequestException as error:

        print(
            "Could not connect to detection API:",
            error
        )


# ==========================================
# FILE MONITOR HANDLER
# ==========================================

class MonitorHandler(FileSystemEventHandler):

    def __init__(self):

        super().__init__()

        self.rename_count = 0

        self.modification_count = 0

        self.start_time = time.time()


    # ======================================
    # IGNORE SYSTEM FILES
    # ======================================

    def ignore_file(self, path):

        ignored_files = [
            "desktop.ini",
            "thumbs.db"
        ]

        return any(
            path.lower().endswith(
                file.lower()
            )
            for file in ignored_files
        )


    # ======================================
    # RESET MONITORING WINDOW
    # ======================================

    def reset_window_if_needed(self):

        current_time = time.time()

        elapsed_time = (
            current_time -
            self.start_time
        )

        if elapsed_time > TIME_WINDOW:

            self.rename_count = 0

            self.modification_count = 0

            self.start_time = current_time

            print(
                "\nMonitoring window reset.\n"
            )


    # ======================================
    # CHECK SUSPICIOUS EXTENSION
    # ======================================

    def is_suspicious_extension(
        self,
        file_path
    ):

        file_path = file_path.lower()

        return int(
            any(
                file_path.endswith(extension)
                for extension in SUSPICIOUS_EXTENSIONS
            )
        )


    # ======================================
    # PROCESS FILE ACTIVITY
    # ======================================

    def process_activity(self, file_path):

        self.reset_window_if_needed()

        # Wait briefly for the file operation
        # to finish.
        time.sleep(0.1)

        # ----------------------------------
        # Calculate features
        # ----------------------------------

        entropy = calculate_entropy(
            file_path
        )

        try:

            file_size = os.path.getsize(
                file_path
            )

        except OSError:

            file_size = 0

        cpu_usage = get_cpu_usage()

        memory_usage = get_memory_usage()

        suspicious_extension = (
            self.is_suspicious_extension(
                file_path
            )
        )


        # ----------------------------------
        # Feature dictionary
        # ----------------------------------

        features = {

            "Entropy": entropy,

            "Rename_Count":
                self.rename_count,

            "Modification_Count":
                self.modification_count,

            "CPU_Usage":
                cpu_usage,

            "Memory_Usage":
                memory_usage,

            "File_Size":
                file_size,

            "Suspicious_Extension":
                suspicious_extension,

            "Time_Window":
                TIME_WINDOW
        }


        # ----------------------------------
        # Display features
        # ----------------------------------

        print(
            "\n-------------------------------"
        )

        print(
            "FEATURES DETECTED"
        )

        print(
            "-------------------------------"
        )

        print(
            "File:",
            file_path
        )

        for key, value in features.items():

            print(
                f"{key}: {value}"
            )


        # ----------------------------------
        # AI prediction
        # ----------------------------------

        prediction, probabilities = (
            predict_activity(features)
        )


        print(
            "\nAI PREDICTION"
        )

        print(
            "-------------------------------"
        )

        print(
            "Prediction:",
            prediction
        )

        print(
            "Probabilities:",
            probabilities
        )


        # ----------------------------------
        # Save dataset
        # ----------------------------------

        save_data(
            features,
            prediction
        )


        # ----------------------------------
        # Update FastAPI
        # ----------------------------------

        send_detection_to_api(
            prediction,
            probabilities,
            file_path
        )


        # ----------------------------------
        # Alert
        # ----------------------------------

        if prediction == "Ransomware":

            print(
                "\n🚨 RANSOMWARE ALERT!"
            )

            print(
                "Suspicious activity detected:"
            )

            print(
                file_path
            )

            print(
                "-------------------------------\n"
            )

        else:

            print(
                "\n✅ Activity appears normal."
            )

            print(
                "-------------------------------\n"
            )


    # ======================================
    # FILE MODIFIED
    # ======================================

    def on_modified(self, event):

        if event.is_directory:
            return

        if self.ignore_file(
            event.src_path
        ):
            return

        self.reset_window_if_needed()

        self.modification_count += 1

        print(
            "Modified:",
            event.src_path
        )

        self.process_activity(
            event.src_path
        )


    # ======================================
    # FILE RENAMED / MOVED
    # ======================================

    def on_moved(self, event):

        if event.is_directory:
            return

        if self.ignore_file(
            event.src_path
        ):
            return

        self.reset_window_if_needed()

        self.rename_count += 1

        print(
            "Renamed:",
            event.src_path,
            "->",
            event.dest_path
        )

        # Use destination because this is
        # the file after the rename.
        self.process_activity(
            event.dest_path
        )


    # ======================================
    # FILE CREATED
    # ======================================

    def on_created(self, event):

        if event.is_directory:
            return

        if self.ignore_file(
            event.src_path
        ):
            return

        print(
            "Created:",
            event.src_path
        )

        # Don't immediately classify a newly
        # created file if it hasn't finished
        # writing yet.
        time.sleep(0.1)

        self.process_activity(
            event.src_path
        )


# ==========================================
# MAIN PROGRAM
# ==========================================

if __name__ == "__main__":

    # --------------------------------------
    # Initialize dataset
    # --------------------------------------

    initialize_dataset()


    # --------------------------------------
    # Monitoring folder
    # --------------------------------------

    path = "demo_folder"


    # Create folder if missing
    if not os.path.exists(path):

        os.makedirs(path)

        print(
            f"Created folder: {path}"
        )


    # --------------------------------------
    # Create event handler
    # --------------------------------------

    event_handler = MonitorHandler()


    # --------------------------------------
    # Create observer
    # --------------------------------------

    observer = Observer()


    observer.schedule(
        event_handler,
        path=path,
        recursive=True
    )


    # --------------------------------------
    # Start monitoring
    # --------------------------------------

    print(
        "\n================================="
    )

    print(
        "AI RANSOMWARE MONITOR STARTED"
    )

    print(
        "Monitoring folder:",
        os.path.abspath(path)
    )

    print(
        "API:",
        API_URL
    )

    print(
        "Press CTRL + C to stop."
    )

    print(
        "=================================\n"
    )


    observer.start()


    # --------------------------------------
    # Keep program running
    # --------------------------------------

    try:

        while True:

            time.sleep(1)


    except KeyboardInterrupt:

        print(
            "\nStopping monitor..."
        )

        observer.stop()


    # --------------------------------------
    # Wait for observer
    # --------------------------------------

    observer.join()


    print(
        "Monitor stopped."
    )