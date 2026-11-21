# Ransomware Detection System

A system that monitors a folder for ransomware-like behavior and shows alerts in a web dashboard.

> **Note:** This project is for learning and demonstration. Only use the safe demo files in `detection-engine/demo_folder`. Never run real malware on your machine.

## Project Structure

```
Ransomware_detection_system/
├── backend/            # FastAPI server (API)
├── frontend/           # Web dashboard (Vite)
├── detection-engine/   # Detection logic, models, demo folder
└── README.md
```

## Requirements

- Python 3.11
- Node.js (LTS version) and npm
- Git

## Setup

### 1. Clone the repository

```powershell
git clone https://github.com/Sadiyasha/Ransomware_detection_system.git
cd Ransomware_detection_system
```

### 2. Create the Python environment

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install fastapi uvicorn
```

Install any other packages the code imports (for example `watchdog`, `psutil`, `scikit-learn`).

### 3. Install frontend dependencies

```powershell
cd frontend
npm install
cd ..
```

## Running the Project

Open **three separate terminals** in the project root and start them in this order.

**Terminal 1: Backend**

```powershell
.\.venv\Scripts\Activate.ps1
cd backend
python -m uvicorn main:app --reload
```

Runs at http://127.0.0.1:8000

**Terminal 2: Frontend**

```powershell
cd frontend
npm run dev
```

Open the URL it prints (usually http://localhost:5173).

**Terminal 3: Monitor**

```powershell
.\.venv\Scripts\Activate.ps1
cd detection-engine
python monitor.py
```

## Troubleshooting

- **`npm` is not recognized:** install Node.js, then fully restart VS Code.
- **`No module named uvicorn`:** activate the virtual environment and run `pip install uvicorn fastapi`.
- **PowerShell blocks scripts:** run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.
