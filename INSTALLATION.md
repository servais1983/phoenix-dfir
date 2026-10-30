# Installation Guide - Phoenix DFIR Graphical Interface

## 🎯 Quick Install (Recommended)

### Prerequisites
- **Node.js 18+** and **pnpm** (or npm)
- **Python 3.9+** 
- **Git**

### Installation Steps

#### 1. Clone the Repository
```bash
git clone https://github.com/servais1983/phoenix-dfir.git
cd phoenix-dfir/phoenix-dfir-gui
```

#### 2. Frontend Setup
```bash
# Install dependencies
pnpm install

# Start the development server
pnpm run dev --host
```
✅ **Frontend available at:** `http://localhost:5173`

#### 3. Backend Setup (separate terminal)
```bash
# Go to the backend folder
cd backend

# Create a virtual environment (recommended)
python -m venv venv

# Activate the virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
# Optional (EVTX parsing, AI providers); may fail without blocking anything:
pip install -r requirements-optional.txt

# Start the Flask server
python app.py
```
✅ **Backend available at:** `http://localhost:5000`

#### 4. Verification
- Open `http://localhost:5173` in your browser
- The Phoenix DFIR interface should load
- Check the API: `http://localhost:5000/api/health`

## 🔧 Advanced Configuration

### AI Analysis with a local LLM

AI analysis runs on a **local LLM** by default: nothing leaves the machine or
the investigation network.

1. **Start a local server**
   - Ollama (default provider): install it from <https://ollama.com>, then
     `ollama pull qwen2.5-coder:14b`
   - or llama.cpp: start `llama-server` and set `PHOENIX_LLM_PROVIDER=llamacpp`
     (`PHOENIX_LLAMACPP_URL`, default `http://127.0.0.1:8080/v1`)
2. **Check it**: `phoenix doctor` shows the provider and whether it answers.
3. **Without any LLM**, `phoenix triage <case>` and the native parsers keep
   working, and `phoenix investigate` falls back to the triage.

Cloud providers (OpenAI, GitHub Models) are refused unless you set
`PHOENIX_ALLOW_CLOUD_LLM=1`; the consent is then recorded in the custody
ledger:

```bash
export PHOENIX_ALLOW_CLOUD_LLM=1
export PHOENIX_LLM_PROVIDER=github
export GITHUB_TOKEN="github_pat_..."        # fine-grained PAT, Models: read
```

### VirusTotal Key (Optional)

For automatic IoC enrichment:

```bash
export API_KEY_VT="your_virustotal_key"
```

**Getting the key (free)**
1. Create an account on [VirusTotal](https://virustotal.com)
2. Go to your profile → API Key
3. Copy the key into the `API_KEY_VT` environment variable

## 🐳 Docker Installation (Alternative)

> **Windows + Docker Desktop**: full guide (WSL 2, read-only evidence vault,
> Windows Defender exclusion, Volatility 3 / Hayabusa, local Ollama LLM) in
> [`docs/WINDOWS_DOCKER.md`](docs/WINDOWS_DOCKER.md).

### Frontend Dockerfile
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host"]
```

### Backend Dockerfile
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install -r requirements.txt
COPY backend/ .
EXPOSE 5000
CMD ["python", "app.py"]
```

### Docker Compose
```yaml
version: '3.8'
services:
  frontend:
    build: .
    ports:
      - "5173:5173"
    depends_on:
      - backend
  
  backend:
    build: 
      context: .
      dockerfile: Dockerfile.backend
    ports:
      - "5000:5000"
    volumes:
      - ./backend/uploads:/app/uploads
      - ./backend/sessions:/app/sessions
      - ./backend/reports:/app/reports
```

## 🔧 Troubleshooting

### Common Issues

#### 1. "Module not found" error
```bash
# Reinstall dependencies
cd phoenix-dfir-gui
rm -rf node_modules package-lock.json
pnpm install
```

#### 2. API connection error
- Make sure the backend is running on port 5000
- Test the API: `curl http://localhost:5000/api/health`
- Check the Flask server logs

#### 3. CORS issues
- The backend is configured to accept `localhost:5173`
- If you change the port, update `backend/app.py`

#### 4. Python "Module not found" error
```bash
# Check the virtual environment
which python
pip list

# Reinstall dependencies
pip install -r requirements.txt
```

### Logs and Debugging

#### Frontend (React)
- Open the browser developer tools (F12)
- Check the console for JavaScript errors
- Use the Network tab for API requests

#### Backend (Flask)
- Logs are printed in the terminal
- Debug mode is enabled by default in development
- Log files in `backend/logs/` (if configured)

## 🚀 Production Deployment

### Frontend (Production Build)
```bash
# Build the application
pnpm run build

# Serve with nginx or another web server
# nginx example:
server {
    listen 80;
    server_name your-domain.com;
    root /path/to/dist;
    
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    location /api {
        proxy_pass http://localhost:5000;
    }
}
```

### Backend (Production)
```bash
# Install Gunicorn
pip install gunicorn

# Start with Gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app

# Or with systemd (Linux)
sudo systemctl enable phoenix-dfir-backend
sudo systemctl start phoenix-dfir-backend
```

### Environment Variables
```bash
# Create a .env file
FLASK_ENV=production
SECRET_KEY=your-very-long-secret-key
PHOENIX_LLM_PROVIDER=ollama               # local LLM (default), or llamacpp
# Cloud LLM only on explicit opt-in (consent recorded in the custody ledger):
# PHOENIX_ALLOW_CLOUD_LLM=1
# GITHUB_TOKEN=your-github-models-token
API_KEY_VT=your-virustotal-key            # IoC enrichment (optional)
```

## 📋 Installation Checklist

- [ ] Node.js 18+ installed
- [ ] Python 3.9+ installed
- [ ] Repository cloned
- [ ] Frontend dependencies installed (`pnpm install`)
- [ ] Backend dependencies installed (`pip install -r requirements.txt`)
- [ ] Frontend started (`pnpm run dev --host`)
- [ ] Backend started (`python app.py`)
- [ ] Interface available at `http://localhost:5173`
- [ ] API available at `http://localhost:5000/api/health`
- [ ] Local LLM reachable (`phoenix doctor`, optional: `phoenix triage` works without it)
- [ ] VirusTotal key configured (optional)

## 🆘 Support

If you run into problems:

1. **Check the prerequisites** and versions
2. **Review the logs** for the frontend and backend
3. **Test the API** with curl or an API client
4. **Open an issue** on GitHub with:
   - Your operating system
   - Node.js and Python versions
   - Full error messages
   - Steps to reproduce the problem

---

**🔥 Phoenix DFIR Graphical Interface: installation complete!** 🚀
