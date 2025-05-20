# Cyber Threat Detection System

A comprehensive cyber threat detection system with real-time monitoring, threat intelligence, and modern UI.

## Features

- Real-time URL analysis
- Multiple threat intelligence sources:
  - VirusTotal
  - URLhaus (Abuse.ch)
  - PhishTank
  - Google Safe Browsing
  - IPQualityScore
- SSL/TLS security checks
- DNS resolution verification
- Suspicious pattern detection
- Domain age analysis
- Security headers inspection
- Port scanning
- Traffic analysis
- Real-time monitoring
- MongoDB integration for scan history
- Modern React frontend with Material-UI
- WebSocket support for real-time updates

## Prerequisites

- Docker and Docker Compose
- Node.js 16+ (for local development)
- Python 3.9+ (for local development)
- MongoDB (handled by Docker)

## Environment Variables

Create a `.env` file in the root directory with the following variables:

```env
# Backend Configuration
FLASK_APP=app.py
FLASK_ENV=production
MONGODB_URI=mongodb://mongodb:27017/

# API Keys
GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_api_key
IPQUALITYSCORE_API_KEY=your_ipqualityscore_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key

# Frontend Configuration
REACT_APP_API_URL=http://localhost:5001
```

## Local Development Setup

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd cyber-threat-detection
   ```

2. Set up the backend:
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. Set up the frontend:
   ```bash
   cd frontend
   npm install
   ```

4. Start the development servers:
   - Backend: `python app.py`
   - Frontend: `npm start`

## Docker Deployment

1. Build and start the containers:
   ```bash
   docker-compose up --build
   ```

2. Access the application:
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:5001
   - MongoDB: mongodb://localhost:27017

## API Endpoints

- `POST /api/analyze`: Analyze a URL
- `GET /api/history`: Get scan history
- WebSocket: Real-time monitoring updates

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License 