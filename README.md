# Cyber Threat Detector

A real-time cyber threat detection system that analyzes URLs for potential threats and provides traffic statistics.

## Features

- Real-time URL threat analysis using VirusTotal API
- Traffic statistics visualization
- Modern, responsive UI built with React and Material-UI
- RESTful API backend built with Flask

## Prerequisites

- Python 3.8+
- Node.js 14+
- npm or yarn
- VirusTotal API key

## Setup

### Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Create a `.env` file in the backend directory and add your VirusTotal API key:
   ```
   VIRUSTOTAL_API_KEY=your_api_key_here
   ```

### Frontend Setup

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

## Running the Application

1. Start the backend server (from the backend directory):
   ```bash
   python app.py
   ```

2. Start the frontend development server (from the frontend directory):
   ```bash
   npm start
   ```

3. Open your browser and navigate to `http://localhost:3000`

## Usage

1. Enter a URL in the input field
2. Click "Analyze" to start the threat analysis
3. View the results, including:
   - Threat analysis chart
   - Traffic statistics
   - Detailed threat information

## API Endpoints

- `POST /api/analyze`
  - Request body: `{ "url": "https://example.com" }`
  - Returns threat analysis and traffic statistics

## Technologies Used

- Frontend:
  - React
  - TypeScript
  - Material-UI
  - Chart.js
  - Axios

- Backend:
  - Flask
  - Flask-CORS
  - Requests
  - Python-dotenv

## Security Considerations

- The application requires a VirusTotal API key for threat analysis
- API keys should be stored securely in environment variables
- CORS is enabled for development purposes
- Input validation is implemented on both frontend and backend

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request 