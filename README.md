# Multi-Client Pixel Tracker

A production-ready solution for tracking Facebook Pixel events across multiple websites.

## Folder Structure
- `backend/`: Contains the Node.js API server.
  - `src/server.js`: Main API server code.
  - `src/clients.json`: Client configuration data.
  - `package.json`: Node.js project configuration.
  - `.env`: Environment variables.
  - `logs/`: Log files (app.log, error.log).
- `frontend/`: Contains the client-side tracking script.
  - `tracking.js`: JavaScript for tracking events.
  - `index.html`: Example HTML implementation.

## Setup Instructions
### Backend
1. Navigate to `backend` folder:
   ```bash
   cd backend