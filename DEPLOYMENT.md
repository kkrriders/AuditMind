# AuditMind Deployment Guide

## 🚀 Render Deployment (Recommended)

### Prerequisites
1. GitHub account with this repository
2. Render account (free tier available)
3. OpenRouter API key (get from [openrouter.ai](https://openrouter.ai))

### Steps

1. **Push to GitHub**
   ```bash
   git init
   git add .
   git commit -m "Initial AuditMind deployment"
   git remote add origin https://github.com/kkrriders/AuditMind
   git push -u origin main
   ```

2. **Deploy to Render**
   - Go to [render.com](https://render.com)
   - Connect your GitHub account
   - Create new "Web Service"
   - Select your AuditMind repository
   - Use these settings:
     - **Build Command**: `pip install -r requirements.txt`
     - **Start Command**: `./start.sh`
     - **Environment Variables**:
       - `OPENROUTER_API_KEY`: Your OpenRouter API key
       - `PORT`: 8000 (optional, defaults to 8000)

3. **Test Deployment**
   - Your API will be available at: `https://your-app-name.onrender.com`
   - Test endpoints:
     - `GET /` - API information
     - `GET /health` - Check if service is running
     - `POST /analyze` - Analyze documents

## 🖥️ Local Development

### Windows Setup
```cmd
# Install Python dependencies
pip install -r requirements.txt

# Set environment variable
set OPENROUTER_API_KEY=your_openrouter_api_key_here

# Run the web server
python web_api.py
```

### Linux/Mac Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variable
export OPENROUTER_API_KEY=your_openrouter_api_key_here

# Run the web server
python web_api.py
```

### Using .env File (Recommended)
Create a `.env` file in the project root:
```env
OPENROUTER_API_KEY=your_openrouter_api_key_here
PORT=8000
CORS_ORIGINS=*
LOG_LEVEL=info
```

Then run:
```bash
python web_api.py
```

## 📡 API Endpoints

### Base URL
- Local: `http://localhost:8000`
- Deployed: `https://your-app-name.onrender.com`

### Available Endpoints

#### Health Check
```http
GET /health
```
Response:
```json
{
  "status": "healthy",
  "timestamp": "2025-09-03T10:00:00",
  "llm_enabled": true,
  "model": "meta-llama/llama-3.1-8b-instruct:free"
}
```

#### Analyze Document
```http
POST /analyze
Content-Type: application/json

{
  "document": "your code/text here",
  "document_type": "code",
  "enable_llm": true,
  "model_name": "meta-llama/llama-3.1-8b-instruct:free"
}
```

#### Quick Analysis (No LLM)
```http
POST /analyze/quick
Content-Type: application/json

{
  "document": "your code/text here",
  "document_type": "code"
}
```

#### List Models
```http
GET /models
```

#### Examples
```http
GET /example/security
GET /example/privacy
```

## 🔧 Configuration

### Environment Variables
```bash
OPENROUTER_API_KEY=your_api_key_here
PORT=8000                    # Server port
CORS_ORIGINS=*              # CORS origins (use specific domains in production)
LOG_LEVEL=info              # Logging level
```

### Available Models (Free Tier)
- `meta-llama/llama-3.1-8b-instruct:free`
- `microsoft/wizardlm-2-8x22b:free`
- `google/gemma-7b-it:free`
- `mistralai/mistral-7b-instruct:free`
- `huggingface/zephyr-7b-beta:free`

## 🧪 Testing

### Test OpenRouter Integration
```bash
python test_openrouter.py
```

### Test Web API
```bash
# Start server
python web_api.py

# In another terminal, test endpoints
curl http://localhost:8000/health
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"document": "api_key = \"sk-test123\"", "document_type": "code"}'
```

## 🔐 Security Notes

1. **API Key**: The provided OpenRouter key is configured in the code
2. **CORS**: Configure `CORS_ORIGINS` appropriately for production
3. **Rate Limiting**: Consider adding rate limiting for production use
4. **HTTPS**: Render provides HTTPS automatically

## 🏗️ Frontend Integration

### JavaScript Example
```javascript
const analyzeDocument = async (document) => {
  const response = await fetch('https://your-app.onrender.com/analyze', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      document: document,
      document_type: 'code',
      enable_llm: true
    })
  });
  
  return await response.json();
};
```

### React Example
```jsx
import { useState } from 'react';

function AuditForm() {
  const [document, setDocument] = useState('');
  const [result, setResult] = useState(null);
  
  const handleAnalyze = async () => {
    const response = await fetch('/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ document })
    });
    
    const data = await response.json();
    setResult(data);
  };
  
  return (
    <div>
      <textarea 
        value={document} 
        onChange={(e) => setDocument(e.target.value)}
        placeholder="Paste your code or document here..."
      />
      <button onClick={handleAnalyze}>Analyze</button>
      {result && <pre>{JSON.stringify(result, null, 2)}</pre>}
    </div>
  );
}
```

## 📊 Monitoring

### Health Monitoring
```bash
# Check if service is healthy
curl https://your-app.onrender.com/health

# Get service statistics
curl https://your-app.onrender.com/stats
```

### Logs
- Render provides built-in logging
- Check the Render dashboard for application logs
- Errors are automatically logged with timestamps

## 🚨 Troubleshooting

### Common Issues
1. **API Key Invalid**: Verify the OpenRouter API key
2. **Model Not Available**: Check `/models` endpoint for available models
3. **CORS Errors**: Configure CORS origins properly
4. **Timeout**: Some models may be slower; consider using `/analyze/quick`

### Debug Mode
Set `LOG_LEVEL=debug` to see detailed request/response logs.