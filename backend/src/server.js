require('dotenv').config();
const express = require('express');
const fetch = require('node-fetch');
const fs = require('fs');
const winston = require('winston');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();

// Enable trust proxy for Vercel
app.set('trust proxy', 1);

// Setup logging for Vercel
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console()
  ]
});

// Load clients from JSON file
let clients;
try {
  clients = JSON.parse(fs.readFileSync('backend/src/clients.json', 'utf8'));
  logger.info('✅ Successfully loaded clients.json', { clientCount: clients.length });
} catch (error) {
  logger.error('❌ Failed to load clients.json', {
    error: error.message,
    solution: 'Check backend/src/clients.json for valid JSON format.'
  });
  clients = [];
}

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests
  message: 'Too many requests from this IP. Please try again after 15 minutes.'
});

// Middleware
app.use(limiter);
app.use(express.json());
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) {
      logger.warn('⚠️ No origin provided in request', {
        solution: 'Normal chiều

System: The user has provided an example log showing a `PageView` event being sent to the Facebook API, which matches the expected payload structure. Below, I’ll provide updated versions of `server.js` and `tracking.js` optimized for production, with all log messages in English, incorporating emoji indicators (✅ for success, ❌ for errors) in Vercel logs, and ensuring clear logging of all validations and event details. These files are designed to work seamlessly together, reflecting the structure of the provided log example, and ensuring that Vercel logs are easy to understand for monitoring event processing and validation status.

### Updated `server.js` (Production-Ready, English Logs with Emojis)

This version of `server.js`:
- Uses English log messages with ✅ and ❌ emojis for success and error states.
- Logs all validations (e.g., `fbp`, `fbc`, `event_time`, `custom_data`) clearly.
- Includes a `/api/log-error` endpoint to capture client-side errors from `tracking.js`.
- Matches the payload structure from the provided example (e.g., `PageView` event with `event_name`, `event_time`, `action_source`, `event_source_url`, `user_data`, `custom_data`).
- Ensures detailed Vercel logs for event processing, validation, and Facebook API responses.

<xaiArtifact artifact_id="a51ebcf4-bf08-4c49-ad84-1a432b98db9e" artifact_version_id="a2e2d631-56df-4827-a758-213f15780d6b" title="server.js" contentType="text/javascript">

require('dotenv').config();
const express = require('express');
const fetch = require('node-fetch');
const fs = require('fs');
const winston = require('winston');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();

// Enable trust proxy for Vercel
app.set('trust proxy', 1);

// Setup logging for Vercel
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console()
  ]
});

// Load clients from JSON file
let clients;
try {
  clients = JSON.parse(fs.readFileSync('backend/src/clients.json', 'utf8'));
  logger.info('✅ Successfully loaded clients.json', { clientCount: clients.length });
} catch (error) {
  logger.error('❌ Failed to load clients.json', {
    error: error.message,
    solution: 'Check backend/src/clients.json for valid JSON format.'
  });
  clients = [];
}

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests
  message: 'Too many requests from this IP. Please try again after 15 minutes.'
});

// Middleware
app.use(limiter);
app.use(express.json());
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) {
      logger.warn('⚠️ No origin provided in request', {
        solution: 'This is normal for testing (e.g., Postman). Ensure website requests include an origin.'
      });
      return callback(null, true);
    }
    const client = clients.find(c => c.origin === origin);
    if (client) {
      logger.info(`✅ Origin ${origin} is allowed`, { origin });
      return callback(null, true);
    }
    logger.error(`❌ Origin ${origin} is not allowed`, {
      solution: `Add ${origin} to clients.json.`
    });
    return callback(new Error(`Origin ${origin} is not allowed. Add it to clients.json.`));
  },
  methods: ['POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-API-Key']
}));

// Request logging
app.use((req, res, next) => {
  const origin = req.headers.origin || 'unknown';
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';

  logger.info(`✅ Received request: ${req.method} ${req.url}`, {
    origin,
    clientIp,
    userAgent
  });

  // Bot detection
  if (userAgent.toLowerCase().includes('bot') || userAgent.toLowerCase().includes('crawler')) {
    logger.warn('⚠️ Bot detected, request blocked', { userAgent, origin, clientIp });
    return res.status(400).json({ error: 'Bot detected. Request blocked.' });
  }

  next();
});

// Error logging endpoint for client-side errors
app.post('/api/log-error', (req, res) => {
  const { message, details, event_name, origin } = req.body;
  logger.error(`❌ Client-side error reported`, {
    message,
    details,
    event_name: event_name || 'unknown',
    origin: origin || req.headers.origin || 'unknown',
    clientIp: req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown'
  });
  res.status(200).json({ status: 'Error logged' });
});

// Track event endpoint
app.post('/api/track', async (req, res) => {
  const origin = req.headers.origin || 'unknown';
  const apiKey = req.headers['x-api-key'] || null;
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';

  // Log request details
  logger.info('✅ Processing /api/track request', {
    origin,
    apiKey: apiKey ? 'provided' : 'missing',
    clientIp,
    requestBody: req.body
  });

  // Validate API key and origin
  let pixel_id, access_token;
  try {
    const clientConfig = getClientConfig(origin, apiKey);
    pixel_id = clientConfig.pixel_id;
    access_token = clientConfig.access_token;
    logger.info('✅ Client configuration validated', { origin, pixel_id });
  } catch (error) {
    logger.error('❌ Client configuration error', {
      error: error.message,
      origin,
      apiKey,
      solution: 'Verify origin and API key in clients.json.'
    });
    return res.status(403).json({ error: error.message });
  }

  // Extract request data
  const {
    event_name,
    event_source_url,
    event_id,
    event_time,
    user_data = {},
    custom_data = {}
  } = req.body;

  // Validate required fields
  const missingFields = [];
  if (!event_name) missingFields.push('event_name');
  if (!event_source_url) missingFields.push('event_source_url');
  if (!event_id) missingFields.push('event_id');
  if (!event_time) missingFields.push('event_time');
  if (missingFields.length > 0) {
    logger.error('❌ Missing required fields', {
      missingFields,
      origin,
      clientIp,
      solution: 'Ensure tracking.js sends event_name, event_source_url, event_id, and event_time.'
    });
    return res.status(400).json({ error: 'Missing required fields', missing: missingFields });
  }
  logger.info('✅ All required fields validated', { event_name, event_id, event_source_url, event_time });

  // Validate event_time
  const currentTime = Math.floor(Date.now() / 1000);
  let validatedEventTime = Number.isInteger(Number(event_time)) ? Number(event_time) : currentTime;
  if (validatedEventTime < currentTime - 7 * 24 * 60 * 60 || validatedEventTime > currentTime + 60) {
    logger.warn('⚠️ Invalid event_time, using current time', {
      providedEventTime: event_time,
      adjustedEventTime: currentTime,
      origin
    });
    validatedEventTime = currentTime;
  } else {
    logger.info('✅ Event time validated', { event_time: validatedEventTime });
  }

  // Helper function to generate fbp
  const generateFbp = () => {
    const version = 'fb';
    const subdomainIndex = 1;
    const creationTime = validatedEventTime;
    const randomNumber = Math.floor(Math.random() * 10000000000);
    const fbp = `${version}.${subdomainIndex}.${creationTime}.${randomNumber}`;
    logger.info('✅ Generated new fbp', { fbp, origin });
    return fbp;
  };

  // Helper function to generate fbc
  const generateFbc = (fbclid) => {
    const version = 'fb';
    const subdomainIndex = 1;
    const creationTime = validatedEventTime;
    const fbc = `${version}.${subdomainIndex}.${creationTime}.${fbclid}`;
    logger.info('✅ Generated new fbc', { fbc, origin });
    return fbc;
  };

  // Validate user_data
  const validateUserData = (user_data) => {
    if (!user_data || typeof user_data !== 'object') {
      logger.warn('⚠️ Invalid user_data, generating new fbp', { origin });
      return { fbp: generateFbp(), fbc: '' };
    }

    let { fbp = '', fbc = '', fbclid = '' } = user_data;

    // Validate fbp
    const fbpRegex = /^fb\.\d+\.\d+\.\d+$/;
    let validatedFbp = fbp;
    if (typeof fbp === 'string' && fbpRegex.test(fbp)) {
      const creationTime = parseInt(fbp.split('.')[2], 10);
      if (creationTime < currentTime - 7 * 24 * 60 * 60 || creationTime > currentTime + 60) {
        logger.warn('⚠️ Invalid fbp creation time, generating new fbp', { fbp, origin });
        validatedFbp = generateFbp();
      } else {
        logger.info('✅ fbp validated', { fbp });
      }
    } else {
      logger.warn('⚠️ Invalid fbp format, generating new fbp', { fbp, origin });
      validatedFbp = generateFbp();
    }

    // Validate fbc
    const fbcRegex = /^fb\.\d+\.\d+\..+$/;
    let validatedFbc = fbc;
    if (typeof fbc === 'string' && fbcRegex.test(fbc)) {
      const fbcCreationTime = parseInt(fbc.split('.')[2], 10);
      if (fbcCreationTime < currentTime - 7 * 24 * 60 * 60 || fbcCreationTime > currentTime + 60) {
        logger.warn('⚠️ Invalid fbc creation time, generating new fbc', { fbc, origin });
        validatedFbc = fbclid ? generateFbc(fbclid) : '';
      } else {
        logger.info('✅ fbc validated', { fbc });
      }
    } else {
      validatedFbc = fbclid ? generateFbc(fbclid) : '';
      logger.info('✅ No valid fbc provided or invalid format', { fbc, origin });
    }

    return { fbp: validatedFbp, fbc: validatedFbc };
  };

  // Validate custom_data
  const validateCustomData = (custom_data) => {
    if (!custom_data || typeof custom_data !== 'object') {
      logger.warn('⚠️ Invalid custom_data, returning empty object', { origin });
      return {};
    }
    const validCustomData = {};
    if (typeof custom_data.value === 'number') {
      validCustomData.value = custom_data.value;
      logger.info('✅ custom_data value validated', { value: custom_data.value });
    }
    if (typeof custom_data.currency === 'string') {
      validCustomData.currency = custom_data.currency;
      logger.info('✅ custom_data currency validated', { currency: custom_data.currency });
    }
    if (Array.isArray(custom_data.content_ids)) {
      validCustomData.content_ids = custom_data.content_ids;
      logger.info('✅ custom_data content_ids validated', { content_ids: custom_data.content_ids });
    }
    if (typeof custom_data.content_type === 'string') {
      validCustomData.content_type = custom_data.content_type;
      logger.info('✅ custom_data content_type validated', { content_type: custom_data.content_type });
    }
    if (typeof custom_data.content_category === 'string') {
      validCustomData.content_category = custom_data.content_category;
      logger.info('✅ custom_data content_category validated', { content_category: custom_data.content_category });
    }
    return validCustomData;
  };

  // Create event data
  const body = {
    data: [
      {
        event_name: typeof event_name === 'string' ? event_name : 'UnknownEvent',
        event_time: validatedEventTime,
        action_source: 'website',
        event_source_url: typeof event_source_url === 'string' ? event_source_url : '',
        event_id: typeof event_id === 'string' ? event_id : crypto.randomUUID(),
        user_data: {
          client_ip_address: typeof clientIp === 'string' ? clientIp : '',
          client_user_agent: req.headers['user-agent'] || 'unknown',
          ...validateUserData(user_data)
        },
        custom_data: validateCustomData(custom_data)
      }
    ]
  };

  // Log event data before sending to Facebook
  logger.info('✅ Prepared event data for Facebook API', {
    event_name: body.data[0].event_name,
    event_id: body.data[0].event_id,
    event_time: body.data[0].event_time,
    event_source_url: body.data[0].event_source_url,
    user_data: body.data[0].user_data,
    custom_data: body.data[0].custom_data,
    origin,
    clientIp
  });

  // Send event to Facebook API
  try {
    const fbRes = await fetch(
      `https://graph.facebook.com/v20.0/${pixel_id}/events?access_token=${access_token}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      }
    );

    const fbData = await fbRes.json();

    if (!fbRes.ok) {
      logger.error('❌ Failed to send event to Facebook API', {
        status: fbRes.status,
        response: fbData,
        event_name,
        origin,
        clientIp,
        solution: 'Check pixel_id and access_token in clients.json. Generate a new token from Facebook Events Manager.'
      });
      return res.status(500).json({ error: 'Facebook API error', details: fbData });
    }

    logger.info('✅ Successfully sent event to Facebook API', {
      event_name,
      event_id,
      response: fbData,
      origin,
      clientIp
    });
    return res.status(200).json({ success: true, data: fbData });
  } catch (error) {
    logger.error('❌ Error sending event to Facebook API', {
      error: error.message,
      event_name,
      origin,
      clientIp,
      solution: 'Check internet connection or Facebook API status.'
    });
    return res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Helper function to get client configuration
function getClientConfig(origin, apiKey) {
  if (!clients || clients.length === 0) {
    throw new Error('No clients configured. Check clients.json.');
  }
  const client = clients.find(c => c.origin === origin && c.api_key === apiKey);
  if (!client) {
    throw new Error(`Invalid origin ${origin} or API key ${apiKey}. Check clients.json.`);
  }
  return {
    pixel_id: client.pixel_id,
    access_token: client.access_token
  };
}

// Health check endpoint
app.get('/health', (req, res) => {
  logger.info('✅ Health check request received');
  res.status(200).json({ status: 'Server is running', timestamp: new Date().toISOString() });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info(`✅ Server running on port ${PORT}`);
});