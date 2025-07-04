require('dotenv').config();
const express = require('express');
const fetch = require('node-fetch');
const fs = require('fs');
const winston = require('winston');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();

// Setup logging
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/app.log' }),
    new winston.transports.Console()
  ]
});

// Load clients from JSON file
const clients = JSON.parse(fs.readFileSync('src/clients.json', 'utf8'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});

// Middleware
app.use(limiter);
app.use(express.json());
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || clients.some(c => c.origin === origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-API-Key']
}));

// Helper function to get client configuration
function getClientConfig(origin, apiKey) {
  const client = clients.find(c => c.origin === origin && c.api_key === apiKey);
  if (!client) {
    throw new Error(`Invalid client: Origin ${origin} or API Key not found`);
  }
  return {
    pixel_id: client.pixel_id,
    access_token: client.access_token
  };
}

// Request logging and validation middleware
app.use((req, res, next) => {
  const origin = req.headers.origin || 'unknown';
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  const timestamp = new Date().toISOString();
  const userAgent = req.headers['user-agent'] || 'unknown';

  logger.info(`Request received: ${req.method} ${req.url} from ${origin} (IP: ${clientIp}, UA: ${userAgent}) at ${timestamp}`);

  // Bot detection
  if (userAgent.toLowerCase().includes('bot') || userAgent.toLowerCase().includes('crawler')) {
    logger.warn(`Bot Detected: ${userAgent} from ${origin} (IP: ${clientIp}) at ${timestamp}`);
    return res.status(400).json({ error: 'Bot detected' });
  }

  next();
});

app.post('/api/track', async (req, res) => {
  const origin = req.headers.origin || 'unknown';
  const apiKey = req.headers['x-api-key'] || null;
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  const timestamp = new Date().toISOString();

  // Validate API Key and Origin
  let pixel_id, access_token;
  try {
    const clientConfig = getClientConfig(origin, apiKey);
    pixel_id = clientConfig.pixel_id;
    access_token = clientConfig.access_token;
  } catch (error) {
    logger.error(`Client Config Error: ${error.message} from ${origin} (IP: ${clientIp}) at ${timestamp}`);
    return res.status(403).json({ error: error.message });
  }

  // Input destructuring
  const {
    event_name,
    event_source_url,
    event_id,
    event_time,
    user_data = {},
    custom_data = {}
  } = req.body;

  // Required field validation
  const missingFields = [];
  if (!event_name) missingFields.push('event_name');
  if (!event_source_url) missingFields.push('event_source_url');
  if (!event_id) missingFields.push('event_id');
  if (!event_time) missingFields.push('event_time');
  if (missingFields.length > 0) {
    logger.error(`Missing Required Fields: ${missingFields.join(', ')} from ${origin} (IP: ${clientIp}) at ${timestamp}`);
    return res.status(400).json({ error: 'Missing required fields', missing: missingFields });
  }

  // Event Time Validation
  const currentTime = Math.floor(Date.now() / 1000);
  let validatedEventTime = Number.isInteger(Number(event_time)) ? Number(event_time) : currentTime;
  if (validatedEventTime < currentTime - 7 * 24 * 60 * 60 || validatedEventTime > currentTime + 60) {
    logger.warn(`Invalid event_time: ${validatedEventTime}. Adjusting to current time: ${currentTime} from ${origin} (IP: ${clientIp}) at ${timestamp}`);
    validatedEventTime = currentTime;
  }

  // Helper function to generate fbp
  const generateFbp = () => {
    const version = 'fb';
    const subdomainIndex = 1;
    const creationTime = validatedEventTime;
    const randomNumber = Math.floor(Math.random() * 10000000000);
    const fbp = `${version}.${subdomainIndex}.${creationTime}.${randomNumber}`;
    logger.info(`Generated fbp: ${fbp} at ${timestamp}`);
    return fbp;
  };

  // Helper function to generate fbc
  const generateFbc = (fbclid) => {
    const version = 'fb';
    const subdomainIndex = 1;
    const creationTime = validatedEventTime;
    const fbc = `${version}.${subdomainIndex}.${creationTime}.${fbclid}`;
    logger.info(`Generated fbc: ${fbc} at ${timestamp}`);
    return fbc;
  };

  // user_data Validation function
  const validateUserData = (user_data) => {
    if (!user_data || typeof user_data !== 'object') {
      logger.warn(`Invalid user_data: not an object from ${origin} (IP: ${clientIp}) at ${timestamp}`);
      return { fbp: generateFbp(), fbc: '' };
    }

    let { fbp = '', fbc = '', fbclid = '' } = user_data;

    // fbp format validation
    const fbpRegex = /^fb\.\d+\.\d+\.\d+$/;
    let validatedFbp = fbp;
    if (typeof fbp === 'string') {
      const fbpParts = fbp.split('.');
      if (fbpParts.length > 4) {
        logger.warn(`Malformed fbp with too many components: ${fbp}. Attempting to fix from ${origin} (IP: ${clientIp}) at ${timestamp}`);
        fbp = `fb.${fbpParts[1]}.${fbpParts[2]}.${fbpParts[3]}`;
      }
      if (fbpRegex.test(fbp)) {
        const creationTime = parseInt(fbp.split('.')[2], 10);
        if (creationTime < currentTime - 7 * 24 * 60 * 60 || creationTime > currentTime + 60) {
          logger.warn(`Invalid fbp creationTime: ${creationTime}. Regenerating fbp from ${origin} (IP: ${clientIp}) at ${timestamp}`);
          validatedFbp = generateFbp();
        }
      } else {
        logger.warn(`Invalid fbp format: ${fbp}. Regenerating fbp from ${origin} (IP: ${clientIp}) at ${timestamp}`);
        validatedFbp = generateFbp();
      }
    } else {
      logger.warn(`Invalid fbp type: ${typeof fbp}. Regenerating fbp from ${origin} (IP: ${clientIp}) at ${timestamp}`);
      validatedFbp = generateFbp();
    }

    // fbc format validation
    const fbcRegex = /^fb\.\d+\.\d+\..+$/;
    let validatedFbc = fbc;
    if (typeof fbc === 'string' && fbcRegex.test(fbc)) {
      let fbcParts = fbc.split('.');
      let fbcCreationTime = parseInt(fbcParts[2], 10);
      if (fbcCreationTime > currentTime * 1000) {
        logger.warn(`fbc creationTime appears to be in milliseconds: ${fbcCreationTime}. Converting to seconds from ${origin} (IP: ${clientIp}) at ${timestamp}`);
        fbcCreationTime = Math.floor(fbcCreationTime / 1000);
        fbcParts[2] = fbcCreationTime;
        fbc = fbcParts.join('.');
      }
      if (fbcCreationTime < currentTime - 7 * 24 * 60 * 60 || fbcCreationTime > currentTime + 60) {
        logger.warn(`Invalid fbc creationTime: ${fbcCreationTime}. Regenerating fbc from ${origin} (IP: ${clientIp}) at ${timestamp}`);
        validatedFbc = fbclid ? generateFbc(fbclid) : '';
      } else {
        validatedFbc = fbc;
      }
    } else {
      validatedFbc = fbclid ? generateFbc(fbclid) : '';
    }

    return { fbp: validatedFbp, fbc: validatedFbc };
  };

  // custom_data Validation
  const validateCustomData = (custom_data) => {
    if (!custom_data || typeof custom_data !== 'object') {
      return {};
    }
    const validCustomData = {};
    if (typeof custom_data.value === 'number') validCustomData.value = custom_data.value;
    if (typeof custom_data.currency === 'string') validCustomData.currency = custom_data.currency;
    if (Array.isArray(custom_data.content_ids)) validCustomData.content_ids = custom_data.content_ids;
    if (typeof custom_data.content_type === 'string') validCustomData.content_type = custom_data.content_type;
    if (typeof custom_data.content_category === 'string') validCustomData.content_category = custom_data.content_category;
    return validCustomData;
  };

  // Event data creation
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

  // Event logging
  logger.info(`Sending to Facebook: ${JSON.stringify(body, null, 2)} from ${origin} (IP: ${clientIp}) at ${timestamp}`);

  // Sending events to the Facebook API
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
      logger.error(`Facebook API Error: ${JSON.stringify(fbData, null, 2)} from ${origin} (IP: ${clientIp}) at ${timestamp}`);
      return res.status(500).json({ error: 'Facebook API error', details: fbData });
    }

    logger.info(`Facebook API Success: ${JSON.stringify(fbData, null, 2)} from ${origin} (IP: ${clientIp}) at ${timestamp}`);
    return res.status(200).json({ success: true, data: fbData });
  } catch (error) {
    logger.error(`Fetch Error: ${error.message} from ${origin} (IP: ${clientIp}) at ${timestamp}`);
    return res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});