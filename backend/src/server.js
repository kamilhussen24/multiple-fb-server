require('dotenv').config();
const express = require('express');
const fetch = require('node-fetch');
const fs = require('fs');
const winston = require('winston');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();

// Vercel-এর জন্য প্রক্সি সেটিং চালু করা
app.set('trust proxy', 1);

// লগিং সেটআপ (Vercel-এর জন্য কনসোল লগ)
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

// clients.json ফাইল লোড করা
let clients;
try {
  clients = JSON.parse(fs.readFileSync('backend/src/clients.json', 'utf8'));
  logger.info('ক্লায়েন্ট ফাইল (clients.json) সফলভাবে লোড হয়েছে', { clientCount: clients.length });
} catch (error) {
  logger.error('ক্লায়েন্ট ফাইল (clients.json) লোড করতে সমস্যা', {
    error: error.message,
    solution: 'backend/src/clients.json ফাইলটি চেক করুন। JSON ফরম্যাট ঠিক আছে কিনা দেখুন।'
  });
  clients = [];
}

// রেট লিমিট সেটআপ (১৫ মিনিটে ১০০টি রিকোয়েস্ট)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // ১৫ মিনিট
  max: 100, // প্রতি IP থেকে ১০০ রিকোয়েস্ট
  message: 'অনেক বেশি রিকোয়েস্ট পাঠানো হয়েছে। ১৫ মিনিট পর আবার চেষ্টা করুন।'
});

// মিডলওয়্যার
app.use(limiter);
app.use(express.json());
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) {
      logger.warn('কোনো ওয়েবসাইট অরিজিন দেওয়া হয়নি', {
        solution: 'টেস্টিংয়ের জন্য এটি ঠিক আছে, কিন্তু ওয়েবসাইট থেকে রিকোয়েস্টে অরিজিন থাকা উচিত।'
      });
      return callback(null, true);
    }
    const client = clients.find(c => c.origin === origin);
    if (client) {
      logger.info(`ওয়েবসাইট অরিজিন ${origin} অনুমোদিত`, { origin });
      return callback(null, true);
    }
    logger.error(`ওয়েবসাইট অরিজিন ${origin} অনুমোদিত নয়`, {
      solution: `clients.json ফাইলে ${origin} যোগ করুন।`
    });
    return callback(new Error(`ওয়েবসাইট ${origin} অনুমোদিত নয়। clients.json ফাইলে এটি যোগ করুন।`));
  },
  methods: ['POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-API-Key']
}));

// রিকোয়েস্ট লগিং
app.use((req, res, next) => {
  const origin = req.headers.origin || 'জানা নেই';
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'জানা নেই';
  const userAgent = req.headers['user-agent'] || 'জানা নেই';

  logger.info(`নতুন রিকোয়েস্ট পাওয়া গেছে: ${req.method} ${req.url}`, {
    origin,
    clientIp,
    userAgent
  });

  // বট চেক
  if (userAgent.toLowerCase().includes('bot') || userAgent.toLowerCase().includes('crawler')) {
    logger.warn('বট শনাক্ত হয়েছে, রিকোয়েস্ট ব্লক করা হলো', { userAgent, origin, clientIp });
    return res.status(400).json({ error: 'বট শনাক্ত হয়েছে। রিকোয়েস্ট ব্লক করা হয়েছে।' });
  }

  next();
});

// ইভেন্ট ট্র্যাকিং এন্ডপয়েন্ট
app.post('/api/track', async (req, res) => {
  const origin = req.headers.origin || 'জানা নেই';
  const apiKey = req.headers['x-api-key'] || null;
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'জানা নেই';

  // রিকোয়েস্টের তথ্য লগ করা
  logger.info('/api/track রিকোয়েস্ট প্রক্রিয়া শুরু', {
    origin,
    apiKey: apiKey ? 'দেওয়া হয়েছে' : 'দেওয়া হয়নি',
    clientIp,
    requestBody: req.body
  });

  // API কী এবং অরিজিন যাচাই
  let pixel_id, access_token;
  try {
    const clientConfig = getClientConfig(origin, apiKey);
    pixel_id = clientConfig.pixel_id;
    access_token = clientConfig.access_token;
    logger.info(`ক্লায়েন্ট কনফিগারেশন ঠিক আছে`, { origin, pixel_id });
  } catch (error) {
    logger.error('ক্লায়েন্ট কনফিগারেশনে সমস্যা', {
      error: error.message,
      origin,
      apiKey,
      solution: 'clients.json ফাইলে অরিজিন এবং API কী ঠিক আছে কিনা চেক করুন।'
    });
    return res.status(403).json({ error: error.message });
  }

  // রিকোয়েস্ট থেকে ডেটা নেওয়া
  const {
    event_name,
    event_source_url,
    event_id,
    event_time,
    user_data = {},
    custom_data = {}
  } = req.body;

  // প্রয়োজনীয় ফিল্ড চেক
  const missingFields = [];
  if (!event_name) missingFields.push('event_name');
  if (!event_source_url) missingFields.push('event_source_url');
  if (!event_id) missingFields.push('event_id');
  if (!event_time) missingFields.push('event_time');
  if (missingFields.length > 0) {
    logger.error('প্রয়োজনীয় ফিল্ড মিসিং', {
      missingFields,
      origin,
      clientIp,
      solution: 'tracking.js ফাইলে event_name, event_source_url, event_id, event_time পাঠানো হচ্ছে কিনা চেক করুন।'
    });
    return res.status(400).json({ error: 'প্রয়োজনীয় ফিল্ড মিসিং', missing: missingFields });
  }
  logger.info('সব প্রয়োজনীয় ফিল্ড পাওয়া গেছে', { event_name, event_id, event_source_url, event_time });

  // ইভেন্ট টাইম যাচাই
  const currentTime = Math.floor(Date.now() / 1000);
  let validatedEventTime = Number.isInteger(Number(event_time)) ? Number(event_time) : currentTime;
  if (validatedEventTime < currentTime - 7 * 24 * 60 * 60 || validatedEventTime > currentTime + 60) {
    logger.warn('ইভেন্ট টাইম সঠিক নয়, বর্তমান সময় ব্যবহার করা হচ্ছে', {
      providedEventTime: event_time,
      adjustedEventTime: currentTime,
      origin
    });
    validatedEventTime = currentTime;
  } else {
    logger.info('ইভেন্ট টাইম সঠিক', { event_time: validatedEventTime });
  }

  // fbp জেনারেট করা
  const generateFbp = () => {
    const version = 'fb';
    const subdomainIndex = 1;
    const creationTime = validatedEventTime;
    const randomNumber = Math.floor(Math.random() * 10000000000);
    const fbp = `${version}.${subdomainIndex}.${creationTime}.${randomNumber}`;
    logger.info('নতুন fbp তৈরি করা হয়েছে', { fbp, origin });
    return fbp;
  };

  // fbc জেনারেট করা
  const generateFbc = (fbclid) => {
    const version = 'fb';
    const subdomainIndex = 1;
    const creationTime = validatedEventTime;
    const fbc = `${version}.${subdomainIndex}.${creationTime}.${fbclid}`;
    logger.info('নতুন fbc তৈরি করা হয়েছে', { fbc, origin });
    return fbc;
  };

  // user_data যাচাই
  const validateUserData = (user_data) => {
    if (!user_data || typeof user_data !== 'object') {
      logger.warn('user_data সঠিক নয়, নতুন fbp তৈরি করা হচ্ছে', { origin });
      return { fbp: generateFbp(), fbc: '' };
    }

    let { fbp = '', fbc = '', fbclid = '' } = user_data;

    // fbp যাচাই
    const fbpRegex = /^fb\.\d+\.\d+\.\d+$/;
    let validatedFbp = fbp;
    if (typeof fbp === 'string' && fbpRegex.test(fbp)) {
      const creationTime = parseInt(fbp.split('.')[2], 10);
      if (creationTime < currentTime - 7 * 24 * 60 * 60 || creationTime > currentTime + 60) {
        logger.warn('fbp-এর সময় সঠিক নয়, নতুন fbp তৈরি করা হচ্ছে', { fbp, origin });
        validatedFbp = generateFbp();
      } else {
        logger.info('fbp সঠিক', { fbp });
      }
    } else {
      logger.warn('fbp ফরম্যাট সঠিক নয়, নতুন fbp তৈরি করা হচ্ছে', { fbp, origin });
      validatedFbp = generateFbp();
    }

    // fbc যাচাই
    const fbcRegex = /^fb\.\d+\.\d+\..+$/;
    let validatedFbc = fbc;
    if (typeof fbc === 'string' && fbcRegex.test(fbc)) {
      const fbcCreationTime = parseInt(fbc.split('.')[2], 10);
      if (fbcCreationTime < currentTime - 7 * 24 * 60 * 60 || fbcCreationTime > currentTime + 60) {
        logger.warn('fbc-এর সময় সঠিক নয়, নতুন fbc তৈরি করা হচ্ছে', { fbc, origin });
        validatedFbc = fbclid ? generateFbc(fbclid) : '';
      } else {
        logger.info('fbc সঠিক', { fbc });
      }
    } else {
      validatedFbc = fbclid ? generateFbc(fbclid) : '';
      logger.info('fbc দেওয়া হয়নি বা ফরম্যাট সঠিক নয়', { fbc, origin });
    }

    return { fbp: validatedFbp, fbc: validatedFbc };
  };

  // custom_data যাচাই
  const validateCustomData = (custom_data) => {
    if (!custom_data || typeof custom_data !== 'object') {
      logger.warn('custom_data সঠিক নয়, খালি অবজেক্ট ফেরত দেওয়া হচ্ছে', { origin });
      return {};
    }
    const validCustomData = {};
    if (typeof custom_data.value === 'number') {
      validCustomData.value = custom_data.value;
      logger.info('custom_data-এর value সঠিক', { value: custom_data.value });
    }
    if (typeof custom_data.currency === 'string') {
      validCustomData.currency = custom_data.currency;
      logger.info('custom_data-এর currency সঠিক', { currency: custom_data.currency });
    }
    if (Array.isArray(custom_data.content_ids)) {
      validCustomData.content_ids = custom_data.content_ids;
      logger.info('custom_data-এর content_ids সঠিক', { content_ids: custom_data.content_ids });
    }
    if (typeof custom_data.content_type === 'string') {
      validCustomData.content_type = custom_data.content_type;
      logger.info('custom_data-এর content_type সঠিক', { content_type: custom_data.content_type });
    }
    if (typeof custom_data.content_category === 'string') {
      validCustomData.content_category = custom_data.content_category;
      logger.info('custom_data-এর content_category সঠিক', { content_category: custom_data.content_category });
    }
    return validCustomData;
  };

  // ইভেন্ট ডেটা তৈরি
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
          client_user_agent: req.headers['user-agent'] || 'জানা নেই',
          ...validateUserData(user_data)
        },
        custom_data: validateCustomData(custom_data)
      }
    ]
  };

  // ফেসবুক API-তে পাঠানোর আগে ডেটা লগ করা
  logger.info('ফেসবুক API-তে ইভেন্ট পাঠানোর জন্য তৈরি ডেটা', {
    event_name: body.data[0].event_name,
    event_id: body.data[0].event_id,
    event_time: body.data[0].event_time,
    event_source_url: body.data[0].event_source_url,
    user_data: body.data[0].user_data,
    custom_data: body.data[0].custom_data,
    origin,
    clientIp
  });

  // ফেসবুক API-তে ইভেন্ট পাঠানো
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
      logger.error('ফেসবুক API-তে ইভেন্ট পাঠাতে সমস্যা', {
        status: fbRes.status,
        response: fbData,
        event_name,
        origin,
        clientIp,
        solution: 'pixel_id এবং access_token চেক করুন। ফেসবুক Events Manager থেকে নতুন টোকেন নিন।'
      });
      return res.status(500).json({ error: 'ফেসবুক API-তে সমস্যা', details: fbData });
    }

    logger.info('ফেসবুক API-তে ইভেন্ট সফলভাবে পাঠানো হয়েছে', {
      event_name,
      event_id,
      response: fbData,
      origin,
      clientIp
    });
    return res.status(200).json({ success: true, data: fbData });
  } catch (error) {
    logger.error('ফেসবুক API-তে ইভেন্ট পাঠাতে ত্রুটি', {
      error: error.message,
      event_name,
      origin,
      clientIp,
      solution: 'ইন্টারনেট সংযোগ বা ফেসবুক API সার্ভার চেক করুন।'
    });
    return res.status(500).json({ error: 'সার্ভারে ত্রুটি', details: error.message });
  }
});

// ক্লায়েন্ট কনফিগারেশন যাচাই ফাংশন
function getClientConfig(origin, apiKey) {
  if (!clients || clients.length === 0) {
    throw new Error('কোনো ক্লায়েন্ট কনফিগার করা নেই। clients.json ফাইল চেক করুন।');
  }
  const client = clients.find(c => c.origin === origin && c.api_key === apiKey);
  if (!client) {
    throw new Error(`অরিজিন ${origin} বা API কী ${apiKey} সঠিক নয়। clients.json চেক করুন।`);
  }
  return {
    pixel_id: client.pixel_id,
    access_token: client.access_token
  };
}

// হেলথ চেক এন্ডপয়েন্ট
app.get('/health', (req, res) => {
  logger.info('হেলথ চেক রিকোয়েস্ট পাওয়া গেছে');
  res.status(200).json({ status: 'সার্ভার ঠিক আছে', timestamp: new Date().toISOString() });
});

// সার্ভার শুরু
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info(`সার্ভার চলছে পোর্ট ${PORT}-এ`);
});