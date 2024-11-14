const express = require('express');
const bodyParser = require('body-parser');
const app = express();
require('dotenv').config();
const logger = require('./utils/logger');
const port = process.env.PORT || 3000;
const webhook_url = process.env.WEBHOOK;
const crypto = require('crypto');
const TelegramBot = require('node-telegram-bot-api');
const axios = require('axios');
const fraudwall_token = process.env.TELEGRAM_TOKEN;
const bot = new TelegramBot(fraudwall_token);


const FormData = require('form-data');


app.use(bodyParser.json());

app.post(`/bot${fraudwall_token}`, (req, res) => {
  bot.processUpdate(req.body);
  res.sendStatus(200);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

bot.setWebHook(`${webhook_url}/bot${fraudwall_token}`)
  .then(() => {
    console.log('Webhook set successfully');
  })
  .catch((error) => {
    throw new Error(`Failed to set webhook: ${error.message}`);
  });


const userStates = {};
let token = '';

const axiosInstance = axios.create();

axiosInstance.interceptors.request.use(
  (config) => {
    if (config.url.includes('/api/report')) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);


bot.on('message', (msg) => {
  const chatId = msg.chat.id;
  const welcomeMsg = process.env.WELCOME_MESSAGE || 'Welcome to Fraudwall bot!';

  if (msg.text === '/start' || msg.text === '/verify' || msg.text === '/report') {
    const keyboard = {
      inline_keyboard: [
        [
          { text: 'Verify', callback_data: '/verify' },
          { text: 'Report', callback_data: '/report' }
        ]
      ]
    };
    bot.sendMessage(chatId, welcomeMsg, { reply_markup: keyboard });
  }
});



bot.on('callback_query', async (query) => {
  const chatId = query.message.chat.id;

  if (query.data === '/verify') {
    userStates[chatId] = 'verifying';
    await bot.sendMessage(chatId, 'Please enter the phone number you want to verify as fraud (+233XXXXXXXX):');
  } else if (query.data === '/report') {
    userStates[chatId] = 'reporting';
    await bot.sendMessage(chatId, 'Please provide your number to be verified (+233XXXXXXXX): ');
  }

  await bot.answerCallbackQuery(query.id);
});

async function showMainMenu(chatId, message) {
  const welcomeMsg = message || process.env.WELCOME_MESSAGE || 'Welcome to Fraudwall bot!';
  const keyboard = {
    inline_keyboard: [
      [
        { text: 'Verify', callback_data: '/verify' },
        { text: 'Report', callback_data: '/report' }
      ]
    ]
  };
  await bot.sendMessage(chatId, welcomeMsg, { reply_markup: keyboard });
}

bot.on('message', (msg) => {
  const chatId = msg.chat.id;
  const text = msg.text;

  if (text === '/start') {
  } else if (userStates[chatId] === 'verifying') {
    handleVerify(chatId, text);
  } else if (userStates[chatId] === 'reporting') {
    handleReport(chatId, text);
  } else if (text !== '/verify' && text !== '/report') {
    return;
  }
});

async function handleVerify(chatId, phoneNumber) {
  try {
    await bot.sendMessage(chatId, `Retrieving information for Phone number: ${phoneNumber}. Please wait...`);
    const apiUrl = `${process.env.BASE_API_URL}${process.env.VALIDATE_ENDPOINT}${phoneNumber}?origin=${process.env.ORIGIN}`;

    const options = {
      method: 'GET',
      url: apiUrl,
      headers: {
        'X-API-KEY': process.env.API_KEY
      },
    };
    const response = await axios.request(options);
    const fraudInfo = response.data;
    logger.info('Number validation', {
      type: 'validation',
      phoneNumber,
      result: fraudInfo.statusCode === 302 ? 'fraudulent' : 'clean',
      platforms: fraudInfo.statusCode === 302 ? fraudInfo.data.reportCountByPlatform : [],
      chatId
    });
    if (fraudInfo.statusCode === 302) {
      const platforms = fraudInfo.data.reportCountByPlatform.join(', ');
      await bot.sendMessage(chatId, `Caution\n ${phoneNumber} has been identified as Fraudulent and reported on the following platforms: ${platforms}`);
      await showMainMenu(chatId, "Tip: Be extremely cautious when dealing with this number. Do not share personal information or send money. If you've been contacted by this number, consider reporting it to local authorities. Use our 'Report' feature to add any new information about fraudulent activities associated with this number.");
    } else {
      await bot.sendMessage(chatId, `Good News\nWe don't have any reports on ${phoneNumber} involved in any fraudulent activities!`);
      
    }
  } catch (error) {
    logger.error('Validation error', {
      type: 'validation_error',
      phoneNumber,
      error: error.response?.data || error.message,
      chatId
    });
    if (error.response?.data.statusCode === 404) {
      await bot.sendMessage(chatId, `Good News\nWe don't have any reports on ${phoneNumber} involved in any fraudulent activities!`);
      await showMainMenu(chatId, "Tip: While this number hasn't been reported, always be cautious when dealing with unknown contacts. If you encounter any suspicious activity, please use our 'Report' feature to help keep our community safe.");
    } else if(error.response?.data.statusCode === 400) {
      await showMainMenu(chatId, 'Invalid phone number. Phone number must be in this format (+233XXXXXXXXX)');
    } else {
      await bot.sendMessage(chatId, 'An error occurred while retrieving fraud information.');
    }
  } finally {
    userStates[chatId] = null;
  }
}

async function handleReport(chatId, reporterNumber) {
  try {
    userStates[chatId] = { 
      reporterNumber: reporterNumber,
      awaitingOTP: true,
      otpListener: null
    };
    
    const otpApiUrl = `${process.env.BASE_API_URL}${process.env.OTP_ENDPOINT}/${reporterNumber}`;

    const otpOptions = {
      method: 'GET',
      url: otpApiUrl,
      headers: {
        'X-API-KEY': process.env.API_KEY
      }
    };

    await axios.request(otpOptions);
    await bot.sendMessage(chatId, `An OTP will be sent to your number ${reporterNumber} and will expire in five minutes.\nEnter OTP to verify your number: `);
    await askForOTP(chatId);
    
    userStates[chatId].otpTimeout = setTimeout(() => {
      if (userStates[chatId] && userStates[chatId].awaitingOTP) {
        cleanupOTPSession(chatId);
        sendOTPExpiredMessage(chatId);
      }
    }, 300000); 

  } catch (error) {
    if (error.response?.data.statusCode === 400) {
      await showMainMenu(chatId, 'Invalid phone number. Phone number must be in this format (+233XXXXXXXXX)');
    } else {
      await handleError(chatId);
    }
  }
}

async function askForOTP(chatId) {
  if (userStates[chatId] && userStates[chatId].otpListener) {
    bot.removeListener('message', userStates[chatId].otpListener);
  }

  userStates[chatId].otpListener = async (message) => {
    if (message.chat.id === chatId && userStates[chatId] && userStates[chatId].awaitingOTP) {
      const otp = message.text;
      const reporterNumber = userStates[chatId].reporterNumber;
      await verifyOTP(chatId, reporterNumber, otp);
    }
  };
  
  bot.on('message', userStates[chatId].otpListener);
}

async function verifyOTP(chatId, reporterNumber, otp) {
  const verifyOtpUrl = `${process.env.BASE_API_URL}${process.env.VERIFY_OTP_ENDPOINT}`;
  const verifyOtpOptions = {
    method: 'POST',
    url: verifyOtpUrl,
    headers: {
      'X-API-KEY': process.env.API_KEY
    },
    data: {
      'reporterNumber': reporterNumber,
      'code': otp
    }
  };

  try {
    const response = await axios.request(verifyOtpOptions);
    cleanupOTPSession(chatId);
    token = response.data.accessToken;
    userStates[chatId] = { ...userStates[chatId], token: token };
    await fetchAndDisplayPlatforms(chatId);
  } catch (error) {
    await bot.sendMessage(chatId, 'Invalid OTP. Please try again.');
    await askForOTP(chatId);
  }
}

function cleanupOTPSession(chatId) {
  if (userStates[chatId]) {
    clearTimeout(userStates[chatId].otpTimeout);
    if (userStates[chatId].otpListener) {
      bot.removeListener('message', userStates[chatId].otpListener);
    }
    delete userStates[chatId].awaitingOTP;
    delete userStates[chatId].otpListener;
    delete userStates[chatId].otpTimeout;
  }
}

async function sendOTPExpiredMessage(chatId) {
  const keyboard = {
    inline_keyboard: [
      [{ text: 'Request New OTP', callback_data: 'request_new_otp' }]
    ]
  };
  await bot.sendMessage(chatId, 'Your OTP has expired. Would you like to request a new one?', { reply_markup: keyboard });
}

bot.on('callback_query', async (query) => {
  const chatId = query.message.chat.id;
  const data = query.data;

  if (data === 'request_new_otp') {
    if (userStates[chatId] && userStates[chatId].reporterNumber) {
      await handleReport(chatId, userStates[chatId].reporterNumber);
    } else {
      await showMainMenu(chatId, 'Something went wrong. Please start over.');
    }
  } else if (data.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i)) {
    userStates[chatId] = { ...userStates[chatId], platformId: data };
    await reportNumber(chatId);
  }

  await bot.answerCallbackQuery(query.id);
});

async function fetchAndDisplayPlatforms(chatId) {
  try {
    const platformsUrl = `${process.env.BASE_API_URL}${process.env.PLATFORMS_ENDPOINT}`;
    const platformsOptions = {
      method: 'GET',
      url: platformsUrl,
      headers: {
        'X-API-KEY': process.env.API_KEY
      }
    };
    await axios.request(platformsOptions)
      .then(response => {
        const apiResponse = response.data;

        const keyboard = {
          inline_keyboard: apiResponse.data.map(platform => [{
            text: platform.displayName,
            callback_data: platform.id
          }])
        };

        bot.sendMessage(chatId, 'Select the social media platform:', { reply_markup: keyboard });
      })
  } catch (error) {
    handleError(chatId);
  }
}


const algorithm = process.env.ENCRYPTION_ALGORITHM;
const secretKey = process.env.ENCRYPTION_SECRET_KEY;


function encrypt(text) {
  try {
    if (typeof text !== "string") {
      throw new Error("Input must be a string");
    }

    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, Buffer.from(secretKey), iv);
    let encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");

    return `${iv.toString("hex")}:${encrypted}`;
  } catch (error) {
    throw new Error(`Encryption error: ${error.message}`);
  }
}

async function reportNumber(chatId) {
  try {
    const reportUrl = `${process.env.BASE_API_URL}${process.env.REPORT_NUMBER_ENDPOINT}/?origin=${process.env.ORIGIN}`;
    const platformId = userStates[chatId].platformId;
    const userToken = userStates[chatId].token;

    userStates[chatId].reportStage = 'suspectNumber';
    await bot.sendMessage(chatId, 'Please enter the suspect number(+233XXXXXXXX):');

    if (userStates[chatId] && userStates[chatId].reportListener) {
      bot.removeListener('message', userStates[chatId].reportListener);
    }

    // Create a unique listener for this chat session
    userStates[chatId].reportListener = createReportListener(chatId, reportUrl, platformId, userToken);
    bot.on('message', userStates[chatId].reportListener);

  } catch (error) {
    await handleError(chatId);
    cleanupReportSession(chatId);
  }
}

function createReportListener(chatId, reportUrl, platformId, userToken) {
  return async (msg) => {
    if (msg.chat.id !== chatId || !userStates[chatId]) return;

    try {
      switch (userStates[chatId].reportStage) {
        case 'suspectNumber':
          userStates[chatId].suspectNumber = encrypt(msg.text);
          userStates[chatId].reportStage = 'incidentDate';
          await bot.sendMessage(chatId, 'Please enter the incident date (DD-MM-YYYY):');
          break;

        case 'incidentDate':
          const [day, month, year] = msg.text.split('-');
          userStates[chatId].formattedDate = `${year}-${month}-${day}`;
          userStates[chatId].reportStage = 'description';
          await bot.sendMessage(chatId, 'Please provide a description:');
          break;

        case 'description':
          userStates[chatId].description = encrypt(msg.text);
          userStates[chatId].reportStage = 'evidence';
          await bot.sendMessage(chatId, 'Please upload an image or file as evidence:');
          break;

        case 'evidence':
          if (msg.photo) {
            const fileId = msg.photo[msg.photo.length - 1].file_id;
            await handleEvidence(chatId, fileId, reportUrl, platformId, userToken);
          } else {
            await bot.sendMessage(chatId, 'Please upload an image as evidence.');
          }
          break;
      }
    } catch (error) {
      await handleError(chatId);
      cleanupReportSession(chatId);
    }
  };
}

async function handleEvidence(chatId, fileId, reportUrl, platformId, userToken) {
  try {
    const fileLink = await bot.getFileLink(fileId);
    const formData = new FormData();
    formData.append('suspectNumber', userStates[chatId].suspectNumber);
    formData.append('platFormId', platformId);
    formData.append('description', userStates[chatId].description);
    formData.append('incidentDate', userStates[chatId].formattedDate);

    const response = await axios.get(fileLink, { responseType: 'stream' });
    formData.append('requestFiles', response.data, { filename: 'image.jpg', contentType: 'image/jpeg' });

    const reportOptions = {
      method: 'POST',
      url: reportUrl,
      headers: {
        'X-API-KEY': process.env.API_KEY,
        'Authorization': `Bearer ${userToken}`,
        ...formData.getHeaders()
      },
      data: formData
    };

    await axiosInstance.request(reportOptions);
    await bot.sendMessage(chatId, 'Report submitted successfully!\nVisit our website fraudwall.ai to verify or report a phone number \nDial *920*419# to verify if a phone number is fraudulent');
  } catch (error) {
    if (error.response && (error.response.status === 400 || error.response.statusText === 'Bad Request')) {
      await bot.sendMessage(chatId, 'The provided report details are invalid. Please check your information and try again.');
    } else {
      await handleError(chatId);
    }
  } finally {
    cleanupReportSession(chatId);
  }
}

function cleanupReportSession(chatId) {
  if (userStates[chatId] && userStates[chatId].reportListener) {
    bot.removeListener('message', userStates[chatId].reportListener);
    delete userStates[chatId].reportListener;
    delete userStates[chatId].reportStage;
    delete userStates[chatId].suspectNumber;
    delete userStates[chatId].formattedDate;
    delete userStates[chatId].description;
  }
}

async function handleError(chatId) {
  return error => {
    if (error.response && error.response.data) {
      let errorMessage = '';
      if (Array.isArray(error.response.data.message)) {
        errorMessage = error.response.data.message.join(', ');
      } else if (typeof error.response.data.message === 'string') {
        errorMessage = error.response.data.message;
      } else if (typeof error.response.data === 'string') {
        errorMessage = error.response.data;
      } else {
        errorMessage = JSON.stringify(error.response.data);
      }
      bot.sendMessage(chatId, `Error: ${errorMessage}`);
    } else {
      bot.sendMessage(chatId, 'An error occurred while processing your request.');
    }
  };
}


