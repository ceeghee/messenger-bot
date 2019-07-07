"use strict";

const
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'),
  request = require('request'),
  mongoose = require('mongoose'),
  configDb = require('./config/db'),
   User    = require('./models/users');
  var app = express();
app.set('port', process.env.PORT || 9000);
app.use(bodyParser.json({ verify: verifyRequestSignature }));

	// Connect to Mongodb Database
    mongoose.connect(configDb.db, {useNewUrlParser: true},function(err){
        if(err){
            console.log('Connection to Database Failed '+ err);

        }else{
             console.log('Connected to the Database '+configDb.db);
        }
    });

var BIRTH_DATE='';
var USER_NAME = "";

const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ?
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');


  // Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');


  // URL where the app is running (include protocol). Used to point to scripts and
// assets located at this address.
const SERVER_URL = (process.env.SERVER_URL) ?
  (process.env.SERVER_URL) :
  config.get('serverURL');

  if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
  console.error("Missing config values");
  process.exit(1);
}


app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
	  req.query['hub.verify_token'] === VALIDATION_TOKEN) {
	console.log("Validating webhook");
	res.status(200).send(req.query['hub.challenge']);
  } else {
	console.error("Failed validation. Make sure the validation tokens match.");
	res.sendStatus(403);
  }
});


app.post('/webhook', function (req, res) {
  var data = req.body;

  // Make sure this is a page subscription
  if (data.object == 'page') {
	// Iterate over each entry
	// There may be multiple if batched
	data.entry.forEach(function(pageEntry) {
	  var pageID = pageEntry.id;
	  var timeOfEvent = pageEntry.time;

	  // Iterate over each messaging event
	  pageEntry.messaging.forEach(function(messagingEvent) {
		if (messagingEvent.optin) {
		  receivedAuthentication(messagingEvent);
		} else if (messagingEvent.message) {
		  receivedMessage(messagingEvent);
		} else if (messagingEvent.delivery) {
		  receivedDeliveryConfirmation(messagingEvent);
		} else if (messagingEvent.postback) {
		  receivedPostback(messagingEvent);
		} else if (messagingEvent.read) {
		  receivedMessageRead(messagingEvent);
		} else if (messagingEvent.account_linking) {
		  receivedAccountLink(messagingEvent);
		} else {
		  console.log("Webhook received unknown messagingEvent: ", messagingEvent);
		}
	  });
	});

	// Assume all went well.
	//
	// You must send back a 200, within 20 seconds, to let us know you've
	// successfully received the callback. Otherwise, the request will time out.
	res.sendStatus(200);
  }
});



/*
 * This path is used for account linking. The account linking call-to-action
 * (sendAccountLinking) is pointed to this URL.
 *
 */
app.get('/authorize', function(req, res) {
  var accountLinkingToken = req.query.account_linking_token;
  var redirectURI = req.query.redirect_uri;

  // Authorization Code should be generated per user by the developer. This will
  // be passed to the Account Linking callback.
  var authCode = "1234567890";

  // Redirect users to this URI on successful login
  var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

  res.render('authorize', {
	accountLinkingToken: accountLinkingToken,
	redirectURI: redirectURI,
	redirectURISuccess: redirectURISuccess
  });
});


function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
	// error.
	console.error("Couldn't validate the signature.");
  } else {
	var elements = signature.split('=');
	var method = elements[0];
	var signatureHash = elements[1];

	var expectedHash = crypto.createHmac('sha1', APP_SECRET)
						.update(buf)
						.digest('hex');

	if (signatureHash != expectedHash) {
	  throw new Error("Couldn't validate the request signature.");
	}
  }
}


function receivedAuthentication(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;

  // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
  // The developer can set this to an arbitrary value to associate the
  // authentication callback with the 'Send to Messenger' click event. This is
  // a way to do account linking when the user clicks the 'Send to Messenger'
  // plugin.
  var passThroughParam = event.optin.ref;

  console.log("Received authentication for user %d and page %d with pass " +
	"through param '%s' at %d", senderID, recipientID, passThroughParam,
	timeOfAuth);

  sendTextMessage(senderID, "Authentication successful");
}


function receivedMessage(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;

  console.log("Received message for user %d and page %d at %d with message:",
	senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(message));

  
  User.findOne({userId:senderID}).select('userId')
  .exec((err,data) => {
  	data ? updateUserData(message) : saveUserData(message)
  });

	function updateUserData(_message){
		const messageData = {
					messageId : _message.mid,
	  				messageText: _message.text,
	  				messageTime: new Date()
				}
		User.findOneAndUpdate({userId:senderID}, {$push:{messages:messageData}},{$new:true})
		.then(data => data ? console.log(data): console.log("error occured"))
		.catch(e => console.log(e))
	}

	function saveUserData(_message){
		let user = new User();
	  	user.userId = senderID;
	  	user.messages = [{
  				messageId : _message.mid,
  				messageText: _message.text,
  				messageTime: new Date()
		  }]
		  user.save((err,data) => { err ? console.log(err) : console.log(data)})
	}

  var isEcho = message.is_echo;
  var messageId = message.mid;
  var appId = message.app_id;
  var metadata = message.metadata;

  // You may get a text or attachment but not both
  var messageText = message.text;
  var messageAttachments = message.attachments;
  var quickReply = message.quick_reply;

  if (isEcho) {
	// Just logging message echoes to console
	console.log("Received echo for message %s and app %d with metadata %s",
	  messageId, appId, metadata);
	return;
  } else if (quickReply) {
	var quickReplyPayload = quickReply.payload;
	console.log("Quick reply for message %s with payload %s",
	  messageId, quickReplyPayload);

	quickReplyResponse(senderID, messageText);
	return;
  }

  if (messageText) {

	// If we receive a text message, check to see if it matches any special
	// keywords and send back the corresponding example. Otherwise, just echo
	// the text we received.
	switch (messageText.replace(/[^\w\s]/gi, '').trim().toLowerCase()) {
		
		 case 'hello':
		  case 'hi':
		 sendHiMessage(senderID);
		  break;

		  case "yes":
		  case "yeah":
		  case "yup":
		  case "yh":
		  quickReplyResponse(senderID, messageText);
		  break;

		  case "no":
		  case "nah":
		  case "nay":
		  case "nada":
		  quickReplyResponse(senderID, messageText);
		  break;

		  default:
			sendBirthDateMessage(senderID, messageText);


		}

	}
}

/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message.
 *
 */
function receivedDeliveryConfirmation(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var delivery = event.delivery;
  var messageIDs = delivery.mids;
  var watermark = delivery.watermark;
  var sequenceNumber = delivery.seq;

  if (messageIDs) {
	messageIDs.forEach(function(messageID) {
	  console.log("Received delivery confirmation for message ID: %s",
		messageID);
	});
  }

  console.log("All message before %d were delivered.", watermark);
}



/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message.
 *
 */
function receivedPostback(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfPostback = event.timestamp;

  
  var payload = event.postback.payload;

  console.log("Received postback for user %d and page %d with payload '%s' " +
	"at %d", senderID, recipientID, payload, timeOfPostback);

  sendTextMessage(senderID, "Postback called");
}

/*
 * Message Read Event
 *
 * This event is called when a previously-sent message has been read.
 *
 */
function receivedMessageRead(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  // All messages before watermark (a timestamp) or sequence have been seen.
  var watermark = event.read.watermark;
  var sequenceNumber = event.read.seq;

  console.log("Received message read event for watermark %d and sequence " +
	"number %d", watermark, sequenceNumber);
}

/*
 * Account Link Event
 *
 * This event is called when the Link Account or UnLink Account action has been
 * tapped.
 *
 */
function receivedAccountLink(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  var status = event.account_linking.status;
  var authCode = event.account_linking.authorization_code;

  console.log("Received account link event with for user %d with status %s " +
	"and auth code %s ", senderID, status, authCode);
}



function sendHiMessage(recipientId) {
  var messageData = {
	recipient: {
	  id: recipientId
	},
	message: {
	  text: `
	  Hi!
	  What is your first name?
	  `
	}
  }

  callSendAPI(messageData);
}



/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
  var messageData = {
	recipient: {
	  id: recipientId
	},
	message: {
	  text: messageText,
	  metadata: "DEVELOPER_DEFINED_METADATA"
	}
  };

  callSendAPI(messageData);
}

function sendBirthDateMessage(recipientId, messageText){
  if(isADate(messageText)){
	BIRTH_DATE = messageText;
	sendDateQuickReply(recipientId);

  }else if(isNaN(messageText) && messageText.length >= 4){
		var messageData = {
		recipient: {
		  id: recipientId
		},
		message: {
		  text: `
			 Hello ${messageText}
			 What is your Birth Date ? 

			 Kindly reply in this format [YYYY-MM-DD, e.g 1997-04-24]

			`
		  ,
		  metadata: "DEVELOPER_DEFINED_METADATA"
		}
	};
	callSendAPI(messageData);

  }
  else{
	sendTextMessage(recipientId, "Didn't get that, please try again");
  }
}

function quickReplyResponse(recipientId, messageText){
  switch(messageText.replace(/[^\w\s]/gi, '').trim().toLowerCase()){
	  case "yes":
	  case "yeah":
	  case "yup":
	  case "yh":
	  sendDaysToBirthDay(recipientId);
	  break;

	  case "no":
	  case "nah":
	  case "nay":
	  case "nop":
	  case "nope":
	  sendTextMessage(recipientId, "Goodbye 👋");
	  break;

	  default:
	  sendTextMessage(recipientId, "Didn't get that, please try again");
	  break;

  }
}

function sendDaysToBirthDay(recipientId){
	sendTypingOn(recipientId);
	let days_to_birthday = calculateDaysToBirthDay(BIRTH_DATE);

	var messageData = {
		recipient: {
		  id: recipientId
		},
		message: {
		  text: `
			 There are ${days_to_birthday} Days to your birthday.
			`
		  ,
		  metadata: "DEVELOPER_DEFINED_METADATA"
		}
	};
	callSendAPI(messageData);
}

function calculateDaysToBirthDay(birthDay){

	 let birth_day = birthDay.split('-');

	 let yr = birth_day[0]
	 let mo = parseInt(birth_day[1],10)
	 let day = parseInt(birth_day[2],10)

	 let today=new Date();
	  let month = 9; //september
	  var days_to_birthday=new Date(today.getFullYear(), mo, day);

	  days_to_birthday.setMonth(days_to_birthday.getMonth()-1); // month index starts from zero[0]
	  
	  if (today.getMonth()>days_to_birthday.getMonth()) 
	  {
		  days_to_birthday.setFullYear(days_to_birthday.getFullYear()+1); 
	  } 
	  if(today.getFullYear() < days_to_birthday.getFullYear()){

	  } 
	  var one_day=1000*60*60*24;
	  let days = Math.ceil((days_to_birthday.getTime()-today.getTime())/(one_day));
	  
	  return days;
}

function isADate(dateString) {
	var regEx = /^\d{4}-\d{2}-\d{2}$/;
	if(!dateString.match(regEx)) return false;  // Invalid format
	var d = new Date(dateString);
	var dNum = d.getTime();
	if(!dNum && dNum !== 0) return false; // NaN value, Invalid date
	return d.toISOString().slice(0,10) === dateString;
  }


  function sendDateQuickReply(recipientId) {
  var messageData = {
	recipient: {
	  id: recipientId
	},
	message: {
	  text: "Will you like to know how many days it is to your next birthday?",
	  quick_replies: [
		{
		  "content_type":"text",
		  "title":"YES",
		  "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_YES"
		},
		{
		  "content_type":"text",
		  "title":"NO",
		  "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_NO"
		}
	  ]
	}
  };

  callSendAPI(messageData);
}


/*
 * Turn typing indicator on
 *
 */
function sendTypingOn(recipientId) {
  console.log("Turning typing indicator on");

  var messageData = {
	recipient: {
	  id: recipientId
	},
	sender_action: "typing_on"
  };

  callSendAPI(messageData);
}


/*
 * Turn typing indicator off
 *
 */
function sendTypingOff(recipientId) {
  console.log("Turning typing indicator off");

  var messageData = {
	recipient: {
	  id: recipientId
	},
	sender_action: "typing_off"
  };

  callSendAPI(messageData);
}


/*
 * Call the Send API. The message data goes in the body. If successful, we'll
 * get the message id in a response
 *
 */
function callSendAPI(messageData) {
  request({
	uri: 'https://graph.facebook.com/v2.6/me/messages',
	qs: { access_token: PAGE_ACCESS_TOKEN },
	method: 'POST',
	json: messageData

  }, function (error, response, body) {
	if (!error && response.statusCode == 200) {
	  var recipientId = body.recipient_id;
	  var messageId = body.message_id;

	  if (messageId) {
		console.log("Successfully sent message with id %s to recipient %s",
		  messageId, recipientId);
	  } else {
	  console.log("Successfully called Send API for recipient %s",
		recipientId);
	  }
	} else {
	  console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
	}
  });
}


// Start server
// Webhooks must be available via SSL with a certificate signed by a valid
// certificate authority.
app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

module.exports = app;


