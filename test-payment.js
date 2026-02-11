const http = require('http');

// The slot we want to "pay" for
const slotId = 5;

// The fake webhook data
const payload = JSON.stringify({
    mock: true, // Tells server to bypass signature check in dev mode
    event_type: 'PAYMENT.CAPTURE.COMPLETED',
    resource: {
        id: 'TEST-TX-' + Date.now(),
        amount: { value: '100.00', currency_code: 'USD' },
        custom_id: slotId.toString(),
        payer: { email_address: 'test-buyer@sandbox.com' }
    }
});

const options = {
    hostname: 'localhost',
    port: 3000,
    path: '/api/webhooks/paypal',
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Content-Length': payload.length
    }
};

console.log(`Sending fake payment for Slot ${slotId}...`);

const req = http.request(options, (res) => {
    console.log(`Server responded with Status: ${res.statusCode}`);

    if (res.statusCode === 200) {
        console.log('✅ Success! The server accepted the payment.');
        console.log('Go to http://localhost:3000/partners.html and check if Slot 5 allows setup.');
    } else {
        console.log('❌ Something went wrong.');
    }
});

req.on('error', (error) => {
    console.error('Error connecting to server:', error.message);
    console.log('Is the server running on port 3000?');
});

req.write(payload);
req.end();
