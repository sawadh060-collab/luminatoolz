const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

async function sendMockWebhook() {
    const userId = process.argv[2];
    if (!userId) {
        console.error('Error: Please provide your userId (found in browser cookies).');
        console.log('Usage: node test-webhook.js <YOUR_USER_ID>');
        process.exit(1);
    }

    console.log(`Sending mock COMPLETED payment for userId: ${userId}...`);

    const payload = {
        mock: true, // This flag allows bypass in development mode
        event_type: 'PAYMENT.CAPTURE.COMPLETED',
        resource: {
            id: 'MOCK-TX-' + Date.now(),
            amount: { value: '5.00', currency_code: 'USD' },
            custom_id: userId,
            payer: { email_address: 'tester@example.com' }
        }
    };

    const res = await fetch('http://localhost:8080/api/webhooks/paypal', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });

    if (res.ok) {
        console.log('Success! Database updated. You should now have access to /survey.html');
    } else {
        console.error('Failed: Server returned', res.status);
    }
}

sendMockWebhook();
