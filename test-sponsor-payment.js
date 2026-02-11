const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

async function testSponsorPayment() {
    const slotId = process.argv[2] || 1;

    console.log(`\n🧪 Testing sponsor payment for slot ${slotId}...\n`);

    // Step 1: Reserve the slot
    console.log('Step 1: Reserving slot...');
    const reserveRes = await fetch('http://localhost:3000/api/reserve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ slotId: parseInt(slotId) })
    });
    const reserveData = await reserveRes.json();
    console.log('Reserve response:', reserveData);

    if (!reserveData.success) {
        console.log('❌ Could not reserve slot. It might be taken.');
        return;
    }

    // Step 2: Simulate PayPal webhook (payment complete)
    console.log('\nStep 2: Simulating PayPal webhook payment...');
    const webhookPayload = {
        mock: true,
        event_type: 'PAYMENT.CAPTURE.COMPLETED',
        resource: {
            id: 'MOCK-TX-' + Date.now(),
            amount: { value: '100.00', currency_code: 'USD' },
            custom_id: slotId.toString(),
            payer: { email_address: 'sponsor@test.com' }
        }
    };

    const webhookRes = await fetch('http://localhost:3000/paypal-webhook', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(webhookPayload)
    });
    console.log('Webhook response status:', webhookRes.status);

    // Step 3: Check the slot status
    console.log('\nStep 3: Checking slot status...');
    const configRes = await fetch('http://localhost:3000/api/config');
    const config = await configRes.json();
    const slot = config.sponsors.find(s => s.slot === parseInt(slotId));

    if (slot) {
        console.log('Slot status:', slot.status);
        if (slot.status === 'paid') {
            console.log('\n✅ SUCCESS! Slot is marked as PAID.');
            console.log('You can now complete the brand setup form on the partners page.');
        } else {
            console.log('\n⚠️ Slot status is:', slot.status);
        }
    } else {
        console.log('❌ Slot not found');
    }
}

testSponsorPayment().catch(console.error);
