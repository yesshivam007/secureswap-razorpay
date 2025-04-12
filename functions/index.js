// functions/index.js
// Backend logic using Firebase Cloud Functions and Razorpay

const functions = require("firebase-functions");
const admin = require("firebase-admin");
const Razorpay = require("razorpay");
const crypto = require("crypto"); // Built-in Node.js crypto library
const cors = require("cors")({ origin: true }); // Enable CORS for callable functions

// Initialize Firebase Admin SDK (runs in the backend environment)
admin.initializeApp();
const db = admin.firestore();

// Initialize Razorpay instance using environment variables
// These MUST be set using `firebase functions:config:set ...`
const razorpayInstance = new Razorpay({
    key_id: functions.config().razorpay.key_id,
    key_secret: functions.config().razorpay.key_secret,
});

/**
 * Creates a Razorpay Order when called by the frontend.
 * - Verifies transaction details in Firestore.
 * - Creates order via Razorpay API.
 * - Updates Firestore transaction with Razorpay order ID.
 * - Returns order details to frontend for checkout.
 */
exports.createRazorpayOrder = functions.https.onCall(async (data, context) => {
    // Check authentication
    if (!context.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'User must be logged in to create an order.');
    }

    const userId = context.auth.uid;
    const transactionId = data.transactionId;
    const userEmail = context.auth.token.email; // Email from authenticated user token

    if (!transactionId) {
        throw new functions.https.HttpsError('invalid-argument', 'Transaction ID is required.');
    }

    console.log(`Creating Razorpay order for transaction ${transactionId} by user ${userEmail}`);

    try {
        const txDocRef = db.collection('transactions').doc(transactionId);
        const txDoc = await txDocRef.get();

        if (!txDoc.exists) {
            throw new functions.https.HttpsError('not-found', 'Transaction not found.');
        }

        const txData = txDoc.data();

        // --- Security & Validation Checks ---
        // 1. Check if the caller is the buyer
        if (txData.buyerEmail !== userEmail) {
            throw new functions.https.HttpsError('permission-denied', 'Only the buyer can initiate payment for this transaction.');
        }
        // 2. Check if transaction status is correct for payment
        if (txData.status !== 'awaiting_payment') {
            throw new functions.https.HttpsError('failed-precondition', `Transaction is not awaiting payment (status: ${txData.status}).`);
        }
        // 3. Check if amount is valid
        if (!txData.amount || txData.amount <= 0) {
            throw new functions.https.HttpsError('failed-precondition', 'Invalid transaction amount.');
        }
        // --- End Checks ---

        const amountInPaise = Math.round(txData.amount * 100); // Razorpay requires amount in smallest currency unit (paise for INR)
        const currency = txData.currency || 'INR';
        const receiptId = `txn_${transactionId}_${Date.now()}`; // Unique receipt ID for Razorpay

        const options = {
            amount: amountInPaise,
            currency: currency,
            receipt: receiptId,
            notes: {
                transactionId: transactionId,
                buyerEmail: txData.buyerEmail,
                sellerEmail: txData.sellerEmail,
                item: txData.itemDescription.substring(0, 50) // Add notes if needed
            }
        };

        // Create Razorpay order
        const order = await razorpayInstance.orders.create(options);
        console.log("Razorpay order created:", order.id);

        // Update Firestore transaction with the Razorpay order ID
        await txDocRef.update({
            razorpayOrderId: order.id // Store the order ID for webhook verification
        });
        console.log(`Stored Razorpay order ID ${order.id} on transaction ${transactionId}`);

        // Return necessary details to the frontend
        return {
            orderId: order.id,
            amount: order.amount, // Amount in paise
            currency: order.currency,
            keyId: functions.config().razorpay.key_id // Return public key ID
        };

    } catch (error) {
        console.error("Error creating Razorpay order:", error);
        if (error instanceof functions.https.HttpsError) {
            throw error; // Re-throw HttpsError
        } else {
            // Throw a generic internal error for other issues
            throw new functions.https.HttpsError('internal', 'Failed to create payment order.', error.message);
        }
    }
});


/**
 * Verifies Razorpay Webhook signature and updates Firestore transaction status on successful payment.
 * - Listens for HTTP POST requests from Razorpay.
 * - Validates signature using webhook secret.
 * - Updates transaction status to 'awaiting_shipment' if payment is 'captured'.
 */
exports.verifyRazorpayPayment = functions.https.onRequest(async (req, res) => {
    // Use CORS middleware for testing if needed, but webhooks usually don't need it if called server-to-server
    // cors(req, res, async () => { ... }); // Uncomment if CORS issues arise during testing

    console.log("Received Razorpay Webhook...");

    // 1. Validate Webhook Signature
    const receivedSignature = req.headers["x-razorpay-signature"];
    const webhookSecret = functions.config().razorpay.webhook_secret;

    if (!receivedSignature || !webhookSecret) {
        console.error("Missing signature or webhook secret configuration.");
        return res.status(400).send("Webhook configuration error.");
    }

    try {
        // IMPORTANT: req.rawBody is needed for signature verification if using Express/body-parser
        // Firebase Functions provide the raw body directly on req.body when no parsing middleware is used explicitly for the function
        // If using Express within the function, ensure body-parser doesn't parse it before verification.
        // For standard Firebase Functions req.body should be the raw buffer or string if Content-Type allows.
        // Let's assume req.body contains the raw payload string/buffer for now.
        // If using Express: const requestBody = req.rawBody || JSON.stringify(req.body);
        const requestBody = JSON.stringify(req.body); // Assuming req.body is parsed JSON, stringify for validation

        const expectedSignature = crypto
            .createHmac("sha256", webhookSecret)
            .update(requestBody)
            .digest("hex");

        if (expectedSignature !== receivedSignature) {
            console.error("Invalid webhook signature.");
            return res.status(400).send("Invalid signature.");
        }

        console.log("Webhook signature verified successfully.");

        // 2. Process the Event Payload
        const event = req.body.event; // e.g., 'payment.captured'
        const paymentEntity = req.body.payload?.payment?.entity;

        console.log("Event:", event);
        // console.log("Payment Entity:", paymentEntity); // Log carefully, may contain sensitive info

        // 3. Handle 'payment.captured' Event
        if (event === 'payment.captured' && paymentEntity && paymentEntity.status === 'captured') {
            const razorpayOrderId = paymentEntity.order_id;
            const razorpayPaymentId = paymentEntity.id;
            const amountPaid = paymentEntity.amount; // Amount in paise
            const currencyPaid = paymentEntity.currency;

            if (!razorpayOrderId) {
                console.error("Webhook Error: Razorpay Order ID missing in payload.");
                return res.status(400).send("Order ID missing.");
            }

            console.log(`Processing captured payment for Razorpay Order ID: ${razorpayOrderId}`);

            // 4. Find corresponding transaction in Firestore using razorpayOrderId
            const transactionsRef = db.collection('transactions');
            const querySnapshot = await transactionsRef.where('razorpayOrderId', '==', razorpayOrderId).limit(1).get();

            if (querySnapshot.empty) {
                console.error(`Webhook Error: No transaction found with Razorpay Order ID ${razorpayOrderId}`);
                // Respond 200 OK to Razorpay anyway, as we can't retry this easily if the order ID was wrong.
                return res.status(200).send("Transaction not found, but webhook acknowledged.");
            }

            const txDoc = querySnapshot.docs[0];
            const txData = txDoc.data();

            // 5. Validate Amount and Status (optional but recommended)
            if (txData.status !== 'awaiting_payment') {
                 console.warn(`Webhook Warning: Received payment webhook for transaction ${txDoc.id} which is not awaiting payment (status: ${txData.status}). Ignoring.`);
                 return res.status(200).send("Webhook acknowledged, but transaction status mismatch.");
            }
            if (amountPaid !== Math.round(txData.amount * 100)) {
                 console.warn(`Webhook Warning: Payment amount mismatch for transaction ${txDoc.id}. Expected ${Math.round(txData.amount * 100)}, received ${amountPaid}. Ignoring.`);
                 return res.status(200).send("Webhook acknowledged, but amount mismatch.");
            }


            // 6. Update Firestore Transaction Status
            console.log(`Updating transaction ${txDoc.id} status to awaiting_shipment.`);
            await txDoc.ref.update({
                status: 'awaiting_shipment',
                razorpayPaymentId: razorpayPaymentId, // Store payment ID for reference
                buyerConfirmedPayment: true, // Mark payment as confirmed
                paymentCapturedAt: admin.firestore.FieldValue.serverTimestamp() // Record time
            });

            console.log(`Transaction ${txDoc.id} updated successfully.`);
            // Respond 200 OK to Razorpay to acknowledge receipt
            return res.status(200).send("Webhook processed successfully.");

        } else {
            // Handle other events or payment statuses if needed
            console.log(`Webhook received for event '${event}', status '${paymentEntity?.status}'. No action taken.`);
            return res.status(200).send("Webhook received, no action needed.");
        }

    } catch (error) {
        console.error("Error processing Razorpay webhook:", error);
        // Don't send detailed errors back to Razorpay
        return res.status(500).send("Internal server error processing webhook.");
    }
    // }); // End CORS wrapper if used
}); // End verifyRazorpayPayment function
