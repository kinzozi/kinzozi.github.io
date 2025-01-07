'''
Gateway LLM API

This is a LLM API that allows you to generate text using a custom model. 
Please use your Hugging Face API key to generate text within the Gateway LLM API interface. 
I will not be responsible for any actions you take with this program.

'''

from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.security import APIKeyHeader
from fastapi.responses import JSONResponse
import stripe
import secrets
import bcrypt
import sqlite3 #For this instance, sqlite3. Use PostgresQL, etc.. for cloud deployment. 
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import uvicorn
import requests
import time
import random

app = FastAPI()

# --- Configuration ---
# Replace with your actual keys and secrets
STRIPE_SECRET_KEY = ""  # Your Stripe Secret Key
STRIPE_WEBHOOK_SECRET = ""  # Your Stripe Webhook Secret
DATABASE = 'users.db'  # Or your database file
MODEL_ENDPOINT_URL = ""  # Your custom endpoint
HUGGINGFACE_API_TOKEN = ""  # Your Hugging Face API Token

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Stripe configuration
stripe.api_key = STRIPE_SECRET_KEY

# API Key Authentication
api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)

# --- Database setup ---
def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row  # This will allow you to access columns by name
    return db

def close_db_connection(db):
    if db is not None:
        db.close()

# Initialize the database (if it doesn't exist)
def init_db():
    db = get_db()
    # The table will be created manually using a DB tool
    close_db_connection(db)

@app.on_event("startup")
async def startup():
    init_db()

@app.on_event("shutdown")
async def shutdown():
    db = get_db()
    close_db_connection(db)

# --- API Key Authentication ---
async def get_api_key(api_key: str = Depends(api_key_header)):
    if not api_key:
        raise HTTPException(status_code=401, detail="API key missing")

    db = None
    try:
        db = get_db()
        cursor = db.cursor()

        # Retrieve user based on API key
        cursor.execute(
            "SELECT payment_status FROM users WHERE api_key=?",
            (api_key,)
        )
        user = cursor.fetchone()

        if not user:
            raise HTTPException(status_code=401, detail="Invalid API key")

        payment_status = user['payment_status']

        # Check if payment is completed
        if payment_status != 'completed':
            raise HTTPException(status_code=403, detail="Payment not completed")

        return api_key  # Return the validated API key

    finally:
        close_db_connection(db)

# --- Webhook handler ---
@app.post('/stripe_webhook')
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError as e:
        # Invalid payload
        raise HTTPException(status_code=400, detail=str(e))
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        raise HTTPException(status_code=400, detail=str(e))

    # Handle the event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        customer_id = session.get('customer')
        customer_email = session.get('customer_details', {}).get('email')  # Get email

        # Generate a unique API key
        api_key = secrets.token_urlsafe(32)

        # Hash the API key for secure storage
        hashed_api_key = bcrypt.hashpw(api_key.encode(), bcrypt.gensalt())

        # Store in the database
        db = None  # Initialize db
        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute(
                "INSERT INTO users (customer_id, api_key, hashed_api_key, email, payment_status) VALUES (?, ?, ?, ?, ?)",
                (customer_id, api_key, hashed_api_key, customer_email, 'completed')  # Store unhashed key and email
            )
            db.commit()
            print("User added to database")

        except sqlite3.IntegrityError:
            raise HTTPException(status_code=400, detail='Customer ID already exists')

        finally:
            close_db_connection(db)

    # Return a 200 response to acknowledge receipt of the event
    return JSONResponse(content={"status": "success"})

# --- API Endpoint ---
@app.post('/generate_text/', dependencies=[Depends(get_api_key)])  # API key validation
@limiter.limit("10/minute")
async def generate_text(request: Request):
    try:
        data = await request.json()
        prompt = data.get("prompt")
        if not prompt:
            raise HTTPException(status_code=400, detail="Prompt is required")

        # Use the requests library to interact with your custom endpoint
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {HUGGINGFACE_API_TOKEN}",  # Use your HF token
            "Content-Type": "application/json"
        }

        payload = {
            "inputs": prompt,
            "parameters": {
                "max_new_tokens": 1024  # Adjust as needed
            }
        }

        retries = 0
        max_retries = 3
        backoff_factor = 2

        while retries < max_retries:
            try:
                response = requests.post(MODEL_ENDPOINT_URL, headers=headers, json=payload)
                response.raise_for_status()  # Raise an exception for bad status codes

                return response.json()

            except requests.exceptions.RequestException as e:
                if isinstance(e, requests.exceptions.HTTPError) and response.status_code == 504:
                    retries += 1
                    wait_time = backoff_factor ** retries + random.uniform(0, 1)
                    print(f"Request timed out, retrying in {wait_time:.2f} seconds...")
                    time.sleep(wait_time)
                else:
                    raise HTTPException(status_code=500, detail=f"Error calling model endpoint: {e}")

        raise HTTPException(status_code=500, detail="Failed to generate text after multiple retries")

    except Exception as e:
        print(f"Error during text generation: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {e}")
#For testing event data, run '$ stripe trigger payment_intent.succeeded '
#For bridging api event to stripe, run '$ listen --forward-to localhost:5000/stripe_webhook
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000) #Run on port 5000