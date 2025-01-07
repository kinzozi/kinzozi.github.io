from flask import Flask, render_template, request, jsonify, session, redirect, Response, stream_with_context
import os
from openai import OpenAI
from datetime import datetime, timedelta
import json
import time
import re

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session management
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS

# Initialize OpenAI client
client = OpenAI()  # Will automatically use OPENAI_API_KEY from environment

# Store conversation history in session instead of memory
def get_conversation_history():
    if 'conversation_history' not in session:
        session['conversation_history'] = []
    return session['conversation_history']

# Create an assistant for learning content generation
def create_assistant():
    assistant = client.beta.assistants.create(
        name="Learning Content Generator",
        instructions="""You are "Socrates," a highly intelligent learning guide whose purpose is to help users deeply understand any topic they choose. You excel at asking insightful questions that help users clarify their goals and tailor the learning experience to their specific needs.

**Your Guiding Principles:**

*   **Be insightful and perceptive:** Your questions should demonstrate a deep understanding of the topic and the user's potential needs.
*   **Be adaptable:** Tailor your approach based on the user's input and responses.
*   **Be supportive and encouraging:** Foster a positive and engaging learning environment.
*   **Be accurate and reliable:** Provide accurate information and avoid making unsubstantiated claims.
*   **Help the user decide what they are looking for if they are unsure:** If they are unsure, help them figure out what exactly they are looking for.

Your goal is to create a truly personalized and effective learning journey that empowers users to master any topic they desire.

# Output Format

- Responses should be formatted with inline HTML tags, designed to fit directly into an existing webpage structure without additional page elements. 

- When responding, ensure all educational content follows the existing stylistic elements and structure of webpages, using relevant HTML tags to demarcate content sections effectively.

- If there are bullet points in your response, they MUST be inside a <ul> with <li> tags.

- If there are numbered lists in your response, they MUST be inside a <ol> tag and use <li> tags.

- Use br tags to break up text into manageable paragraphs.

- Use <p> tags to wrap all text.

- Break up your questions at the end of the response with a <br> tag.
""",
        model="gpt-4-1106-preview",
        tools=[{"type": "code_interpreter"}]
    )
    return assistant

# Initialize the assistant
try:
    ASSISTANT_ID = create_assistant().id
except Exception as e:
    print(f"Error creating assistant: {e}")
    # For development, you might want to use a pre-created assistant ID
    ASSISTANT_ID = os.getenv('OPENAI_ASSISTANT_ID', 'default_assistant_id')

@app.route('/')
def dashboard():
    # Initialize empty conversation history if needed
    if 'conversation_history' not in session:
        session['conversation_history'] = []
    return render_template('dashboard.html', conversation=session['conversation_history'])

@app.route('/send_message', methods=['POST', 'GET'])
def send_message():
    # Set SSE headers for GET requests
    if request.method == 'GET':
        user_message = request.args.get('message', '')
        if not user_message:
            return jsonify({'error': 'No message provided'}), 400
            
        headers = {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'yes'
        }

        def generate():
            try:
                # Initialize thread if needed
                if 'learning_state' not in session:
                    thread = client.beta.threads.create()
                    session['learning_state'] = {
                        'thread_id': thread.id,
                        'state': 'conversing'
                    }
                    session.modified = True

                thread_id = session['learning_state']['thread_id']

                # Add user message to conversation history
                conversation_history = get_conversation_history()
                conversation_history.append({
                    'role': 'user',
                    'content': user_message,
                    'timestamp': datetime.now().strftime('%H:%M')
                })
                session.modified = True

                # Add message to thread
                client.beta.threads.messages.create(
                    thread_id=thread_id,
                    role="user",
                    content=user_message
                )

                # Run the assistant
                run = client.beta.threads.runs.create(
                    thread_id=thread_id,
                    assistant_id=ASSISTANT_ID
                )

                # Stream the response
                current_message = ""
                last_message_id = None
                
                while True:
                    run_status = client.beta.threads.runs.retrieve(
                        thread_id=thread_id,
                        run_id=run.id
                    )
                    
                    if run_status.status == 'completed':
                        messages = client.beta.threads.messages.list(
                            thread_id=thread_id,
                            order="desc",
                            limit=1
                        )
                        
                        if messages.data and messages.data[0].id != last_message_id:
                            assistant_message = messages.data[0].content[0].text.value
                            last_message_id = messages.data[0].id
                            
                            # Split message into HTML chunks while preserving tags
                            chunks = re.findall(r'(<[^>]+>|[^<]+)', assistant_message)
                            current_chunk = ""
                            
                            for chunk in chunks:
                                current_chunk += chunk
                                # Send chunk when we have a complete element or accumulated enough text
                                if chunk.startswith('</') or len(current_chunk) > 100:
                                    yield f"data: {json.dumps({'chunk': current_chunk, 'timestamp': datetime.now().strftime('%H:%M')})}\n\n"
                                    current_chunk = ""
                                    time.sleep(0.1)
                            
                            # Send any remaining content
                            if current_chunk:
                                yield f"data: {json.dumps({'chunk': current_chunk, 'timestamp': datetime.now().strftime('%H:%M')})}\n\n"
                            
                            # Add to conversation history
                            conversation_history = get_conversation_history()
                            conversation_history.append({
                                'role': 'assistant',
                                'content': assistant_message,
                                'timestamp': datetime.now().strftime('%H:%M')
                            })
                            session.modified = True
                            
                            yield f"data: {json.dumps({'done': True, 'timestamp': datetime.now().strftime('%H:%M')})}\n\n"
                        break
                    
                    elif run_status.status == 'failed':
                        yield f"data: {json.dumps({'error': 'Assistant run failed'})}\n\n"
                        break
                    
                    elif run_status.status in ['queued', 'in_progress']:
                        yield f"data: {json.dumps({'status': run_status.status})}\n\n"
                        time.sleep(0.5)

            except Exception as e:
                print(f"Error in generate: {e}")
                yield f"data: {json.dumps({'error': 'An error occurred processing your request'})}\n\n"

        return Response(stream_with_context(generate()), mimetype='text/event-stream', headers=headers)

    # Handle POST requests for non-streaming responses
    user_message = request.json.get('message', '')
    if not user_message:
        return jsonify({'error': 'No message provided'}), 400
        
    # Add user message to conversation history
    conversation_history = get_conversation_history()
    conversation_history.append({
        'role': 'user',
        'content': user_message,
        'timestamp': datetime.now().strftime('%H:%M')
    })
    session.modified = True

    try:
        # Initialize thread if needed
        if 'learning_state' not in session:
            thread = client.beta.threads.create()
            session['learning_state'] = {
                'thread_id': thread.id,
                'state': 'conversing'
            }
            session.modified = True

        # Add message to thread
        client.beta.threads.messages.create(
            thread_id=session['learning_state']['thread_id'],
            role="user",
            content=user_message
        )

        # Run the assistant
        run = client.beta.threads.runs.create(
            thread_id=session['learning_state']['thread_id'],
            assistant_id=ASSISTANT_ID
        )

        # Wait for completion
        while True:
            run_status = client.beta.threads.runs.retrieve(
                thread_id=session['learning_state']['thread_id'],
                run_id=run.id
            )
            if run_status.status == 'completed':
                break
            elif run_status.status == 'failed':
                raise Exception("Assistant run failed")
            time.sleep(0.5)

        # Get the response
        messages = client.beta.threads.messages.list(
            thread_id=session['learning_state']['thread_id']
        )
        assistant_message = messages.data[0].content[0].text.value

        # Handle content generation trigger
        if "GENERATE_CONTENT" in assistant_message:
            assistant_message = assistant_message.replace("GENERATE_CONTENT", "").strip()
            conversation_history = get_conversation_history()
            conversation_history.append({
                'role': 'assistant',
                'content': assistant_message,
                'timestamp': datetime.now().strftime('%H:%M')
            })
            session.modified = True
            return jsonify({
                'response': assistant_message,
                'redirect': '/learn',
                'timestamp': datetime.now().strftime('%H:%M')
            })

        # Regular response
        conversation_history = get_conversation_history()
        conversation_history.append({
            'role': 'assistant',
            'content': assistant_message,
            'timestamp': datetime.now().strftime('%H:%M')
        })
        session.modified = True
        return jsonify({
            'response': assistant_message,
            'timestamp': datetime.now().strftime('%H:%M')
        })

    except Exception as e:
        print(f"Error in send_message: {e}")
        return jsonify({'error': 'An error occurred processing your request'}), 500

@app.route('/learn')
def learn():
    if 'learning_state' not in session or session['learning_state']['state'] != 'generating':
        return redirect('/')

    # Create a thread for this learning session
    thread = client.threads.create()

    # Add the user's requirements to the thread
    prompt = f"""
    Generate learning content about {session['learning_state']['topic']}.
    Specific interests: {session['learning_state']['responses'][0]}
    Preferred learning style: {session['learning_state']['responses'][1]}
    
    Please provide the response in the following JSON format:
    {{
        "title": "The main title for the learning page",
        "toc": "HTML formatted table of contents with nested <ul> elements",
        "content": "The main content in HTML format"
    }}
    """

    # Add the message to the thread
    message = client.threads.messages.create(
        thread_id=thread.id,
        role="user",
        content=prompt
    )

    # Run the assistant
    run = client.threads.runs.create(
        thread_id=thread.id,
        assistant_id=ASSISTANT_ID
    )

    # Wait for the completion
    while True:
        run_status = client.threads.runs.retrieve(
            thread_id=thread.id,
            run_id=run.id
        )
        if run_status.status == 'completed':
            break

    # Get the assistant's response
    messages = client.threads.messages.list(
        thread_id=thread.id
    )
    
    # Parse the JSON response
    response_content = messages.data[0].content[0].text.value
    try:
        content_data = json.loads(response_content)
    except json.JSONDecodeError:
        content_data = {
            "title": "Error in Content Generation",
            "toc": "<ul><li>Error occurred</li></ul>",
            "content": "<p>There was an error generating the content. Please try again.</p>"
        }

    # Clear the learning state
    session.pop('learning_state', None)

    return render_template('template.html',
                         TITLE=content_data['title'],
                         TOC=content_data['toc'],
                         CONTENT=content_data['content'])

if __name__ == '__main__':
    app.run(debug=True) 