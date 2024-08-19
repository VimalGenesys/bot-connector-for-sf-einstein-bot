from Amfampoc_Automate_BYOB2MS import lambda_handler, make_or_touch_bot_session, create_conversation_session
# , , send_text_message, convert_ms_response_to_byob

import json

# Sample input data
sample_event = {
    'body': {
        'botSessionId': 'sampleSessionId',
        'inputMessage': {'text': 'Hello!'}
    },
    'headers': {
        'Authorization': 'Bearer valid_token'
    }
}

def test_lambda_handler():
    result = lambda_handler(sample_event, None)
    print('Lambda Handler Result:')
    print(json.dumps(result, indent=4))

def test_make_or_touch_bot_session():
    bot_session = make_or_touch_bot_session(sample_event['body'])
    print('Make or Touch Bot Session Result:')
    print(bot_session)

def test_create_conversation_session():
    bot_session = sample_event['body']
    session_id = create_conversation_session(bot_session)
    print('Create Conversation Session Result:')
    print(session_id)

def test_send_text_message():
    session_id = 'sampleServiceSessionId'
    result = send_text_message(sample_event['body'], session_id)
    print('Send Text Message Result:')
    print(json.dumps(result, indent=4))

def test_convert_ms_response_to_byob():
    ms_response = {
        'activities': [
            {'type': 'message', 'text': 'Sample response from bot'}
        ]
    }
    bot_session = {'serviceSessionId': 'sampleServiceSessionId'}
    result = convert_ms_response_to_byob(ms_response, bot_session)
    print('Convert MS Response to BYOB Result:')
    print(json.dumps(result, indent=4))

if __name__ == '__main__':
    # test_lambda_handler()
    # test_make_or_touch_bot_session()
    test_create_conversation_session()
    # test_send_text_message()
    # test_convert_ms_response_to_byob()

