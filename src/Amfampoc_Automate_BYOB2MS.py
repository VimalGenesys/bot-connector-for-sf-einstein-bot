import os
import http.client
import json
import time
import logging
import bot_sessions
import uuid



# Token information
SF_BOT_AUTHORIZATION_SECRET = None
TOKEN_EXPIRATION = None  # Stores the expiration timestamp

# Logging setup
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

def retrieve_salesforce_token():
    """Retrieve the Salesforce OAuth token and store it in MS_BOT_AUTHORIZATION_SECRET with expiration time."""
    global SF_BOT_AUTHORIZATION_SECRET, TOKEN_EXPIRATION
    
    # Load client credentials from environment variables
    client_id = os.getenv("SALESFORCE_CLIENT_ID")
    client_secret = os.getenv("SALESFORCE_CLIENT_SECRET")
    domain_name = os.getenv("SALESFORCE_DOMAIN_NAME")
    
    if not client_id:
        logger.error("Salesforce client ID not set in environment variables.")
        raise EnvironmentError("Missing Salesforce client ID in environment variables.")
    if not client_secret:
        logger.error("Salesforce client secret not set in environment variables.")
        raise EnvironmentError("Missing Salesforce client secret in environment variables.")
    if not domain_name:
        logger.error("Salesforce domain name not set in environment variables.")
        raise EnvironmentError("Missing Salesforce domain name in environment variables.")
    
    # Define the payload
    payload = f'grant_type=client_credentials&client_id={client_id}&client_secret={client_secret}'
    
    # Headers for the request
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    # Making the request
    conn = http.client.HTTPSConnection(domain_name)
    conn.request("POST", "/services/oauth2/token", payload, headers)
    res = conn.getresponse()
    data = res.read()
    conn.close()
    
    # Parse the token from the response
    token_response = json.loads(data.decode("utf-8"))    
    if 'access_token' in token_response:
        SF_BOT_AUTHORIZATION_SECRET = f"Bearer {token_response['access_token']}"
        TOKEN_EXPIRATION = time.time() + 3600  # Assuming token is valid for 1 hour
        logger.info("Successfully retrieved Salesforce OAuth token.")
    else:
        logger.error("Failed to retrieve Salesforce OAuth token.")
        raise ValueError("Invalid response when retrieving Salesforce token.")

def is_token_expired():
    """Check if the current token is expired or about to expire."""
    global TOKEN_EXPIRATION
    return TOKEN_EXPIRATION is None or time.time() > TOKEN_EXPIRATION

def lambda_handler(event, context):
    logger.info('Event:')
    logger.info(json.dumps(event))
    #print('event:' + str(event))
    
    if 'body' not in event or type(event['body']) is not dict:
        return {
            "errorInfo":
                {
                    "errorCode": 500,
                    "errorMessage": "event input is malformed"
                }
        }

    if 'headers' not in event or type(event['headers']) is not dict:
        return {
            "errorInfo":
                {
                    "errorCode": 500,
                    "errorMessage": "event input is malformed"
                }
        }

    if 'Authorization' not in event['headers']:
        print("bad secret - " + str(event))
        return {
            "errorInfo":
                {
                    "errorCode": 403,
                    "errorMessage": "Unauthorized secret",
                    "event": str(event),
                }
        }

    try:
        event_body = event['body']
        bot_session = make_or_touch_bot_session(event_body)
        print ('bot_session:' + str(bot_session))

        if 'serviceSessionId' in bot_session:
            print("serviceSessionId - " + bot_session['serviceSessionId'])
            session_id = bot_session['serviceSessionId']
        else:
            # Didn't have a session - we'll treat this as a new one
            print("Didn't have a session - we'll treat this as a new one")

        

        print ('Calling create_conversation_session()')
        session_id = create_conversation_session(bot_session)
    
        # Retrieve the token if it's expired or not yet retrieved
        if is_token_expired():
            retrieve_salesforce_token()

    
    # # Example usage of the do_http_call_with_token_refresh function
    # try:
    #     response_data = do_http_call_with_token_refresh(
    #         method="POST",
    #         uri_host="some-api-host.com",
    #         uri_path="/some/api/endpoint",
    #         body=json.dumps({"key": "value"}),
    #         headers={"Content-Type": "application/json"}
    #     )
    #     logger.info("Response from API: " + response_data)
        
    #     # Continue processing with the response...
    
    # except Exception as ex:
    #     logger.error("Failed to process request: " + str(ex))
    #     return {
    #         "errorInfo": {
    #             "errorCode": 500,
    #             "errorMessage": "Failed to process request"
    #         }
    #     }

    # Proceed with the rest of your lambda_handler code...

    except SyntaxError as error:
        print("SyntaxError - " + str(error.text))
        return {
            "errorInfo":
            {
                "errorCode": "400",
                "errorMessage": error.text,
                "event": str(event)
            }
        }
    except Exception as ex:
        print("Exception - " + str(ex))
        return {
            "errorInfo":
                {
                    "errorCode": "400",
                    "errorMessage": ex,
                    "event": str(event)
                }
        }

    

# Rest of the script...

def make_or_touch_bot_session(event):
    """
    Create the bot session if it doesn't exist.. or else update it by incrementing its touchCount and return it for
    subsequent accesses.
    """
    bot_session = dict()
    bot_session['botSessionId'] = event['botSessionId']
    bot_session['expireAt'] = bot_sessions.aws_expire_at_seconds(60 * 5)  # convert min to sec here

    
    bot_session = bot_sessions.BYOB2MSHandlerSessions.update_session(bot_session, False)
    
    if bot_session is None:
        raise SyntaxError('bot session creation failed')

    return bot_session

def create_conversation_session(bot_session):
    # Load client credentials from environment variables
    sf_runtime_base_host = os.getenv("SALESFORCE_RUNTIME_BASEHOST")
    sf_botid = os.getenv("SALESFORCE_BOTID")
    sf_forceconfigendpoint = os.getenv("SALESFORCE_FORCECONFIGENDPOINT")
    sf_orgid = os.getenv("SALESFORCE_ORGID")
    
    if not sf_runtime_base_host:
        logger.error("SALESFORCE_RUNTIME_BASEHOST not set in environment variables.")
        raise EnvironmentError("Missing SALESFORCE_RUNTIME_BASEHOST in environment variables.")
    if not sf_botid:
        logger.error("SALESFORCE_BOTID not set in environment variables.")
        raise EnvironmentError("Missing SALESFORCE_BOTID in environment variables.")
    if not sf_forceconfigendpoint:
        logger.error("SALESFORCE_FORCECONFIGENDPOINT not set in environment variables.")
        raise EnvironmentError("Missing SALESFORCE_FORCECONFIGENDPOINT in environment variables.")
    if not sf_orgid:
        logger.error("SALESFORCE_ORGID not set in environment variables.")
        raise EnvironmentError("Missing SALESFORCE_ORGID in environment variables.")
    
    uri_host = sf_runtime_base_host
    uri_path = "/v5.1.0/bots/"+ sf_botid + "/sessions"
    
    # Define the payload for the request
    payload = json.dumps({
        "forceConfig": {
            "endpoint": sf_forceconfigendpoint
        },
        "externalSessionKey": bot_session['botSessionId']
    })
    
    # Define the headers for the request
    headers = {
        'X-Org-Id': sf_orgid,
        'X-Request-ID': str(uuid.uuid4()),
        'Content-Type': 'application/json',
        'Authorization': SF_BOT_AUTHORIZATION_SECRET  # Use the managed token
    }
    
    # Make the API call with token refresh handling
    data,response_headers = do_http_call(
        method="POST",
        uri_host=uri_host,
        uri_path=uri_path,
        body=payload,
        headers=headers
    )

    # Process the response
    responsevalue = json.loads(data)
    responseheadervalue = dict(response_headers)    

    # Ensure the response contains the required information
    if 'sessionId' not in responsevalue:
        raise SyntaxError("No 'sessionId' returned from SF Bot")
    # Ensure the response contains the required information
    if 'x-runtime-crc' not in responseheadervalue:
        raise SyntaxError("X-Runtime-CRC header not found from SF Bot")


    # Update our bot_session with the necessary values
    session_id = responsevalue['sessionId']
    bot_session['serviceSessionId'] = session_id
    bot_session['xRuntimeCrc'] = responseheadervalue['x-runtime-crc']

    # Update the session in your custom session handler
    bot_session = bot_sessions.BYOB2MSHandlerSessions.update_session(bot_session)

    return session_id


def http_client_request_with_raise(connection, method, url, body=None, headers={}, *, encode_chunked=False, log_body_on_error=False, retry_on_unauthorized=True):
    """
    A helper method that wraps the native http.client.HTTPSConnection::request() method and transforms the
    HTTP result into an exception if it's a non-2xx status, which is generally what callers want.  It returns
    the full response object if it's a 2xx range status

    :param connection: an instance of an http.client.HTTPSConnection object
    :param method: the HTTP method, such as GET/PUT/POST/etc
    :param url: the URL to request, which should begin with a leading slash
    :param body: the body to send, or None to omit the body
    :param headers: headers to send, or None to omit extra headers
    :param encode_chunked: True or False based on your chosen encoding style
    :param log_body_on_error: if True, print out the body (if available) on error
    :return: the HTTP response object for 2xx statuses
    """
    if connection is None or type(connection) is not http.client.HTTPSConnection:
        # You're likely mis-using this method.. it's intended to be used with an HTTPSConnection object
        raise SyntaxError("Bad HTTPS connection object in request")

    global SF_BOT_AUTHORIZATION_SECRET
    
    if SF_BOT_AUTHORIZATION_SECRET is None or is_token_expired():
        retrieve_salesforce_token()

    # Set Authorization header
    headers['Authorization'] = SF_BOT_AUTHORIZATION_SECRET


    connection.request(method, url, body=body, headers=headers, encode_chunked=encode_chunked)
    res = connection.getresponse()
    if res is None:
        raise SyntaxError("HTTPS request returned no response")

    if 200 <= res.status <= 299:
        # This is good, a success. return the res object
        return res

    if log_body_on_error:
        # NOTE that we don't read the body unless we're asked to, because the body can only be read once. If the
        # caller is going to read the body then he can't let us do it here.
        try:
            body = res.read().decode('utf-8')
            print(body)
        except Exception as ex:
            body = 'Cannot ready body, exception ' + str(ex)
            print(body)

    # A non-2xx response
    # If we receive a 401 Unauthorized, refresh the token and retry the request once
    if res.status == 401 and retry_on_unauthorized:
        logger.warning("401 Unauthorized received. Attempting to refresh the token.")
        retrieve_salesforce_token()
        headers['Authorization'] = SF_BOT_AUTHORIZATION_SECRET
        http_client_request_with_raise(connection, method, url, body=body, headers=headers,log_body_on_error=True, retry_on_unauthorized=False)
    if res.status == 429:  # Too Many Requests
        raise SyntaxError("Too Many Requests")
    if res.status == 503:  # Service Unavailable
        raise SyntaxError("Service Unavailable")
    if res.status == 504:  # Gateway Timeout
        raise SyntaxError("Gateway Timeout")
    raise SyntaxError(res)


def do_http_call(method, uri_host, uri_path, body=None, headers={}):
    conn = None
    try:
        conn = http.client.HTTPSConnection(uri_host, timeout=11)

        res = http_client_request_with_raise(conn, method, uri_path, body=body, headers=headers,
                                             log_body_on_error=True)

        # res will get deleted on conn close (in finally below) we copy it to data here
        data = res.read().decode('utf-8')
        response_headers = res.getheaders()  # Get the response headers
        return data, response_headers

    except SyntaxError:
        raise
    except Exception as ex:
        raise SyntaxError(str(ex))
    finally:
        # Attempt to close the connection, we're done with it
        if conn is not None:
            try:
                conn.close()
            except Exception:
                # Ignore exceptions closing the connection - make this a best effort
                pass
