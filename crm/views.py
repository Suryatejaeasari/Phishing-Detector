from django.http import HttpResponse
from django.shortcuts import render
from tensorflow import keras 
import re
from urllib.parse import urlparse


# First Directory Length
def fd_length(url):
    urlpath = urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0


def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits


def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters


def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')


# Use of IP or not in domain
def having_ip_address(url):
    match = re.search(
        # IPv4 in hexadecimal
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        # print match.group()
        return -1
    else:
        # print 'No matching pattern found'
        return 1



def hostname_length(url):
    return len(urlparse(url).netloc)

def url_length(url):
    return len(urlparse(url).path)


# Gets all count features
def get_counts(url):

    count_features = []

    i = url.count('-')
    count_features.append(i)

    i = url.count('@')
    count_features.append(i)

    i = url.count('?')
    count_features.append(i)


    i = url.count('%')
    count_features.append(i)

    i = url.count('.')
    count_features.append(i)

    i = url.count('=')
    count_features.append(i)

    i = url.count('http')
    count_features.append(i)

    i = url.count('https')
    count_features.append(i)

    i = url.count('www')
    count_features.append(i)

    return count_features






def extract_features(url):
    url_features = []

    # hostname length
    i = hostname_length(url)
    url_features.append(i)

    # path length
    i = url_length(url)
    url_features.append(i)

    i = fd_length(url)
    url_features.append(i)

    i = get_counts(url)
    url_features = url_features + i

    i = digit_count(url)
    url_features.append(i)

    i = letter_count(url)
    url_features.append(i)

    i = no_of_dir(url)
    url_features.append(i)

    i = having_ip_address(url)
    url_features.append(i)

    return url_features

def get_prediction(url, model_path):
    #print("Loading the model...")
    model = keras.models.load_model(model_path)

    #print("Extracting features from url...")
    url_features = extract_features(url)
    #print(url_features)

    #print("Making prediction...")
    prediction = model.predict([url_features])
    i = prediction[0][0] * 100
    i = round(i,3)
    if i >=50 :
        print("There is ",i,"% chance,the url is malicious !")
        #a = "There is ",i,"% chance,the url is malicious !"
    else:
        print("The url is not malicious")
        #a = "The url is not malicious"

    return i

def home(request):
    return render(request, "home.html")

def result(request):
    # Load the Keras model
    #model = keras.models.load_model('Malicious_URL_Prediction.h5')
    model_path = "Malicious_URL_Prediction.h5"

# input url
    url = request.GET.get('url-in','')
    print("hell",url)
    #print("hello")
    #url = "www.google.com"    #print(url)


    try:
    # Get the prediction using the get_prediction function
        prediction = get_prediction(url, model_path)
    
    # Print the prediction
        print(f"Probability of URL being malicious: {prediction}")
        # b = f"Probability of URL being malicious: {prediction}"
        b = f"{prediction}"
    except Exception as e:
    # Handle any exceptions that may occur
        print(f"An error occurred: {str(e)}")
        b = f"An error occurred: {str(e)}"
    j = prediction
    j = round(j,3)
    if j>=50:
        a = f"Yes"
        # a = f"Malicious"
    else:
        a = f"Not"
        # a = f"Not malicious"
    return render(request, "result.html", {'a': a, 'b': b})


    # Get the user input (URL) from the request's GET parameters
    user_url = request.GET.get('RI', '')  # Assuming 'RI' is the name of the input field in your form
    result=get_prediction(user_url,model)
    print(result)

    # You can choose to print the user input or process it in any way you like here

    # Comment out the prediction-related code to keep it inactive
    # Perform feature extraction on the user URL (you may need to implement this)
    url_features = extract_features(user_url)  # Implement extract_features as needed

    # Make predictions using the model
    #prediction = model.predict([url_features])

    # Assuming 'prediction' is the probability of being malicious (0 to 1)
    # You can convert it to a more user-friendly message or format
    #probability = prediction[0][0] * 100
    #probability = round(probability, 3)

    # Create a context dictionary to pass data to the template
    #context = {
        #'user_url': user_url,
        # 'probability': probability,
    #}
    
