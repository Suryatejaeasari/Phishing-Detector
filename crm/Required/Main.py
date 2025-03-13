

from API import get_prediction

# path to trained model
model_path = r"D:/Projects/phishingDetectorWeb/Phishing-Attack-Domain-Detection/models/Malicious_URL_Prediction.h5"

# input url
url = input("Enter the URL you want to check for maliciousness: ")


try:
    # Get the prediction using the get_prediction function
    prediction = get_prediction(url, model_path)
    
    # Print the prediction
    print(f"Probability of URL being malicious: {prediction}")
except Exception as e:
    # Handle any exceptions that may occur
    print(f"An error occurred: {str(e)}")
