from flask import request
from flask import Flask,render_template
from extractFeatures import get_prediction

app = Flask(__name__)

@app.route('/')
def index():
    title = "Voror"
    return render_template("index.html", title=title, status = "Examine your URL", color='black', value = "")

@app.route('/url', methods=['POST'])
def handle_submit():
    title = "Voror"
    url = request.form.get("url")
    prediction = (get_prediction(url))
    prediction = int(prediction[0])
    print(prediction)
    if(prediction == 1):
        return render_template("index.html", title=title, status = "Legitimate URL", color='green', value = url)

    else:
        return render_template("index.html", title=title, status = "Phishing URL", color='red' , value = url)

    


if __name__ == "__main__":
    app.run(debug=True)