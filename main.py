import requests
import datetime
from flask import Flask, render_template, request, jsonify, redirect, flash
import re
from flask import Flask, session, redirect, url_for, escape, request
from controller import generate_card_number
from dateutil import parser

app = Flask(__name__)
app.secret_key = 'not-yet-defined'
global access_token
API_ENDPOINT = "https://charityplus.tech/api/v1"
DOMAIN = "https://charityplus.tech"
limit = 100

@app.route('/home')
def home():
    return render_template('home.html')


@app.route('/',methods=['GET','POST'])
def index():
    global access_token
    if request.method=='POST':
        email = request.form['email']
        password = request.form['password']
        loginEndPoint = f"{DOMAIN}/login?limit={limit}"
        payload = {
            "email": str(email),
            "password": str(password)
        }
        print(payload)

        response = requests.post(loginEndPoint, json=payload)

        if response.ok:
            print(response.json()['token'])
            access_token = response.json()['token']
            session['access_token']=access_token
            return redirect("/user",code=200)
        else:
            flash('Invalid email or password. Please try again.', 'error')
            return render_template('index.html')

    return render_template('index.html')

@app.route('/user', methods=['GET', 'POST'])
def user():
    headers = {"Authorization": f"Bearer {session['access_token']}"}
    response = requests.get(f"{API_ENDPOINT}/users?limit={limit}", headers=headers)
    print(response.json())
    usersData = response.json()['data']

    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        conf_password = request.form['confirm_password']
        role = request.form['role']
        if(password!=conf_password):
            flash("Password didn't match")
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password):
            flash('Password must be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, one digit, and one special character.')

        # Create the payload
        payload = {
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "password": password,
            "role": role
        }

        # Send the POST request to the API
        response = requests.post(f"{API_ENDPOINT}/users/", json=payload)

        # Print the response text

        if response.ok:
            flash('User created successfully!')
        else:
            flash(f'Error creating user: {response.text}')

    return render_template('users.html',usersData=usersData)


@app.route('/client', methods=['GET', 'POST'])
def client():
    headers = {"Authorization": f"Bearer {session['access_token']}"}
    users_url = f"{API_ENDPOINT}/users?limit={limit}"
    merchants_url = f"{API_ENDPOINT}/merchants?limit={limit}"
    response = requests.get(users_url, headers=headers)
    activeMerchants = requests.get(merchants_url, headers=headers)

    if response.status_code == 401:
        flash('Invalid access token')
    elif response.status_code == 403:
        flash('Forbidden access')
    elif response.status_code == 404:
        flash('Not Found')
    elif response.status_code == 200:
        user_ids = [[user['id'], user['email'], user['role']] for user in response.json()['data'] if user['role'] in ['merchant']]
        activeTempMerchants = [user['User']['email'] for user in activeMerchants.json()['data']]
        pendingMerchants = []
        for i in user_ids:
            if i[1] not in activeTempMerchants:
                pendingMerchants.append([i[0],i[1]])

        if request.method == 'POST':
            merchant_name = request.form['merchant_name']
            location = request.form['location']
            user_id = request.form['user_id']
            data = {
                'merchant_name': merchant_name,
                'location': location,
                'user_id': int(user_id)
            }
            print(data)
            response = requests.post(merchants_url, headers=headers, json=data)

            if response.ok:
                flash('Success')
            else:
                flash(f'Error: {response.text}')
        else:
            return render_template('clients.html', user_ids=pendingMerchants,activeMerchants=activeMerchants.json()['data'])


@app.route('/card', methods=['GET', 'POST'])
def card():
    headers = {"Authorization": f"Bearer {session['access_token']}"}
    response = requests.get(f"{API_ENDPOINT}/users?limit={limit}", headers=headers)

    if response.status_code == 401:
        return jsonify({'error': 'Invalid access token'}), 401
    elif response.status_code == 403:
        return jsonify({'error': 'Forbidden access'}), 403
    elif response.status_code == 404:
        return jsonify({'error': 'Not found'}), 404
    elif response.status_code == 200:
        user_ids = [[user['id'], user['email']] for user in response.json()['data'] if user['role'] in ['user']]
        activeUsers = requests.get(f"{API_ENDPOINT}/subscriptions?limit={limit}", headers=headers)
        usersData = []
        for i in activeUsers.json()['data']:
            s = i['number']
            s = s[:4] + " xxxx xxxx " + s[-4:]

            usersData.append(
                [i['id'], s, i['User']['first_name'] + ' ' + i['User']['last_name'], parser.parse(i['CreatedAt']).strftime("%B %d, %Y"), i["card_name"],
                 i['User']['role']])
        cardsAlloted = [user['user_id'] for user in activeUsers.json()['data']]
        users_not_alloted = []
        for user in user_ids:
            if user[0] not in cardsAlloted:
                users_not_alloted.append(user)


        usersPending = len(users_not_alloted)

        if request.method == 'POST':
            user_id = request.form['user_id']
            card_plan = request.form['user_plan']
            card_number = generate_card_number()

            payload = {
                "user_id": int(user_id),
                "number": str(card_number),
                "card_name":str(card_plan)
            }

            response = requests.post(f"{API_ENDPOINT}/subscriptions", json=payload, headers=headers)

            if response.ok:
                flash('Card added successfully!')
            else:
                flash(f'Error adding card: {response.text}')

        return render_template('cards.html', user_ids=users_not_alloted, usersData=usersData,usersPending=usersPending)


@app.route('/offers',methods=['GET','POST'])
def offers():
    headers = {"Authorization": f"Bearer {session['access_token']}"}
    allOffers = requests.get(f"{API_ENDPOINT}/offers?limit={limit}", headers=headers).json()['data']
    activeMerchants = requests.get(f"{API_ENDPOINT}/merchants?limit={limit}", headers=headers).json()['data']

    if request.method == 'POST':
        merchID = request.form['merchantid']
        cardPlan = request.form['cardPlan']
        discountValue = request.form['discountValue']
        data = {
            "card_name": str(cardPlan),
            "discount_rate": int(discountValue),
            "merchant_info_id": int(merchID)
        }
        response = requests.post(f"{API_ENDPOINT}/offers", headers=headers, json=data)
        if response.ok:
            flash("Offer added")
        else:
            flash(f'Error: {response.text}')

    return render_template('offers.html', activeMerchants=activeMerchants, allOffers=allOffers)


@app.route('/user-application', methods=['GET', 'POST'])
def onBoardUser():
    headers = {"Authorization": f"Bearer {session['access_token']}"}
    response = requests.get(f"{API_ENDPOINT}/users?limit={limit}", headers=headers)

    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        conf_password = request.form['confirm_password']
        role = request.form['role']

        if password != conf_password:
            return "<script>alert('Password didn\\'t match');</script>"

        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password):
            return "<script>alert('Password must be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, one digit, and one special character.');</script>"

        payload = {
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "password": password,
            "role": role
        }

        response = requests.post(f"{API_ENDPOINT}/users/", json=payload)

        if response.ok:
            return "<script>alert('User created successfully!');</script>"
        else:
            return f"<script>alert('Error creating user: {response.text}');</script>"

    return render_template('user-application.html')


@app.route('/transactions')
def transaction():
    headers = {"Authorization": f"Bearer {session['access_token']}"}
    allTransactions = requests.get(f"{API_ENDPOINT}/transactions?limit={limit}", headers=headers)
    print(allTransactions.json())
    allTransactions = allTransactions.json()['data']
    print(allTransactions)
    dataDisplay = []
    for i in allTransactions:
        dataDisplay.append([i['id'], i['CardSubscription']['User']['first_name']+' '+i['CardSubscription']['User']['last_name'], i['MerchantOffer']['MerchantInfo']['merchant_name'] ,i['CardSubscription']['number'],i['amount'], int(i['amount']) * (int(i['MerchantOffer']['discount_rate'])/100), i['created_at']])
    return render_template('transactions.html',dataDisplay=dataDisplay)


@app.route('/userprofile',methods=['GET','POST'])
def userprofile():
    headers = {"Authorization": f"Bearer {session['access_token']}"}
    response = requests.get(f"{API_ENDPOINT}/users?limit={limit}", headers=headers)
    usersData = response.json()['data']
    print(usersData)
    userInfo = []
    for i in usersData:
        if(i['role']=="user"):
            userInfo.append([i['id'],i['first_name']+" "+i["last_name"],i['email'],i['created_at']])
    userProfile = []
    dataDisplay=[]
    if request.method == 'POST':
        user_id = request.form['user_id']
        headers = {"Authorization": f"Bearer {session['access_token']}"}
        response = requests.get(f"{API_ENDPOINT}/subscriptions?limit={limit}", headers=headers)

        print("-------",response.json()['data'])

        for i in response.json()['data']:
            if(int(i['User']['id'])==int(user_id)):
                userProfile= [
                    i['id'],
                    i['number'],
                    i['User']['first_name'] + " " + i['User']['last_name'],
                    i['User']['email'],
                    i['card_name'],
                    i['CreatedAt']
                ]

        allTransactions = requests.get(f"{API_ENDPOINT}/transactions?limit={limit}", headers=headers)
        allTransactions = allTransactions.json()['data']
        dataDisplay = []
        for i in allTransactions:
            if(int(user_id)==int(i['CardSubscription']['User']['id'])):
                dataDisplay.append(
                    [i['id'], i['CardSubscription']['User']['first_name'] + ' ' + i['CardSubscription']['User']['last_name'],
                     i['MerchantOffer']['MerchantInfo']['merchant_name'], i['CardSubscription']['number'], i['amount'],
                     int(i['amount']) * (int(i['MerchantOffer']['discount_rate']) / 100), i['created_at']])

    return render_template('userprofile.html',userInfo=userInfo, userProfile=userProfile,dataDisplay=dataDisplay)


if __name__ == '__main__':
    app.run(debug=True)
