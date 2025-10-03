# Secure Overlay Chat Protocol (SOCP)


## ⚙️ Installation

- Clone the repo 

```bash
git clone git@github.com:aniketrattan/secure-programming.git
cd secure-programming
```


- Create a virtual environment 
```bash
python3 -m venv venv
source venv/bin/activate   # Linux / Mac
venv\Scripts\activate      # Windows
```


- Install dependencies
```bash
pip install -r integration/requirements.txt
```


## ▶️ Running

### Start the server
```bash
python -m integration.run_server
```


### Start the client
```bash
python -m integration.run_client
```


## Client commands

### Register
```
/register

## Output:
## Register for new user id <auto_generated_user_id>
## Create password: <enter_your_password>
```

### Login

```
/login <user_id>

## Output:
## Enter password: <enter_your_password>
```

On login success, the terminal will display `[LOGIN SUCCESS]`, otherwise `[LOGIN FAILED]`.


### List online users
```
/list
```

This will return a sorted list of user ids of online users.


### Direct message
```bash
/tell <user_id> <message>
```

Send a direct message  with content `<message>` to user `<user_id>`.

Receiver will receive DM notification as

```
DM from <sender_user_id>: <message>

```

### File transfer

```bash
/file <recipient_id> <filepath>
```

Send the file from `<filepath>` to user with user id `<recipient_id>`
