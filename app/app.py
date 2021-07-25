from flask import (
    Flask,
    request,
    render_template,
    make_response,
    jsonify,
    abort,
    redirect,
    session,
)
import datetime
import base64
import json
import requests
import uuid
import os


app = Flask(__name__)

app.secret_key = os.getenv("COOKIE_SECRET", "TEST_SECRET")

users = [
    {
        "id": "1822f21a-d720-4494-a31f-943bec140789",
        "username": "congon4tor",
        "role": "admin",
        "password": os.getenv("AMDIN_PASSWORD", "qwerty123"),
        "picture": "default.jpg",
    },
    {
        "id": "243eae36-621a-47a6-b306-841bbffbcac4",
        "username": "jellytalk",
        "role": "user",
        "password": "test",
        "picture": "default.jpg",
    },
    {
        "id": "9d6492e1-c73d-4231-add7-7ea285fc98a1",
        "username": "pinkykoala",
        "role": "user",
        "password": "test",
        "picture": "default.jpg",
    },
]

secrets = [
    {
        "id": "afce78a8-23d6-4f07-81f2-47c96ddb10cf",
        "name": "Flag",
        "value": os.getenv("FLAG", "TEST_FLAG"),
        "readers": ["1822f21a-d720-4494-a31f-943bec140789"],
        "writers": ["1822f21a-d720-4494-a31f-943bec140789"],
        "owner": "1822f21a-d720-4494-a31f-943bec140789",
    },
    {
        "id": "d2e0704c-55a5-4a63-aad5-849798283da5",
        "name": "Test 1",
        "value": "test secret",
        "readers": ["243eae36-621a-47a6-b306-841bbffbcac4"],
        "writers": ["243eae36-621a-47a6-b306-841bbffbcac4"],
        "owner": "243eae36-621a-47a6-b306-841bbffbcac4",
    },
    {
        "id": "491e16d2-fd2b-4965-bcb6-5931ef61ed5b",
        "name": "Test 2",
        "value": "test secret 2",
        "readers": ["9d6492e1-c73d-4231-add7-7ea285fc98a1"],
        "writers": ["9d6492e1-c73d-4231-add7-7ea285fc98a1"],
        "owner": "9d6492e1-c73d-4231-add7-7ea285fc98a1",
    },
]


def create_user(id, username, role, password):
    if username in [user["username"] for user in users]:
        return False, "Username already exists"
    users.append(
        {
            "id": id,
            "username": username,
            "role": role,
            "password": password,
            "picture": "default.jpg",
        }
    )
    headers = {
        "Content-Type": "application/json",
    }
    payload = f"""{{"user":"{username}","role":"{role}"}}"""
    r = requests.put(
        url=f"http://localhost:8181/v1/data/users/{id}", headers=headers, data=payload
    )
    if r.status_code != 204:
        users.remove(
            {
                "id": id,
                "username": username,
                "role": role,
                "password": password,
                "picture": "default.jpg",
            }
        )
        return False, "Error creating user"
    return True, ""


def get_user(id):
    u = [user for user in users if user["id"] == id]
    if len(u) != 1:
        return None
    return [user for user in users if user["id"] == id][0]


def get_secrets(id):
    return [
        secret
        for secret in secrets
        if secret["owner"] == id or id in secret["readers"] or id in secret["writers"]
    ]


def get_secret(secret_id, user_id):
    secret = [secret for secret in secrets if secret["id"] == secret_id]
    if len(secret) != 1:
        return None, "Secret not found"

    headers = {
        "Content-Type": "application/json",
    }

    payload = f"""{{
        "input": {{
            "user":"{user_id}",
            "secret":"{secret_id}"
        }}
    }}"""

    r = requests.post(
        url=f"http://localhost:8181/v1/data/access/read",
        headers=headers,
        data=payload,
    )
    if r.status_code != 200:
        return None, "Forbiden"

    return secret[0].get("value"), None


def get_permissions(secret_id, user_id):
    secret = [secret for secret in secrets if secret["id"] == secret_id]
    if len(secret) != 1:
        return None, "Secret not found"

    headers = {
        "Content-Type": "application/json",
    }

    payload = f"""{{
        "input": {{
            "user":"{user_id}",
            "secret":"{secret_id}"
        }}
    }}"""

    r = requests.post(
        url=f"http://localhost:8181/v1/data/access/read",
        headers=headers,
        data=payload,
    )
    if r.status_code != 200:
        return None, "Forbiden"

    permissions = []
    for reader in secret[0].get("readers"):
        user = [user for user in users if user["id"] == reader]
        if len(user) != 1:
            continue
        permissions.append({"username": user[0].get("username"), "read": True})

    for writer in secret[0].get("writers"):
        user = [user for user in users if user["id"] == writer]
        if len(user) != 1:
            continue
        already = [u for u in permissions if u["username"] == user[0].get("username")]
        if len(already) != 1:
            permissions.append({"username": user[0].get("username"), "write": True})
        else:
            already[0]["write"] = True

    return permissions, None


def add_secret(secretId, name, value, owner):
    secret = {
        "id": secretId,
        "name": name,
        "value": value,
        "readers": [owner],
        "writers": [owner],
        "owner": owner,
    }

    secrets.append(secret)

    headers = {
        "Content-Type": "application/json",
    }
    payload = f"""{json.dumps(secret["readers"])}"""
    r = requests.put(
        url=f"http://localhost:8181/v1/data/readers/{secretId}",
        headers=headers,
        data=payload,
    )
    if r.status_code != 204 and r.status_code != 304:
        secrets.remove(secret)
        return False, "Error adding reader"

    payload = f"""{json.dumps(secret["writers"])}"""
    r = requests.put(
        url=f"http://localhost:8181/v1/data/writers/{secretId}",
        headers=headers,
        data=payload,
    )
    if r.status_code != 204 and r.status_code != 304:
        secrets.remove(secret)
        return False, "Error adding writer"
    return True, ""


def edit_secret(secret_id, value, user_id):
    secret = [secret for secret in secrets if secret["id"] == secret_id]
    if len(secret) != 1:
        return None, "Secret not found"

    headers = {
        "Content-Type": "application/json",
    }

    payload = f"""{{
        "input": {{
            "user":"{user_id}",
            "secret":"{secret_id}"
        }}
    }}"""

    r = requests.post(
        url=f"http://localhost:8181/v1/data/access/write",
        headers=headers,
        data=payload,
    )
    if r.status_code != 200:
        return None, "Forbiden"

    secret[0]["value"] = value

    return True, None


def add_reader(userId, secretId):
    secret = [secret for secret in secrets if secret["id"] == secretId][0]

    if userId in secret["readers"]:
        return False, "User already is a reader"
    secret["readers"].append(userId)

    headers = {
        "Content-Type": "application/json",
    }
    payload = f"""{json.dumps(secret["readers"])}"""
    r = requests.put(
        url=f"http://localhost:8181/v1/data/readers/{secretId}",
        headers=headers,
        data=payload,
    )
    if r.status_code != 204 and r.status_code != 304:
        secret["readers"].remove(userId)
        return False, "Error adding reader"
    return True, ""


def add_writer(userId, secretId):
    secret = [secret for secret in secrets if secret["id"] == secretId][0]

    if userId in secret["writers"]:
        return False, "User already is a writer"
    secret["writers"].append(userId)

    headers = {
        "Content-Type": "application/json",
    }
    payload = f"""{json.dumps(secret["writers"])}"""
    r = requests.put(
        url=f"http://localhost:8181/v1/data/writers/{secretId}",
        headers=headers,
        data=payload,
    )
    if r.status_code != 204 and r.status_code != 304:
        secret["writers"].remove(userId)
        return False, "Error adding writer"
    return True, ""


def remove_reader(userId, secretId):
    secret = [secret for secret in secrets if secret["id"] == secretId][0]

    if userId not in secret["readers"]:
        return False, "User is not a reader"
    secret["readers"].remove(userId)

    headers = {
        "Content-Type": "application/json",
    }
    payload = f"""{json.dumps(secret["readers"])}"""
    r = requests.put(
        url=f"http://localhost:8181/v1/data/readers/{secretId}",
        headers=headers,
        data=payload,
    )
    if r.status_code != 204 and r.status_code != 304:
        secret["readers"].append(userId)
        return False, "Error removing reader"
    return True, ""


def remove_writer(userId, secretId):
    secret = [secret for secret in secrets if secret["id"] == secretId][0]

    if userId not in secret["writers"]:
        return False, "User is not a writer"
    secret["writers"].remove(userId)

    headers = {
        "Content-Type": "application/json",
    }
    payload = f"""{json.dumps(secret["writers"])}"""
    r = requests.put(
        url=f"http://localhost:8181/v1/data/writers/{secretId}",
        headers=headers,
        data=payload,
    )
    if r.status_code != 204 and r.status_code != 304:
        secret["writers"].append(userId)
        return False, "Error removing writer"
    return True, ""


@app.route("/")
def index():
    if not session.get("id", None):
        return redirect("/signin?error=Please sign in")
    user_id = session.get("id")
    user = get_user(user_id)
    if not user:
        return redirect("/signin?error=Invalid session")
    secrets = get_secrets(user_id)
    error = request.args.get("error", None)
    success = request.args.get("success", None)
    return render_template(
        "index.html",
        user=user,
        secrets=secrets,
        error=error,
        success=success,
        users=users,
    )


@app.route("/signin", methods=["GET", "POST"])
def signin():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = [user for user in users if user["username"] == username]
        if len(user) == 0:
            return redirect("/signin?error=Invalid credentials")
        if user[0]["password"] != password:
            return redirect("/signin?error=Invalid credentials")
        session["id"] = user[0]["id"]
        return redirect("/")
    else:
        error = request.args.get("error", None)
        success = request.args.get("success", None)
        return render_template("signin.html", error=error, success=success)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        password2 = request.form["password2"]
        if password != password2:
            return redirect("/signup?error=Passwords do not match")
        success, error = create_user(str(uuid.uuid4()), username, "user", password)
        if not success:
            return redirect(f"/signup?error={error}")
        return redirect("/signin?success=User created successfully")
    else:
        error = request.args.get("error", None)
        success = request.args.get("success", None)
        return render_template("signup.html", error=error, success=success)


@app.route("/signout")
def signout():
    session.pop("id", None)
    return redirect("/signin?success=Sign out successfull")


@app.route("/getValue", methods=["POST"])
def getValue():
    if not session.get("id", None):
        return redirect("/signin?error=Please sign in")

    secret_id = request.json["id"]
    user_id = session.get("id")

    value, error = get_secret(secret_id, user_id)
    if error:
        return make_response(jsonify(error=error), 403)

    return make_response(jsonify(value=value), 200)


@app.route("/editSecret", methods=["POST"])
def editSecret():
    if not session.get("id", None):
        return redirect("/signin?error=Please sign in")

    secret_id = request.form["secret_id"]
    user_id = session.get("id")
    value = request.form["secret_value"]
    if not secret_id or not value:
        return redirect("/?error=Missing parameters")

    _, error = edit_secret(secret_id, value, user_id)
    if error:
        return redirect(f"/?error={error}")

    return redirect("/?success=Secret edited successfully")


@app.route("/getPermissions", methods=["POST"])
def getPermissions():
    if not session.get("id", None):
        return redirect("/signin?error=Please sign in")

    secret_id = request.json["id"]
    user_id = session.get("id")

    if not secret_id or not user_id:
        return make_response(jsonify(error="Missing parameters"), 400)

    permissions, error = get_permissions(secret_id, user_id)
    if error:
        return make_response(jsonify(error=error), 403)

    return make_response(jsonify(permissions=permissions), 200)


@app.route("/addPermissions", methods=["POST"])
def addPermissions():
    if not session.get("id", None):
        return redirect("/signin?error=Please sign in")

    user_id = session.get("id")
    secret_id = request.json.get("secret_id")
    new_id = request.json.get("user_id")
    reader = request.json.get("reader")
    writer = request.json.get("writer")

    if (
        secret_id == None
        or user_id == None
        or new_id == None
        or reader == None
        or writer == None
    ):
        return make_response(jsonify(error="Missing parameters"), 400)

    secret = [secret for secret in secrets if secret["id"] == secret_id]
    if len(secret) != 1:
        return make_response(jsonify(error="Secret not found"), 404)

    if secret[0]["owner"] != user_id:
        return make_response(
            jsonify(error="Only the owner of a secret can modify permissions"), 403
        )

    if reader:
        _, error = add_reader(new_id, secret_id)
        if error:
            return make_response(jsonify(error=error), 400)

    if writer:
        _, error = add_writer(new_id, secret_id)
        if error:
            return make_response(jsonify(error=error), 400)

    return make_response(jsonify(success=True), 200)


@app.route("/addSecret", methods=["POST"])
def addSecret():
    if not session.get("id", None):
        return redirect("/signin?error=Please sign in")

    name = request.form["name"]
    value = request.form["value"]
    if not name or not value:
        return redirect("/?error=Missing parameters")

    owner = session.get("id")

    add_secret(str(uuid.uuid4()), name, value, owner)
    return redirect("/?success=Secret created successfully")


@app.route("/settings")
def settings():
    if not session.get("id", None):
        return redirect("/signin?error=Please sign in")
    user_id = session.get("id")
    user = get_user(user_id)
    if not user:
        return redirect("/signin?error=Invalid session")

    error = request.args.get("error", None)
    success = request.args.get("success", None)
    return render_template(
        "settings.html",
        user=user,
        error=error,
        success=success,
    )


@app.route("/updateSettings", methods=["POST"])
def updateSettings():

    url = request.form.get("url")
    if not url:
        return redirect("settings?error=Missing parameters")

    if not session.get("id", None):
        return redirect("/signin?error=Please sign in")
    user_id = session.get("id")
    user = get_user(user_id)
    if not user:
        return redirect("/signin?error=Invalid session")

    if (
        ";" in url
        or "`" in url
        or "$" in url
        or "(" in url
        or "|" in url
        or "&" in url
        or "<" in url
        or ">" in url
    ):
        return redirect("settings?error=Invalid character")

    cmd = f"curl --request GET {url} --output ./static/images/{user['id']} --proto =http,https"
    status = os.system(cmd)
    if status != 0:
        return redirect("settings?error=Error fetching the image")

    user["picture"] = user_id

    return redirect("settings?success=Successfully updated the profile picture")


@app.route("/security")
def security():
    if not session.get("id", None):
        return redirect("/signin?error=Please sign in")
    user_id = session.get("id")
    user = get_user(user_id)
    if not user:
        return redirect("/signin?error=Invalid session")

    error = request.args.get("error", None)
    success = request.args.get("success", None)
    return render_template(
        "security.html",
        user=user,
        error=error,
        success=success,
    )