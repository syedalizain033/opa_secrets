package access.read

default allow_read = false

allow_read {
  data.users[input.user].role == "admin"
}

allow_read {
  data.users[input.user].role == "user"
  data.readers[input.secret][_] == input.user
}
