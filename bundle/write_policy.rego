package access.write

default allow_write = false

allow_write {
  data.users[input.user].role == "admin"
}

allow_write {
  data.users[input.user].role == "user"
  data.writers[input.secret][_] == input.user
}
