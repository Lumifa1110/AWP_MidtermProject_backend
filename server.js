require('dotenv').config()

const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
const cors = require('cors')
const bcrypt = require('bcrypt')
const verifyToken = require('./middleware/auth')


const corsOptions = {
  origin: 'http://localhost:3000',
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  credentials: true,
  optionsSuccessStatus: 204,
};

app.use(express.json())
app.use(
  cors()
)
// app.options('*', cors(corsOptions));

let users = [
  {
    username: 'Administrator',
    password: '$2b$10$4OWtKR9inqBxD5Wl4x/dQuoQKDkYapLxjAfwbKbdadqXEpvoixeBS',
    role: 'Ad',
    title: 'This is Admin Account',
    refreshToken: null
  },
  {
    username: 'Moderator',
    password: '$2b$10$4OWtKR9inqBxD5Wl4x/dQuoQKDkYapLxjAfwbKbdadqXEpvoixeBS',
    role: 'Mod',
    title: 'This is Moderator Account',
    refreshToken: null
  },
  {
    username: 'TestingUser',
    password: '$2b$10$4OWtKR9inqBxD5Wl4x/dQuoQKDkYapLxjAfwbKbdadqXEpvoixeBS',
    role: 'User',
    title: 'This is Moderator Account',
    refreshToken: null
  }
]

const mongoose = require('mongoose')
mongoose.connect("mongodb://127.0.0.1:27017 ", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log("Connection Successfull")
}).catch((err) => {
  console.log(err)
})
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    require: true,
    min: 6,
    max: 20,
    unique: true,
  },
  email: {
    type: String,
    require: true,
    max: 50,
    unique: true,
  },
  password: {
    type: String,
    require: true,
    min: 6,
  },
  role: String,
  refreshToken: {
    type: String,
    default: null
  }

})
const UserModel = new mongoose.model("UserModel", userSchema)

app.post("/register", async (req, res) => {
  const username = req.body.username
  const password = req.body.password
  // console.log({username, password})
  const user = users.find(user => { return user.username === username })
  if (user) return res.sendStatus(409)

  const hashedPassword = await bcrypt.hash(password, 10);
  
  const newUser = {
    username,
    password: hashedPassword,
    role: 'User', // Set a default role or customize based on your requirements
    title: 'This is a User Account',
    refreshToken: null
  };
  users.push(newUser);

  const successResponse = { message: "Registration successful!" };
  // Send the success response to the client
  res.status(200).json(successResponse);
})

app.get('/posts', verifyToken, (req, res) => {
  res.json(users.filter(user => user.username === req.user.name));
})

app.get('/all', (req, res) => {
  res.json(users);
})

app.post('/token', (req, res) => {
  const refreshToken = req.body.refreshToken
  if (refreshToken === null) return res.sendStatus(401)
  const user = users.find(user => user.refreshToken === refreshToken)
  // console.log("User: ", user)
  if (!user) return res.sendStatus(403)

  try {
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET)
    const newAccessToken = generateAccessToken({ name: user.username })
    // const newRefreshToken = generateRefreshToken({ name: user.username })
    const tokens = { accessToken: newAccessToken }
    // updateRefreshToken(user.username, tokens.newRefreshToken)
    res.json(tokens)
  } catch (error) {
    // console.log(error)
    res.sendStatus(403)
  }
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body
  // Check user existed
  const user = users.find(user => { return user.username === username })
  if (!user) return res.sendStatus(400)
  // Check password match
  const isMatch = await bcrypt.compare(password, user.password)
  if (!isMatch) return res.sendStatus(400)

  if (user && isMatch) {
    const authUser = { name: username }
    const newAccessToken = generateAccessToken(authUser)
    const newRefreshToken = generateRefreshToken(authUser)
    const { password, ...others } = user;
    updateRefreshToken(authUser.name, newRefreshToken)
    res.status(200).json({ ...others, accessToken: newAccessToken, refreshToken: newRefreshToken })
  }
})

app.delete('/logout', verifyToken, (req, res) => {
  console.log(req)
  const user = users.find(user => user.username === req.user.name)
  updateRefreshToken(user.username, null)
  if (user.refreshToken) {
    console.log('Logout success')
  }
  res.status(204).json({ message: 'Logout success' });
})

function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '30s' })
}

function generateRefreshToken(user) {
  return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '365d' })
}

function updateRefreshToken(username, refreshToken) {
  users = users.map(user => {
    if (user.username === username)
      return { ...user, refreshToken }
    return user
  })
}
app.listen(3000)

