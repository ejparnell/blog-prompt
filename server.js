// Express app set up
const express = require('express')
const app = express()

// DB set up
const mongoose = require('mongoose')
const db = require('./config/db')

mongoose.connect(db)

// Middleware imports
const cors = require('cors')
const requestLogger = require('./utils/request_logger')
const errorHandler = require('./utils/error_handler')
const auth = require('./utils/auth')

// Import Routes
const userRoutes = require('./routes/user_routes')

// Port number
const SERVER_DEV_PORT = 8000
const CLIENT_DEV_PORT = 3000 // replace with localhost for front end
const PORT = process.env.PORT || SERVER_DEV_PORT

// Application
app.use(cors({ origin: process.env.CLIENT_ORIGIN || `http://localhost:${CLIENT_DEV_PORT}` })) // cors
app.use(auth) // Auth strategy
app.use(express.json()) // accept JSON
app.use(express.urlencoded({ extended: true })) // supports body parser
app.use(requestLogger) // Logs request - custom middleware

// Routes
app.use(userRoutes)

// Error handler
app.use(errorHandler)

app.listen(PORT, () => console.log(`Listing on port ${PORT}`))

// for testing
module.exports = app