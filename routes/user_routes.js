const express = require('express')
const crypto = require('crypto')
const passport = require('passport')
const bcrypt = require('bcrypt')

const SALT_ROUNDS = 10

const { BadParamsError, BadCredentialsError } = require('../utils/custom_errors')

const User = require('../models/user')

const reqToken = passport.authenticate('bearer', { session: false })

const router = express.Router()

router.post('/sign-up', (req, res, next) => {
    Promise.resolve(req.body.credentials)
    .then(credentials => {
        if (!credentials || !credentials.password || credentials.password !== credentials.password_confirmation) {
            throw new BadCredentialsError()
        }
    })
    .then(() => bcrypt.hash(req.body.credentials.password, SALT_ROUNDS))
    .then(hash => {
        return {
            email: req.body.credentials.email,
            hashedPassword: hash
        }
    })
    .then(user => User.create(user))
    .then(user => res.status(201).json({ user: user.toObject() }))
    .catch(next)
})

router.post('/sign-in', (req, res, next) => {
    const password = req.body.credentials.password
    let user 
    
    User.findOne({ email: req.body.credentials.email })
    .then(record => {
        if (!record) {
            throw new BadCredentialsError()
        }
        user = record

        return bcrypt.compare(password, user.hashedPassword)
    })
    .then(correctPassword => {
        if (correctPassword) {
            const token = crypto.randomBytes(16).toString('hex')
            user.token = token
            return user.save()
        } else {
            throw new BadCredentialsError()
        }
    })
    .then(user => {
        res.status(201).json({ user: user.toObject() })
    })
    .catch(next)
})

module.exports = router
