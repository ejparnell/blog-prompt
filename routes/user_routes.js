const express = require('express')
const crypto = require('crypto')
const passport = require('passport')
const bcrypt = require('bcrypt')
const User = require('../models/user')
const { BadParamsError, BadCredentialsError } = require('../utils/custom_errors')

const SALT_ROUNDS = 10
const RANDOM_BYTES = 16
const reqToken = passport.authenticate('bearer', { session: false })

const router = express.Router()

router.post('/sign-up', (req, res, next) => {

    const credentials = req.body.credentials

    Promise.resolve(credentials)
    .then(credentials => {

        const isValidCredentials = !credentials || !credentials.password || credentials.password !== credentials.password_confirmation

        if (isValidCredentials) {
            throw new BadCredentialsError()
        }
    })
    .then(() => bcrypt.hash(credentials.password, SALT_ROUNDS))
    .then(hash => {
        return {
            email: credentials.email,
            hashedPassword: hash
        }
    })
    .then(user => User.create(user))
    .then(user => res.status(201).json({ user: user.toObject() }))
    .catch(next)
})

router.post('/sign-in', (req, res, next) => {
    const credentials = req.body.credentials
    let user 
    
    User.findOne({ email: credentials.email })
    .then(record => {
        if (!record) {
            throw new BadCredentialsError()
        }
        user = record

        return bcrypt.compare(credentials.password, user.hashedPassword)
    })
    .then(correctPassword => {
        if (correctPassword) {
            const token = crypto.randomBytes(RANDOM_BYTES).toString('hex')
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

router.patch('/change-password', reqToken, (req, res, next) => {
    const passwords = req.body.passwords
    let user 

    User.findById(req.user.id)
    .then(record => { user = record })
    .then(() => bcrypt.compare(passwords.old, user.hashedPassword))
    .then(correctPassword => {
        if (!passwords.new || !correctPassword) {
            throw new BadParamsError()
        }
    })
    .then(() => bcrypt.hash(passwords.new, SALT_ROUNDS))
    .then(hash => {
        user.hashedPassword = hash
        user.save()
    })
    .then(() => res.sendStatus(204))
    .catch(next)
})

router.delete('/sign-out', reqToken, (req, res, next) => {
    req.user.token = null

    req.user.save()
    .then(() => res.sendStatus(204))
    .catch(next)
})

module.exports = router
