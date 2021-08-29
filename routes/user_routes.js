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

router.patch('/change-password', reqToken, (req, res, next) => {
    let user 

    User.findById(req.user.id)
    .then(record => { user = record })
    .then(() => bcrypt.compare(req.body.passwords.old, user.hashedPassword))
    .then(correctPassword => {
        if (!req.body.passwords.new || !correctPassword) {
            throw new BadParamsError()
        }
    })
    .then(() => bcrypt.hash(req.body.passwords.new, SALT_ROUNDS))
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
