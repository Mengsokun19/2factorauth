const express = require('express')
const speakeasy = require('speakeasy')
const uuid = require('uuid')

const { JsonDB } = require('node-json-db');
const { Config } = require('node-json-db/dist/lib/JsonDBConfig')

const app = express()

app.use(express.json())

const db = new JsonDB(new Config('newDB', true, false, '/'))

app.get('/', (req, res) => res.json({message: 'Welcome to the two factor authentication.'}))

// Register user and create temp secret
app.post('/api/register', (req, res) => {
    const id = uuid.v4()

    try {
        const path = `/user/${id}`
        const tempSecret = speakeasy.generateSecret()
        db.push(path, {id, tempSecret})

        res.json({id, secret: tempSecret.base32})
    } catch (err) {
        console.error(err)
        res.status(500).send({message: err.message})
    }
})


// Verify token and make secret perm
app.post('/api/verify', (req, res) => {
    const {token, userId} = req.body

    try {
        const path = `/user/${userId}`
        const user = db.getData(path)

        const {base32: secret} = user.tempSecret

        const verified = speakeasy.totp.verify({
            secret, 
            encoding: 'base32',
            token
        })

        if (verified) {
            db.push(path, {id: userId, secret: user.tempSecret})
            res.json({ verified: true })
        }
        else {
            res.json({ verified: false })
        }
    } catch (err) {
        console.error(err)
        res.status(500).send({message: err.message})
    }
})

// Validate Token
app.post('/api/validate', (req, res) => {
    const {token, userId} = req.body

    try {
        const path = `/user/${userId}`
        const user = db.getData(path)

        const {base32: secret} = user.secret

        const tokenValidates = speakeasy.totp.verify({
            secret, 
            encoding: 'base32',
            token,
            window: 1
        })

        if (tokenValidates) {
            res.json({ validated: true })
        }
        else {
            res.json({ validated: false })
        }
    } catch (err) {
        console.error(err)
        res.status(500).send({message: err.message})
    }
})

const PORT = process.env.PORT || 5000

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
})