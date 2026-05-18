import express from 'express'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'


const app = express()

const secret_key = 'secretAss'

const users = []

app.use(express.json())

app.post('/api/register', async (req, res) => {
    const {username, password} = req.body 

    const hashedPasswod = await bcrypt.hash(password, 10)

    users.push( {id: users.length + 1, username: username, password: hashedPasswod} )

    res.status(201).json({message: 'Пользователь создан: ' + username})
})

app.post('/api/login', async (req, res) => {
    const {username, password} = req.body

    const condidate = users.find(user => user.username === username)
    if(!condidate) return res.status(401).json({error: "Неверный логин или пароль"})

    const isPasswordValid = bcrypt.compare(password, condidate.password)

    if(!isPasswordValid) return res.status(401).json({error: "Неверный логин или пароль"})

    const token = jwt.sign(
        {userId: condidate.id,
        username: condidate.username},
        secret_key,
        { expiresIn: '1h'}
    )
    res.json({message: token})    
})

const authJWT = (req, res, next) => {
    if(!req.headers.authorization) {
        return res.status(401).json({error: "Нет доступа"})
    }

    const token = req.headers.authorization.split(' ')[1]

    jwt.verify(token, secret_key, (err, decoded) => {
        if(err) {
            return res.status(403).json({error: "Токен не действителен"})
        }
        req.user = decoded
        next()
    })
}

app.get('api/profile', authJWT, async(req, res) => {
    res.json({
        message: "Это защищённые данные",
        user: req.user
    })
})

app.listen('3000', console.log("Сервер запущен. Порт 3000. Ссылка: http://localhost:3000/api/register"))