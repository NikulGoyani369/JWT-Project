require('dotenv/config');
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { verify } = require('jsonwebtoken');
const { hash, compare } = require('bcryptjs');
const  { 
        createAccessToken, 
        createRefreshToken, 
        sendAccessToken, 
        sendRefreshToken 
    } = require('./tokens.js');
const  {isAuth} = require('./isAuth.js')

const { fakeDB } = require('./fakeDB.js')

// 1. Register a user
// 2. Login a user
// 3. Logout a user
// 4. Setup a protected route
// 5. Get a new accesstoken with refresh token


const server = express();


// Use express middleware for easier cookie handling
server.use(cookieParser());

server.use(
    cors({
        origin: 'http://localhost:3000',
        credentials: true,
    })
);

// Needed to be able to read body data
server.use(express.json()); // to support JSON-encoded bodies
server.use(express.urlencoded({ extended: true })); // to support URL-encoded bodies



// 1. Register a user
server.post('/register', async(req, res) => {
    const { email, password } = req.body;

    try {
        // 1. Check if user exist
        const user = fakeDB.find(user => user.email === email);
        if(user) throw new Error('User alredy exist');
        // 2. If  not user exist, hash the password
        const hashedPassword = await hash(password, 10);
        // 3. Insert the user in "database"
        fakeDB.push({
            id: fakeDB.length,
            email,
            password: hashedPassword
        })

        res.send({
            message: 'User Created'});
            console.log(fakeDB);
    } catch (err) {
        res.send({
            error: `${err.message}`,
        })

    }

});


// 2. Login a user endpoint
server.post('/login', async(req, res) => {
    const { email, password } = req.body;
    try {
        //1. Find user in "database". If not exist send error 
        const user = fakeDB.find(user => user.email === email);
        if(!user) throw new Error("User does not exist");

        // 2. Compare crypted password and see if it checks out. Send error if not
        const valid = await compare(password, user.password);
        if(!valid) throw new Error("Password not correct");
        // 3. Create Refresh and Accesstoken
        const accesstoken =  createAccessToken(user.id);
        const refreshtoken = createRefreshToken(user.id);
        
        // 4. put the refreshtoken in the "database"
        user.refreshtoken = refreshtoken;
        console.log(fakeDB);

        //5. Send token. Refreshtoken as a cookie and accesstoken as regular response
        sendRefreshToken(res, req, refreshtoken);
        //sendAccessToken(res, req, accesstoken)
        
        res.send({
            accesstoken: accesstoken,
            refreshtoken:refreshtoken
        });
    }  catch (err) {
        res.send(  {
            error: `${err.message}`
        })

    }
});


// 3. Logout a user

server.post('/logout', (_req, res) => {
    res.clearCookie('refreshtoken', { path: '/refresh_token' }) //When we logout we have to remove our refreshToken from the cookie and also we have to clear out accesToken from the clien when user logout  // we can not get new accessToken without the login

    return res.send({
        message: 'Logged out',
    })
})


// 4 Protected route means Authorization with token
server.post('/protected', async(req, res) => {

    try {
        console.log('Header',req.headers);

        const userId = isAuth(req)

        if(userId !== null) {
            res.send({ data:"This is Protected data." });
           
        }
        else{
            res.status(403).send({ data:"Forbidden." });           
        }

    } catch (err) {
        res.send({
            error: `${err.message}`
        })
    }

})

server.get('/user', (req, res) => {
    
    return res.send({ fakeDB });
})

// 5. Get a new access token with a refresh token 
server.post('/refresh_token', (req, res) => {
console.log('------------------------refresh_token ');

    const token = req.cookies.refreshtoken
    // If we do not have a token in our request 
    if(!token) return res.send({ accesstoken: '' });

    // We have a token, let's verify it!
    let payload = null;
    try {
        payload = verify(token, process.env.REFRESH_TOKEN_SECRET);
    } catch(err) {
        return res.send({accesstoken: 'Test' });
    }

    // Token is valid, check if user exist in our database
    const user = fakeDB.find(user => user.id === payload.userId);
    if (!user) return res.send({ accesstoken : ''});

    // User exist, check if refreshtoken exist on user with check in our fakeDB or OrigialDB
    if (user.refreshtoken !== token) {
        return res.send({ accesstoken: ''});
    }

    // Token exist, create new Refresh- and Accesstoken
    const accesstoken = createAccessToken(user.id);
    const refreshtoken = createRefreshToken(user.id);
    user.refreshtoken = refreshtoken; // here it will update refreshToken in database

    // All good to go, send new refreshtoken and accesstoken 
    sendRefreshToken(res, req, refreshtoken);
    return res.send({
        accesstoken: accesstoken,
        refreshtoken:refreshtoken
    });
})

server.listen(process.env.PORT, () => 
    console.log(`Server listening on port ${process.env.PORT}`)
);
