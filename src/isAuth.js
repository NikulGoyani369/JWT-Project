const { verify } = require('jsonwebtoken'); // this was we can varify our token in have header 

const isAuth = req => {
    const authorization = req.headers['authorization'];
    if(!authorization) throw new Error('You need to login');
    // in header token looks like 
    // 'Bearer sdsadlaflaegfea8f9as8f0afoadnklasd897ag98a6g7z98g9ß09ßbfsdkah'

    const token = authorization.split(' ')[1];
    try {
        const { userId } = verify(token, process.env.ACCESS_TOKEN_SECRET);    
        return userId;
    } catch (error) {
        console.warn('isAuth()',error);
    }

    return null;
}

module.exports = {
    isAuth,
}