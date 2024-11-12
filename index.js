const express = require('express')
// const csurf = require('csurf');
const cookieParser = require('cookie-parser');
const cors = require("cors")
const mongoose = require('mongoose');
const app = express()
const PORT = process.env.PORT || 5000;
const bcrypt = require('bcrypt');
const moment = require('moment');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const jwt = require('jsonwebtoken');


// // cross origin resources allowed
// app.use(cors({
//     origin: 'http://localhost:3001', // Allow only this origin
//     credentials: true                // Allow credentials if needed (e.g., cookies)
// }));

const allowedOrigins = ['http://localhost:3001', 'https://info-sec-frontend-1.onrender.com'];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'username']
}));


const SECRET_KEY ="The unexamined life is not worth living@"


// max -failed attempts
const MAX_ATTEMPTS = 5
const BLOCK_TIME  = 5 * 60 * 1000


app.use(express.json());



var DATABASE_NAME = "infosecdb"
var COLLECTION_NAME = "infoseccollection"
const CONNECTION_STRING = `mongodb+srv://admin:password%4024@cluster0.7tz0a.mongodb.net/${DATABASE_NAME}?retryWrites=true&w=majority&appName=Cluster0`;
var database;

// connection
mongoose.connect(CONNECTION_STRING)
.then(()=> console.log('MongoDb connected'))
.catch(err => console.log("Monog Error", err));

// Schema
const userSchema = new mongoose.Schema({
    id:{
        type:String,
        required:true,
    },
    fullname:{
        type:String,
        required:true,

    },
    username:{
        type:String,
        required:true,
        unique:true
    },
    password:{
        type:String,
        required:true
    },
    secret_code:{
        type:String,
        required:true
    }

},{timestamps:true})

const userFailedSchema = new mongoose.Schema({
    username:{
        type:String,
        required:true,
        unique:true
    },
    failed_attempts:{
        type:Number
    },
    last_failed_attempt:{
        type:Date,
        default: Date.now
    },
    locked_until:{
        type:Date
    }
}, {timestamps:true})



// Model , later we will use User object to all kind of things
// collection will be name 'users'
const User = mongoose.model('user',userSchema);
const UserFailed = mongoose.model('user_failed',userFailedSchema);

console.log("starting server...")

const verifyPassword = async (password, hashedPassword) => {
    const match = await bcrypt.compare(password, hashedPassword);
    return match;
  };


app.get('/forgetpass/usernameverify', async(req,res)=>{
    const username = req.headers['username'];

    try {
        const userFailed = await UserFailed.findOne({ username });
        if(!userFailed){
            return res.status(401).json({ message: 'Invalid username' });
        }

        if(userFailed.locked_until && new Date(userFailed.locked_until) > new Date()){
            const lockTimeLeft =  new Date(userFailed.locked_until)  - new Date();
            console.log(`account blocked`)
            return res.status(403).json({message:`Account locked. Try again ${Math.ceil(lockTimeLeft/1000)} seconds`})
        }else{
            const result = await UserFailed.updateOne(
                { username: userFailed.username }, // Filter condition
                { $set: {  locked_until : null,   failed_attempts: 0 } } // The fields to update
              );

        }

        // Find the user by username
        const user = await User.findOne({ username });
        if (!user) {
            console.log(`username not matched `)
            
            const failedAttempts = userFailed.failed_attempts +1 ;

            if(failedAttempts >= 5){
                const lockedUntil = moment().add(5, 'minutes').toDate();

                const result = await UserFailed.updateOne(
                    { username: userFailed.username }, // Filter condition
                    { $set: {  locked_until : lockedUntil } } // The fields to update
                  );

                return res.status(403).json({message:`Account locked try after 5 minutes`})
            }else{

                const result = await UserFailed.updateOne(
                    { username: userFailed.username }, // Filter condition
                    { $set: { failed_attempts : failedAttempts } } // The fields to update
                  );

                  return res.status(403).json({message:`Invalid credentials`})
            }
          return res.status(401).json({ message: 'Invalid username' });
        }

    
        console.log(`login sucess of ${username}`)
        return  res.status(200).json({ message: 'Login successful' });

    } catch (error) {
        console.log('Error:', error);
       return res.status(500).json({ message: 'Error logging in' });
    }


})


//API FOR PASSWORD CHANGE

app.post('/setnewpass', async(req,res)=>{


    try{

    const { username, password } = req.body;

       // Hash the password
       const hashedPassword = await hashPassword(password);

     // Find the user by username
     const user = await User.findOne({ username });
     if (!user) {
       return res.status(401).json({ message: 'Invalid username or password' });
     }


    const result = await User.updateOne(
        { username: username }, // Filter condition
        { $set: {  password : hashedPassword  } } // The fields to update
      );


      console.log(`login sucess of ${username}`)
      return  res.status(200).json({ message: 'password change successful' });


    }catch(error){

        console.log('Error:', error);
        return res.status(500).json({ message: 'Error logging in' });

    }



})

// API FOR LOGIN
app.post('/login',async (req,res)=>{
    console.log(`user requested for login `)


    try {
        const { username, password } = req.body;

        const userFailed = await UserFailed.findOne({ username });

        if(!userFailed){
            
            return res.status(401).json({ message: 'Invalid username or password' });
        }

       
        if(userFailed.locked_until && new Date(userFailed.locked_until) > new Date()){
            const lockTimeLeft =  new Date(userFailed.locked_until)  - new Date();
            console.log(`account blocked`)
            return res.status(403).json({message:`Account locked. Try again ${Math.ceil(lockTimeLeft/1000)} seconds`})
        }else{

            const result = await UserFailed.updateOne(
                { username: userFailed.username }, // Filter condition
                { $set: {  locked_until : null,   failed_attempts: 0 } } // The fields to update
              );

        }

       
        // Find the user by username
        const user = await User.findOne({ username });
        if (!user) {
          return res.status(401).json({ message: 'Invalid username or password' });
        }

        console.log(`test 1 ${userFailed} locked until ${userFailed.locked_until}`)
    
        // Verify the password
        const isMatch = await verifyPassword(password, user.password);
        if (!isMatch) {

            console.log(`password not matched `)
            
            const failedAttempts = userFailed.failed_attempts +1 ;

            if(failedAttempts >= MAX_ATTEMPTS){
                const lockedUntil = moment().add(5, 'minutes').toDate();

                const result = await UserFailed.updateOne(
                    { username: userFailed.username }, // Filter condition
                    { $set: {  locked_until : lockedUntil } } // The fields to update
                  );

                return res.status(403).json({message:`Account locked try after 5 minutes`})
            }else{

                const result = await UserFailed.updateOne(
                    { username: userFailed.username }, // Filter condition
                    { $set: { failed_attempts : failedAttempts } } // The fields to update
                  );

                  return res.status(403).json({message:`Invalid credentials`})

            }

          return res.status(401).json({ message: 'Invalid username or password' });
        }

    
        console.log(`login sucess of ${username}`)
        return  res.status(200).json({ message: 'Login successful' });

    } catch (error) {
        console.log('Error:', error);
       return res.status(500).json({ message: 'Error logging in' });
    }



   return res.send('POST request to login api')
})


const hashPassword = async (password) => {
    const saltRounds = 10; // Determines the cost of hashing; higher = more secure, but slower
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    return hashedPassword;
  };


//API FOR SIGNUP
app.post('/signup', async (req,res)=>{
    const body = req.body;
    
    var secret = speakeasy.generateSecret();
  

    console.log(body)

        if(!body.username || !body.password || !body.fullname){
            return res.status(400).json({msg:"All fields are required.."})
        }

        try{

            // Hash the password
            const hashedPassword = await hashPassword(body.password);

            const result = await User.create({
                id: body.id,
                fullname:body.fullname,
                username:body.username,
                password: hashedPassword,
                secret_code: secret.base32,
            })

            const resultUserfailed = await UserFailed.create({
                username:body.username,
                failed_attempts:0,   
                locked_until: null
            })

          

            console.log("user created")
            QRCode.toDataURL(secret.otpauth_url, (err, data_url) => {
                // Display `data_url` as an image in HTML to let users scan it

        
                console.log(`this is url ${data_url}`)
                return res.status(200).json({message:'success',qr_url:data_url})


            });

        

         

        }catch(error){
        
            if (error.name === 'ValidationError') {
                return res.status(400).json({ message: 'Validation Error', details: error.errors });
            } else if (error.code === 11000) {  
                return res.status(409).json({ message: 'Username already exists' });
            } else {
                return res.status(500).json({ message: 'Internal Server Error', error: error.message });
            }
            
        }
})

app.post('/gauth', async (req,res)=>{
    const body = req.body;

    const { user_token, username} = req.body;

    console.log(`gauth ${user_token} , ${username}`)

    if(!body.user_token || !body.username){
        return res.status(400).json({msg:"user token is required.."})
    }

    try{

        // Find the user by username
        const user = await User.findOne({ username });
        if (!user) {
          return res.status(401).json({ message: 'Invalid username or password' });
        }


        const isValid = speakeasy.totp.verify({
            secret: user.secret_code,
            encoding: 'base32',
            token: user_token // Token provided by the user
          });
          
          if (isValid) {
             
            console.log('2FA successful');
            res.status(200).json({ message: '2FA successful' });


          } else {
            console.log('Invalid token');

            return res.status(401).json({ message: 'Invalid token' });

          }
          

    }catch(error ){

        res.status(403).json({ message: `server error ${error.message}` });

    }

})


app.listen(PORT, (e)=>{
    if(e){
        console.log(`error occured : ${e.message}`)
        process.exit(1)
    }else{
        console.log(`Server is running on http://localhost:${PORT}`)
    }
})
