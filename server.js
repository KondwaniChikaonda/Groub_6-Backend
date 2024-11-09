const express = require('express');

const mysql = require('mysql2');

const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
require('dotenv').config();

const multer = require('multer');
const path = require('path');
const bcrypt = require('bcryptjs'); // Use bcryptjs instead of bcrypt




const app = express();
const port = 3000;

app.use(cors());
app.use(bodyParser.json());










// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Set up Cloudinary storage for Multer
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  folder: 'uploads/images', // Folder in Cloudinary
  allowedFormats: ['jpg', 'png'],
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  },
});

const upload = multer({ storage: storage });

// Serve static files
app.use('/uploads', express.static('uploads'));





const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS, 
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
    
});



// Promisify for Node.js async/await
const promiseDb = db.promise();

// Function to execute queries using the pool
const executeQuery = async (query, params) => {
    try {
        const [rows] = await promiseDb.query(query, params);
        return rows;
    } catch (err) {
        console.error('Error executing query:', err);
        throw err; // Optionally handle the error or notify the system
    }
};




// Middleware to verify the token and extract the user ID
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.sendStatus(401);
  console.log(process.env.JWT_SECRET);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    console.log('Decoded user from token:', user);
    next();
  });
};








const JWT_SECRET = process.env.JWT_SECRET ;
const MAILTRAP_SMTP_SERVER = process.env.MAILTRAP_SMTP_SERVER;
const MAILTRAP_SMTP_PORT = process.env.MAILTRAP_SMTP_PORT; // Mailtrap typically uses 587 for TLS
const MAILTRAP_USERNAME = process.env.MAILTRAP_USERNAME;
const MAILTRAP_PASSWORD = process.env.MAILTRAP_PASSWORD;




const generateResetToken = (email) => {
  const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: '10mins' });
  return token;
};

const transporter = nodemailer.createTransport({
  host: MAILTRAP_SMTP_SERVER,
  port: MAILTRAP_SMTP_PORT,
  auth: {
    user: MAILTRAP_USERNAME,
    pass: MAILTRAP_PASSWORD
  }
});





app.get('/', (req, res) => {
  res.send('Hello, World!');
});




app.post('/register', (req, res) => {
    const { registrationNumber,email, password } = req.body;

    db.query('INSERT INTO login (registration_number,email,password) VALUES (?, ?, ?)', [registrationNumber, email, password], (err, result) => {
        if (err) {
            res.status(500).send('Server error');
            return;
        }
        res.status(200).send('User registered');
    });
});


app.post('/login', (req, res) => {
    const { username, password } = req.body;

    console.log(username);

    // Query to find the user by email
    db.query('SELECT * FROM login WHERE email = ?', [username], async (err, result) => {
        if (err) {
            res.status(500).send('Server error');
            return;
        }

        if (result.length === 0) {
            res.status(401).send('Login failed: User not found');
            return;
        }

        const user = result[0];

        try {
            // Compare the provided password with the stored hashed password
            const passwordMatch = await bcrypt.compare(password, user.password);

            if (!passwordMatch) {
                res.status(401).send('Login failed: Incorrect password');
                return;
            }

            // No JWT token here; just send the user details
            res.status(200).send({
                auth: true,
                userId: user.id,       // Send the user id (or any other data you need)
                registrationNumber: user.registration_number    // Optionally, send the user name or other details
            });
        } catch (compareErr) {
            res.status(500).send('Server error');
        }
    });
});





const otps = {}; // Store OTPs in-memory for simplicity (consider a more persistent storage in production)







app.post('/send-otp', (req, res) => {
    const { registrationNumber, password, email} = req.body;

    
    console.log(email);
    
    const otp = Math.floor(100000 + Math.random() * 900000).toString(); // Generate a 6-digit OTP
    otps[email] = otp;

    const mailOptions = {
        from:   MAILTRAP_USERNAME,
        to: email,
        subject: 'Your OTP Code From Loan Bonding System!',
        text: `Welcome to Loan Bonding System Please Enter Your OTP Code To Start Our services ${otp}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error('Error sending email:', error);
            res.status(500).send({ success: false, message: 'Error sending OTP' });
        } else {
            res.send({ success: true, message: 'OTP sent successfully' });
        }
    });
});





app.post('/verify-otp', async (req, res) => {
    const { registrationNumber, email, otp, password} = req.body;

    console.log(otps[email]);
    console.log("Password received:", password);


    if (otps[email] === otp) {
        delete otps[email]; // Remove OTP after successful verification

        try {
            // Hash the password before storing it
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            // Insert user into the database with the hashed password
            db.query('INSERT INTO login (registration_number, password, email) VALUES (?, ?, ?)', 
                [registrationNumber, hashedPassword, email], 
                (err, result) => {
                    if (err) {
                        console.error('Error inserting user:', err);
                        res.status(500).send({ success: false, message: 'Server error' });
                    } else {
                        res.send({ success: true, message: 'User signed up successfully' });
                    }
                }
            );
        } catch (err) {
            console.error('Error hashing password:', err);
            res.status(500).send({ success: false, message: 'Server error' });
        }
    } else {
        res.send({ success: false, message: 'Invalid OTP' });
    }
});









app.post('/submit-form', (req, res) => {
    const {
      SurName, FirstName, OtherName, dob, Village, Traditional, District, PostalAddress, PhoneNumber, Email, 
      BankName, Branch, BankAccountNumber, BankAccountName, FullName, postalAddress, PhysicalAddress, 
      HomeVillage, Occupation, PhoneNumberParents, UniversityName, ProgramOfStudy, RegistrationNumber, 
      AcademicYear, YearOfStudy, Sex, PostalAddressParents, PhysicalAddressParents, HomeVillageParents, 
      DistrictParents, EmailParents, userId
    } = req.body;
  
    
      // Insert into `studentpersonaldetails`
      db.query(`
        INSERT INTO studentpersonaldetails (SurName, FirstName, OtherName, dob, Village, TraditionalAuthority, 
        District, PostalAddress, PhoneNumber, Email, Sex) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [SurName, FirstName, OtherName, dob, Village, Traditional, District, PostalAddress, PhoneNumber, Email, Sex], (err, result) => {
        if (err) {
       
            console.error('Error inserting personal details:', err);
            return res.status(500).json({ message: 'An error occurred while inserting personal details.' });
        
        }

  
        // Insert into `studentbankdetails`
        db.query(`
          INSERT INTO studentbankdetails (user_id, BankName, Branch, BankAccountNumber, BankAccountName) 
          VALUES (?, ?, ?, ?, ?)
        `, [userId, BankName, Branch, BankAccountNumber, BankAccountName], (err) => {
          if (err) {
           
              console.error('Error inserting bank details:', err);
              return res.status(500).json({ message: 'An error occurred while inserting bank details.' });
          
          }
  
          // Insert into `parentguardiandetails`
          db.query(`
            INSERT INTO parentguardiandetails (user_id, FullName, Occupation, PostalAddressParents, 
            PhysicalAddressParents, HomeVillageParents, DistrictParents, EmailParents, PhoneNumberParents) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          `, [userId, FullName, Occupation, PostalAddressParents, PhysicalAddressParents, HomeVillageParents, 
              DistrictParents, EmailParents, PhoneNumberParents], (err) => {
            if (err) {
            
                console.error('Error inserting guardian details:', err);
                return res.status(500).json({ message: 'An error occurred while inserting guardian details.' });
           
            }
  
            // Insert into `studentuniversitydetails`
            db.query(`
              INSERT INTO studentuniversitydetails (user_id, UniversityName, ProgramOfStudy, RegistrationNumber, 
              AcademicYear, YearOfStudy) 
              VALUES (?, ?, ?, ?, ?, ?)
            `, [userId, UniversityName, ProgramOfStudy, RegistrationNumber, AcademicYear, YearOfStudy], (err) => {
              if (err) {
             
                  console.error('Error inserting university details:', err);
                  return res.status(500).json({ message: 'An error occurred while inserting university details.' });
             
              }
  
              // Commit the transaction if all queries succeed
             
                if (err) {
                
                    console.error('Error committing transaction:', err);
                    return res.status(500).json({ message: 'An error occurred while committing the transaction.' });
              
                }
                res.status(200).json({ message: 'Form submitted successfully!' });
              });
            });
          });
        });
      });


app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
