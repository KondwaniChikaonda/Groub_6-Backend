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
const port = 3001;

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




app.get('/', (req, res) => {
  res.send('Hello, World!');
});




app.post('/register', (req, res) => {
    const { username, password } = req.body;

    db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, password], (err, result) => {
        if (err) {
            res.status(500).send('Server error');
            return;
        }
        res.status(200).send('User registered');
    });
});



app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Query to find the user by email
    db.query('SELECT * FROM users WHERE email = ?', [username], async (err, result) => {
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

            // Generate a JWT token
            const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
                expiresIn: 1200 // 20 minutes in seconds
            });

            res.status(200).send({ auth: true, token });
        } catch (compareErr) {
            res.status(500).send('Server error');
        }
    });
});




app.get('/user', (req, res) => {
    // Extract token from request headers
    const token = req.headers.authorization.split(' ')[1];
    // Verify and decode token (example using jwt.verify)
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).send('Unauthorized');
        }
        // Find user in database based on decoded token (e.g., user ID)
        db.query('SELECT * FROM users WHERE id = ?', [decoded.id], (err, result) => {
            if (err) {
                return res.status(500).send('Server error');
            }
            if (!result[0]) {
                return res.status(404).send('User not found');
            }
            // Return user data
            const user = {
                id: result[0].id,
                username: result[0].username,
                email: result[0].email,
                gender: result[0].gender,
                phoneNumber: result[0].phoneNumber,
                description: result[0].description,
                location: result[0].location
            };
            res.status(200).json(user);
        });
    });
});





app.get('/count-users', (req, res) => {
  // Execute the query to get the count of users
  db.query('SELECT COUNT(*) AS userCount FROM users', (err, results) => {
    if (err) {
      console.error('Error fetching user count:', err);
      return res.status(500).json({ message: 'Error fetching user count' });
    }

    // Extract the count from the query result
    const userCount = results[0]?.userCount;

    // Send the count as a JSON response
    res.json({ count: userCount });
  });
});























// Get all users
app.get('/users', (req, res) => {
    const sql = 'SELECT * FROM users';
    db.query(sql, (err, result) => {
      if (err) throw err;
      res.send(result);
    });
  });
  





  // Add new user
  app.post('/users', (req, res) => {
    
    const { username, password, email, dob, gender } = req.body;

    const birthday = new Date(dob);
    const today = new Date();

    const age = today.getFullYear() - birthday.getFullYear();

    const sql = 'INSERT INTO users (username, password, email, dob, gender) VALUES (?, ?, ?, ?, ?)';
    db.query(sql, [username, password, email, dob, gender], (err, result) => {
      if (err) throw err;
      res.send(result);
    
    });

  });
  
  

  // Edit user
  app.put('/users/:id', async (req, res) => {
      const { id } = req.params;
      const { username, password, email, gender, phoneNumber, description,location} = req.body;
  
      function removeSpaces(str) {
          return str.replace(/\s+/g, '');
      }  
     
      const phoneWithoutSpaces = removeSpaces(phoneNumber);
  
      console.log(phoneWithoutSpaces);
      console.log(password);
      console.log(id);
  
      // If password is not provided, update the user without changing the password
      if (!password) {
          const sql = 'UPDATE users SET username = ?, email = ?, gender = ?, phoneNumber = ?, description = ?, location = ? WHERE id = ?';
          db.query(sql, [username, email, gender, phoneWithoutSpaces, description, location, id], (err, result) => {
              if (err) {
                  return res.status(500).json({ message: 'Database update error', err });
              }
              res.send(result);
          });
      } else {
          try {
              // Hash the password if it's provided
              const saltRounds = 10;
              const hashedPassword = await bcrypt.hash(password, saltRounds);
  
              const sql = 'UPDATE users SET username = ?, password = ?, email = ?, gender = ?, phoneNumber = ?, description = ?, location = ? WHERE id = ?';
              db.query(sql, [username, hashedPassword, email, gender, phoneWithoutSpaces, description, location, id], (err, result) => {
                  if (err) {
                      return res.status(500).json({ message: 'Database update error', err });
                  }
                  res.send(result);
              });
          } catch (err) {
              return res.status(500).json({ message: 'Error hashing password', err });
          }
      }
  });
  




  
  // Delete user
  app.delete('/users/:id', (req, res) => {
    const { id } = req.params;
    const sql = 'DELETE FROM users WHERE id = ?';
    db.query(sql, [id], (err, result) => {
      if (err) throw err;
      res.send(result);
    });
  });
  
  




  //Get all products to the market
  app.get('/products', (req, res) => {
    const sql = `
      SELECT p.*, u.phoneNumber, u.location, u.description AS userDescription, u.email AS email, u.username AS owner_username
      FROM product p
      LEFT JOIN users u ON p.owner_id = u.id
      ORDER BY created_at DESC
    `;
    db.query(sql, (err, result) => {
      if (err) throw err;
      res.send(result);
    });
  });







  //Get all products
  app.get('/houses', (req, res) => {
    const sql = `
      SELECT p.*, u.phoneNumber, u.email AS email, u.username AS owner_username
      FROM accommodation p
      LEFT JOIN users u ON p.owner_id = u.id
      ORDER BY created_at DESC
    `;
    db.query(sql, (err, result) => {
      if (err) throw err;
      res.send(result);
    });
  });




















app.post('/messages',authenticateToken, async (req, res) => {
  const { recipientId, description } = req.body;

  if (!recipientId || !description) {
    return res.status(400).json({ error: 'Recipient ID and description are required' });
  }

  const senderId = req.user.id; // Assuming you have user information in req.user

  try {
    // Insert into messages table
    const [result] = await db.execute('INSERT INTO messages (sender_id, recipient_id, description) VALUES (?, ?, ?)', [senderId, recipientId, description]);

    // Optionally, you can send back the inserted message
    const insertedMessage = {
      id: result.insertId,
      sender_id: senderId,
      recipient_id: recipientId,
      description: description,
      created_at: new Date().toISOString() // Adjust as per your timestamp format
    };

    res.status(201).json(insertedMessage);
  } catch (err) {
    console.error('Error inserting message:', err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});















// Assuming this is your existing endpoint setup
app.get('/messages', authenticateToken, (req, res) => {
  const ownerId = req.user.id; // Get owner_id from authenticated user
  const query = `
    SELECT messages.*, users.username as sender_username
    FROM messages
    INNER JOIN users ON messages.sender_id = users.id
    WHERE messages.recipient_id = ?
    ORDER BY messages.sender_id, messages.created_at ASC
  `;

  db.query(query, [ownerId], (err, results) => {
    if (err) {
      console.error('Error fetching messages:', err);
      return res.status(500).send(err);
    }

    // Organize messages by sender
    const groupedMessages = results.reduce((acc, message) => {
      const senderId = message.sender_id;
      if (!acc[senderId]) {
        acc[senderId] = {
          senderId: senderId,
          senderUsername: message.sender_username,
          messages: []
        };
      }
      acc[senderId].messages.push({
        id: message.id,
        description: message.description,
        sender_id: message.sender_id,
        sender_username: message.sender_username,
        created_at: message.created_at
      });
      return acc;
    }, {});

    res.json(Object.values(groupedMessages)); // Send grouped messages data as JSON response
  });
});






 
  // Delete user
  app.delete('/messages/:id', (req, res) => {
    const messageId  = req.params.id;;


    console.log("delete message "+ messageId);

    const sql = 'DELETE FROM messages WHERE id = ?';
    db.query(sql, [messageId], (err, result) => {
      if (err) throw err;
      res.send(result);
    });
  });











//GETTING THE BLOG
app.get('/blogs', (req, res) => {
  const query = 'SELECT * FROM blog ORDER BY created_at DESC';

  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching blogs:', err);
      return res.status(500).send('Error fetching blogs');
    }
    res.json(results);
  });
});







// Endpoint to get products
app.get('/my-product', authenticateToken, (req, res) => {
  const query = 'SELECT * FROM product WHERE owner_id = ? ORDER BY created_at DESC';
  db.query(query, [req.user.id], (err, results) => {
    if (err) {
      console.error('Error fetching products:', err);
      res.status(500).send('Error fetching products');
    } else {
      res.json(results);
    }
  });
});









  // Assuming you have a route like this in your Node.js backend

app.get('/products', async (req, res) => {
  const searchTerm = req.query.search || '';
  try {
    let products = await Product.findAll({
      where: {
        [Op.or]: [
          { name: { [Op.like]: `%${searchTerm}%` } },
          { description: { [Op.like]: `%${searchTerm}%` } },
          { owner_username: { [Op.like]: `%${searchTerm}%` } },
          { email: { [Op.like]: `%${searchTerm}%` } }
        ]
      }
    });

    // Transforming products to include likes count
    products = products.map(product => ({
      ...product.toJSON(),
      likes: product.likes || 0 // Default to 0 if likes are null
    }));

    res.json(products);
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

  




app.post('/orders', (req, res) => {
  const { productId, Owner, buyerId, email } = req.body;

  console.log(email);

  const query = 'INSERT INTO cart (product_id, owner_id, buyer_id) VALUES (?, ?, ?)';
  
  db.query(query, [productId, Owner, buyerId], (err, result) => {
    if (err) {
      return res.status(500).send(err);
    }

    
    const mailOptions = {
      from: MAILTRAP_USERNAME,
      to: email,
      subject: 'Congratulations!, Received a Request in waiiona market',
      text: `You have received a request from waiiona market, please login to get in touch with your customer. Click the link to login: https://www.waiiona.store/Login`
    };

    
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending email:', error);
        return res.status(500).json({ message: 'Error sending email', error });
      }
      
      // If everything is successful
      res.status(200).json({ message: 'Product ordered and email sent successfully!' });
    });
  });
});








app.get('/my-cart', authenticateToken, (req, res) => {
  const userId = req.user.id;

  // First query to get cart details
  const cartQuery = `
    SELECT cart.*, product.*, users.username, users.location, users.description AS userDescription, users.phoneNumber, users.email 
    FROM cart 
    JOIN product ON cart.product_id = product.id 
    JOIN users ON product.owner_id = users.id 
    WHERE cart.buyer_id = ?
  `;

  // Second query to get product count and total price
  const anotherQuery = `
    SELECT c.buyer_id, COUNT(c.product_id) AS product_count, SUM(p.price) AS total_price 
    FROM cart c 
    JOIN product p ON c.product_id = p.id 
    WHERE c.buyer_id = ?
    GROUP BY c.buyer_id
  `;

  db.query(cartQuery, [userId], (err, cartResult) => {
    if (err) {
      return res.status(500).send(err);
    }

    db.query(anotherQuery, [userId], (err, summaryResult) => {
      if (err) {
        return res.status(500).send(err);
      }

      // Combine the results
      const response = {
        cart: cartResult,
        summary: summaryResult[0] // There should be only one row for the summary query
      };

      res.json(response);
    });
  });
});












app.get('/my-notice', authenticateToken, (req, res) => {
  const userId = req.user.id;

  // First query to get cart details
  const cartQuery = `
  SELECT cart.*, product.*, users.username, users.phoneNumber, users.email 
  FROM cart 
  JOIN product ON cart.product_id = product.id 
  JOIN users ON cart.buyer_id = users.id 
  WHERE cart.owner_id = ?`;

  // Second query to get product count and total price
  const anotherQuery = `
    SELECT c.buyer_id, COUNT(c.product_id) AS product_count, SUM(p.price) AS total_price 
    FROM cart c 
    JOIN product p ON c.product_id = p.id 
    WHERE c.owner_id = ?
    GROUP BY c.owner_id
  `;

  db.query(cartQuery, [userId], (err, cartResult) => {
    if (err) {
      return res.status(500).send(err);
    }

    db.query(anotherQuery, [userId], (err, summaryResult) => {
      if (err) {
        return res.status(500).send(err);
      }

      // Combine the results
      const response = {
        cart: cartResult,
        summary: summaryResult[0] // There should be only one row for the summary query
      };

      res.json(response);
    });
  });
});








app.get('/check-cart',(req, res) => {
  const { product_id, buyer_id } = req.query;

  const query = 'SELECT * FROM cart WHERE product_id = ? AND buyer_id = ?';

  db.query(query, [product_id, buyer_id], (err, results) => {
    if (err) {
      console.error('Database query error:', err);
      return res.status(500).json({ message: 'Database query error', err });
    }

    if (results.length === 0) {
      return res.status(200).json({ exists: false });
    }

    return res.status(200).json({ exists: true });
  });
});






app.delete('/my-notice/:id', (req, res) => {
  const { id } = req.params;
  const { buyer } = req.query;

  const sql = 'DELETE FROM cart WHERE product_id = ? AND buyer_id = ?';
  db.query(sql, [id, buyer], (err, result) => {
    if (err) throw err;
    res.send({ message: 'Product deleted' });
  });
});








app.delete('/my-cart/:id', authenticateToken, (req, res) => {
  const { id } = req.params;

  const sql = 'DELETE FROM cart WHERE product_id = ? AND buyer_id = ?';
  db.query(sql, [id, req.user.id], (err, result) => {
    if (err) throw err;
    res.send({ message: 'Product deleted' });
  });
});








app.get('/cart-notification-count', (req, res) => {
  const ownerId = req.query.owner_id;  // or however you pass the owner ID

  const anotherQuery = `
    SELECT c.buyer_id, COUNT(c.product_id) AS product_count, SUM(p.price) AS total_price 
    FROM cart c 
    JOIN product p ON c.product_id = p.id 
    WHERE c.owner_id = ?
    GROUP BY c.owner_id
  `;

  db.query(anotherQuery, [ownerId], (err, results) => {
    if (err) {
      console.error('Error fetching cart notifications:', err);
      return res.status(500).json({ message: 'Error fetching cart notifications' });
    }

    const notificationCount = results.length > 0 ? results[0].product_count : 0;
    res.json({ count: notificationCount });
  });
});












// Endpoint to handle file upload

app.post('/upload/:id', authenticateToken, upload.single('picture'), (req, res) => {

      const { id } = req.params;
 
      console.log(req.file.path);
      const filename  = req.file.path;
      
      // Update file information into the database
      const query = 'UPDATE users SET picture = ? WHERE id = ?';
      db.query(query, [filename, id], (err, result) => {
        if (err) throw err;
        res.send('File uploaded and saved to database.');
      });
 
});







const fs = require('fs');
const uploadsDir = './uploads';
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}







app.post('/my-product', authenticateToken, upload.single('picture'), (req, res) => {
  const { name, price, description, status } = req.body;
  const picture = req.file ? req.file.path : null;
  const ownerId = req.user.id; // Extracted from token




  if(!picture){

          const myPicture = 'https://res.cloudinary.com/danbkh9uu/image/upload/v1724928038/rgtan5tzrqf4xfimgxnb.png';

    const sql = 'INSERT INTO product (name, price, description, picture, status, owner_id) VALUES (?, ?, ?, ?, ?, ?)';
    db.query(sql, [name, price, description, myPicture, status, ownerId], (err, result) => {
      if (err) throw err;
      res.send({ id: result.insertId, name, price, description, myPicture, status });
    });

  }

  else{
    const sql = 'INSERT INTO product (name, price, description, picture, status, owner_id) VALUES (?, ?, ?, ?, ?, ?)';
    db.query(sql, [name, price, description, picture, status, ownerId], (err, result) => {
      if (err) throw err;
      res.send({ id: result.insertId, name, price, description, picture, status });
    });

  }


 
});






app.put('/my-product/:id', authenticateToken, upload.single('picture'), (req, res) => {
  const { id } = req.params;
  const { name, price, description, status } = req.body;
  const picture = req.file ? req.file.path : null;
    
 if(!picture){
     
  const sql = 'UPDATE product SET name = ?, price = ?, description = ?, status = ? WHERE id = ? AND owner_id = ?';
  db.query(sql, [name, price, description,status, id, req.user.id], (err, result) => {
    if (err) throw err;
    res.send({ id, name, price, description, status });
  });

 }
  else{

    const sql = 'UPDATE product SET name = ?, price = ?, description = ?, picture = ?, status = ? WHERE id = ? AND owner_id = ?';
    db.query(sql, [name, price, description, picture, status, id, req.user.id], (err, result) => {
      if (err) throw err;
      res.send({ id, name, price, description, picture, status });
    });

  }


});

app.delete('/my-product/:id', authenticateToken, (req, res) => {
  const { id } = req.params;

  const sql = 'DELETE FROM product WHERE id = ? AND owner_id = ?';
  db.query(sql, [id, req.user.id], (err, result) => {
    if (err) throw err;
    res.send({ message: 'Product deleted' });
  });
});








// Update Picture
app.post('/users/:id/picture', authenticateToken, upload.single('picture'), async (req, res) => {
  const userId = req.params.id;
  const picture = req.file ? req.file.path : null;
  console.log(picture);

  try {
    // Update user record with the new picture path
    await db.query('UPDATE users SET picture = ? WHERE id = ?', [picture, userId]);
    res.status(200).json({ message: 'Profile picture updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update profile picture' });
  }
});

// Remove Picture
app.delete('/users/:id/picture', authenticateToken, async (req, res) => {
  const userId = req.params.id;

  try {
    // Update user record to remove picture
    await db.query('UPDATE users SET picture = NULL WHERE id = ?', [userId]);
    res.status(200).json({ message: 'Profile picture removed successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to remove profile picture' });
  }
});
























app.post('/my-house', authenticateToken, upload.single('picture'), (req, res) => {
  const { name, price, description, status, location } = req.body;
  const picture = req.file ? req.file.path : null;
  const ownerId = req.user.id; 


  if(!picture){

    const myPicture = 'https://res.cloudinary.com/danbkh9uu/image/upload/v1724928038/rgtan5tzrqf4xfimgxnb.png';

    const sql = 'INSERT INTO accommodation (name, price, description, picture, status, location, owner_id) VALUES (?, ?, ?, ?, ?, ?, ?)';
    db.query(sql, [name, price, description, myPicture, status, location, ownerId], (err, result) => {
      if (err) throw err;
      res.send({ id: result.insertId, name, price, description, myPicture, status, location });
    });

  }

  else {


    const sql = 'INSERT INTO accommodation (name, price, description, picture, status, location, owner_id) VALUES (?, ?, ?, ?, ?, ?, ?)';
    db.query(sql, [name, price, description, picture, status, location, ownerId], (err, result) => {
      if (err) throw err;
      res.send({ id: result.insertId, name, price, description, picture, status, location });
    });


  }


});



app.put('/my-house/:id', authenticateToken, upload.single('picture'), (req, res) => {
  const { id } = req.params;
  const { name, price, description, status, location } = req.body;
  const picture = req.file ? req.file.path : null;
    
 if(!picture){
     
  const sql = 'UPDATE accommodation SET name = ?, price = ?, description = ?, status = ?, location = ? WHERE id = ? AND owner_id = ?';
  db.query(sql, [name, price, description,status, location, id, req.user.id], (err, result) => {
    if (err) throw err;
    res.send({ id, name, price, description, status, location });
  });

 }
  else{

    const sql = 'UPDATE accommodation SET name = ?, price = ?, description = ?, picture = ?, status = ?, location = ? WHERE id = ? AND owner_id = ?';
    db.query(sql, [name, price, description, picture, status, location, id, req.user.id], (err, result) => {
      if (err) throw err;
      res.send({ id, name, price, description, picture, status, location });
    });

  }


});



app.delete('/my-house/:id', authenticateToken, (req, res) => {
  const { id } = req.params;

  const sql = 'DELETE FROM accommodation WHERE id = ? AND owner_id = ?';
  db.query(sql, [id, req.user.id], (err, result) => {
    if (err) throw err;
    res.send({ message: 'Product deleted' });
  });
});



app.get('/my-house', authenticateToken, (req, res) => {
  const query = 'SELECT * FROM accommodation WHERE owner_id = ? ORDER BY created_at DESC';
  db.query(query, [req.user.id], (err, results) => {
    if (err) {
      console.error('Error fetching products:', err);
      res.status(500).send('Error fetching products');
    } else {
      res.json(results);
    }
  });
});
























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

app.post('/api/users/reset-password-request', (req, res) => {
  const { email } = req.body;

  db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) {
      return res.status(500).json({ message: 'Database query error', err });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    const token = generateResetToken(email);
    const expiry = new Date(Date.now() + 3600000); // 1 hour from now

    db.query('UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?', [token, expiry, email], (err) => {
      if (err) {
        return res.status(500).json({ message: 'Database update error', err });
      }

      const mailOptions = {
        from: MAILTRAP_USERNAME, // This can be any email
        to: email,
        subject: 'Password Reset',
        text: `You requested a password reset. Click the link to reset your password: https://www.waiiona.store/ResetPassword?token=${token}`
      };

      transporter.sendMail(mailOptions, (error, info) => {
        console.log(email);
        if (error) {
          console.error('Error sending email:', error);
          return res.status(500).json({ message: 'Error sending email', error });
        }
        console.log('Email sent:', info.response);
        res.status(200).json({ message: 'Password reset email sent' });
      });
    });
  });
});













app.post('/api/users/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const email = decoded.email;
        console.log(email);
        console.log(decoded);

        db.query('SELECT * FROM users WHERE email = ? AND reset_token = ? AND reset_token_expiry > ?', [email, token, new Date()], async (err, results) => {
            if (err) {
                return res.status(500).json({ message: 'Database query error', err });
            }

            if (results.length === 0) {
                return res.status(400).json({ message: 'Invalid or expired token' });
            }

            try {
                // Hash the new password before updating it in the database
                const saltRounds = 10;
                const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

                // Update the user's password in the database
                db.query('UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE email = ?', [hashedPassword, email], (err) => {
                    if (err) {
                        return res.status(500).json({ message: 'Database update error', err });
                    }

                    res.status(200).json({ message: 'Password reset successful' });
                });
            } catch (hashError) {
                return res.status(500).json({ message: 'Error hashing password', hashError });
            }
        });
    } catch (error) {
        res.status(400).json({ message: 'Invalid or expired token', error });
    }
});

















const otps = {}; // Store OTPs in-memory for simplicity (consider a more persistent storage in production)










app.post('/send-otp-email',(req, res) => {
  const {email} = req.body;

  console.log("email only "+email);
  
  const otp = Math.floor(100000 + Math.random() * 900000).toString(); // Generate a 6-digit OTP
  otps[email] = otp;

  const mailOptions = {
      from:   MAILTRAP_USERNAME,
      to: email,
      subject: 'Your OTP Code From Waiona!',
      text: `Welcome to Waiona Market Please Enter Your OTP Code To change your email ${otp}`
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



app.put('/verify-otp-email/:id', (req, res) => {
  const { email, otp } = req.body;
  const userId = req.params.id; // Get the user ID from the URL parameter

  console.log('Received OTP for email verification:', {
    email,
    otp,
    userId,
  });

  if (otps[email] === otp) {
    delete otps[email]; // Remove OTP after successful verification

    // Update user's email in the database
    db.query('UPDATE users SET email = ? WHERE id = ?', [email, userId], (err, result) => {
      if (err) {
        console.error('Error updating user email:', err);
        return res.status(500).send({ success: false, message: 'Server error' });
      }

      if (result.affectedRows > 0) {
        res.send({ success: true, message: 'Email updated successfully.' });
      } else {
        res.status(404).send({ success: false, message: 'User not found.' });
      }
    });
  } else {
    console.log('Invalid OTP for email:', email);
    res.send({ success: false, message: 'Invalid OTP.' });
  }
});






























app.post('/send-otp', (req, res) => {
    const { username, password, email, gender, phoneNumber } = req.body;


    
    const otp = Math.floor(100000 + Math.random() * 900000).toString(); // Generate a 6-digit OTP
    otps[email] = otp;

    const mailOptions = {
        from:   MAILTRAP_USERNAME,
        to: email,
        subject: 'Your OTP Code From Waiona!',
        text: `Welcome to Waiona Market Please Enter Your OTP Code To Start Our services ${otp}`
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
    const { email, otp, username, password, gender, phoneWithoutSpaces } = req.body;

    console.log(otps[email]);

    if (otps[email] === otp) {
        delete otps[email]; // Remove OTP after successful verification

        try {
            // Hash the password before storing it
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            // Insert user into the database with the hashed password
            db.query('INSERT INTO users (username, password, email, gender, phoneNumber) VALUES (?, ?, ?, ?, ?)', 
                [username, hashedPassword, email, gender, phoneWithoutSpaces], 
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















app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
