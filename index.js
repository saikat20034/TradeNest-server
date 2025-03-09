require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const morgan = require('morgan');
const stripe = require('stripe')(process.env.PAYMENT_SECRET_KEY);

const port = process.env.PORT || 5000;
const app = express();
// middleware
const corsOptions = {
  origin: [
    'http://localhost:5173',
    'http://localhost:5174',
    'http://localhost:5175',
    'http://localhost:5176',
    'http://localhost:5177',
    // 'https://medi-quest-c6cb9.web.app',
  ],
  credentials: true,
  optionSuccessStatus: 200,
};
app.use(cors(corsOptions));

app.use(express.json());
app.use(cookieParser());
app.use(morgan('dev'));

const verifyToken = async (req, res, next) => {
  const token = req.cookies?.token;

  if (!token) {
    return res.status(401).send({ message: 'unauthorized access' });
  }
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      console.log(err);
      return res.status(401).send({ message: 'unauthorized access' });
    }
    req.user = decoded;
    next();
  });
};

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@mycluster1.rs796.mongodb.net/?retryWrites=true&w=majority&appName=myCluster1`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
async function run() {
  try {
    const db = client.db('MediQuest');
    const userCollection = db.collection('users');
    const medicinesCollection = db.collection('medicines');
    const ordersCollection = db.collection('orders');

    // verify admin middleware
    const verifyAdmin = async (req, res, next) => {
      // console.log('hello',req.user?.email);
      const email = req.user?.email;
      const query = { email };
      const result = await userCollection.findOne(query);
      if (!result || result?.role !== 'admin')
        return res
          .status(403)
          .send({ message: 'Forbidden access ! Admin Only' });
      next();
    };

    // verify seller middleware
    const verifySeller = async (req, res, next) => {
      // console.log('hello',req.user?.email);
      const email = req.user?.email;
      const query = { email };
      const result = await userCollection.findOne(query);
      if (!result || result?.role !== 'seller')
        return res
          .status(403)
          .send({ message: 'Forbidden access! Seller Only' });
      next();
    };

    // save or update users in db
    app.post('/users/:email', async (req, res) => {
      const email = req.params.email;
      const query = { email };
      const user = req.body;
      // check if user already exists
      const isExist = await userCollection.findOne(query);
      if (isExist) {
        return res.send(isExist);
      }
      const result = await userCollection.insertOne({
        ...user,
        timestamp: Date.now(),
        role: 'customer',
      });
      res.send(result);
    });

    // manage user role
    app.patch('/users/:email', verifyToken, async (req, res) => {
      const email = req.params.email;

      const query = { email };
      const user = await userCollection.findOne(query);
      if (!user || user?.status === 'requested') {
        return res
          .status(400)
          .send({ message: 'Already Requested, wait some time' });
      }
      const { status } = req.body;
      const updateDoc = {
        $set: {
          status: 'requested',
        },
      };
      const result = await userCollection.updateOne(query, updateDoc);
      res.send(result);
    });

    // get all users
    app.get('/all-users/:email', verifyToken, verifyAdmin, async (req, res) => {
      const email = req.params.email;
      const query = { email: { $ne: email } };
      const result = await userCollection.find(query).toArray();
      res.send(result);
    });

    //  GET user data by email
    app.get('/user/:email', verifyToken, async (req, res) => {
      const email = req.params.email;
      const user = await userCollection.findOne({ email });
      if (!user) return res.status(404).send({ message: 'User not found' });
      res.send(user);
    });

    // UPDATE user profile
    app.put('/update-profile', verifyToken, async (req, res) => {
      const { email, displayName, photoURL } = req.body;
      if (!email) return res.status(400).send({ message: 'Email is required' });

      const existingUser = await userCollection.findOne({ email });
      if (
        existingUser.displayName === displayName &&
        existingUser.photoURL === photoURL
      ) {
        return res.status(400).send({ message: 'No changes detected' });
      }

      const updatedData = { $set: { displayName, photoURL } };
      const result = await userCollection.updateOne({ email }, updatedData);

      if (result.modifiedCount > 0) {
        res.send({ message: 'Profile updated successfully' });
      } else {
        res.status(400).send({ message: 'Failed to update profile' });
      }
    });

    // update password
    app.post('/update-password', async (req, res) => {
      const { email, currentPassword, newPassword } = req.body;

      try {
        // Verify the current password
        const user = await admin.auth().getUserByEmail(email);
        const auth = getAuth(); // Firebase Auth instance

        // Reauthenticate the user
        const credential = firebase.auth.EmailAuthProvider.credential(
          email,
          currentPassword
        );
        await reauthenticateWithCredential(auth.currentUser, credential);

        // Update the password
        await admin.auth().updateUser(user.uid, {
          password: newPassword,
        });

        res
          .status(200)
          .json({ success: true, message: 'Password updated successfully.' });
      } catch (error) {
        console.error('Error updating password:', error);
        res.status(400).json({ success: false, message: error.message });
      }
    });

    // get user role
    app.get('/users/role/:email', async (req, res) => {
      const email = req.params.email;
      const result = await userCollection.findOne({ email });
      // console.log(result);
      res.send(result);
    });

    // update user role
    app.patch('/users/role/:email', verifyToken, async (req, res) => {
      const email = req.params.email;
      const { role } = req.body;
      const filter = { email };
      const updateDoc = {
        $set: {
          role,
          status: 'verified',
        },
      };
      const result = await userCollection.updateOne(filter, updateDoc);
      res.send(result);
    });

    // Generate jwt token
    app.post('/jwt', async (req, res) => {
      const email = req.body;
      const token = jwt.sign(email, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: '365d',
      });
      res
        .cookie('token', token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        })
        .send({ success: true });
    });
    // Logout
    app.get('/logout', async (req, res) => {
      try {
        res
          .clearCookie('token', {
            maxAge: 0,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
          })
          .send({ success: true });
      } catch (err) {
        res.status(500).send(err);
      }
    });

    // add medicine
    app.post('/medicines', verifyToken, verifySeller, async (req, res) => {
      const med = req.body;
      const result = await medicinesCollection.insertOne(med);
      res.send(result);
      // console.log('Request Body:', req.body);
      // res.send('Received!');
    });

    // get medicine
    app.get('/medicines', async (req, res) => {
      const result = await medicinesCollection.find().toArray();
      res.send(result);
    });

    // get medicine by category
    app.get('/medicines/category/:category', async (req, res) => {
      try {
        const category = req.params.category;
        const query = { category: category };
        const result = await medicinesCollection.find(query).toArray();
        res.send(result);
      } catch (err) {
        console.log(err);
      }
    });

    // get medicine by id
    app.get('/medicines/:id', async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await medicinesCollection.findOne(query);
      res.send(result);
    });

    // save order to db
    app.post('/order', verifyToken, async (req, res) => {
      const orderInfo = req.body;
      const result = await ordersCollection.insertOne(orderInfo);
      res.send(result);
      // console.log('Request Body:', req.body);
      // res.send('Received!');
    });

    // get inventory data for seller
    app.get('/meds/seller', verifyToken, verifySeller, async (req, res) => {
      const email = req.user.email;
      const result = await medicinesCollection
        .find({ 'seller.email': email })
        .toArray();
      res.send(result);
    });

    // delete medicine by seller
    app.delete(
      '/medicines/:id',
      verifyToken,
      verifySeller,
      async (req, res) => {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await medicinesCollection.deleteOne(query);
        res.send(result);
      }
    );

    // medicine quantity after purchase
    app.patch('/medicines/quantity/:id', verifyToken, async (req, res) => {
      const id = req.params.id;
      const { quantityToUpdate, status } = req.body;
      const filter = { _id: new ObjectId(id) };
      let updateDoc = {
        $inc: { quantity: -quantityToUpdate },
      };
      if (status === 'increase') {
        updateDoc = {
          $inc: { quantity: quantityToUpdate },
        };
      }
      const result = await medicinesCollection.updateOne(filter, updateDoc);
      res.send(result);
    });

    // get orders from a user
    app.get('/customer-orders/:email', verifyToken, async (req, res) => {
      const email = req.params.email;
      const query = { 'customer.email': email };
      const result = await ordersCollection
        .aggregate([
          { $match: query },
          {
            $addFields: {
              medId: { $toObjectId: '$medId' },
            },
          },
          {
            $lookup: {
              from: 'medicines',
              localField: 'medId',
              foreignField: '_id',
              as: 'medicines',
            },
          },
          {
            $unwind: '$medicines',
          },
          {
            $addFields: {
              name: '$medicines.name',
              image: '$medicines.image',
              category: '$medicines.category',
            },
          },
          {
            $project: {
              medicines: 0,
            },
          },
        ])
        .toArray();
      res.send(result);
    });

    // get orders for seller
    app.get(
      '/seller-orders/:email',
      verifyToken,
      verifySeller,
      async (req, res) => {
        const email = req.params.email;
        console.log(email);
        const result = await ordersCollection
          .aggregate([
            { $match: { seller: email } },
            {
              $addFields: {
                medId: { $toObjectId: '$medId' },
              },
            },
            {
              $lookup: {
                from: 'medicines',
                localField: 'medId',
                foreignField: '_id',
                as: 'medicines',
              },
            },
            {
              $unwind: '$medicines',
            },
            {
              $addFields: {
                name: '$medicines.name',
              },
            },
            {
              $project: {
                medicines: 0,
              },
            },
          ])
          .toArray();
        // console.log(result);
        res.send(result);
      }
    );

    // cancel delete order
    app.delete('/order/:id', verifyToken, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const order = await ordersCollection.findOne(query);
      if (order.status === 'delivered') {
        return res.status(409).send({ message: 'Order already delivered' });
      }
      const result = await ordersCollection.deleteOne(query);
      res.send(result);
    });

    // update order status
    app.patch('/orders/:id', verifyToken, verifySeller, async (req, res) => {
      const id = req.params.id;
      const { status } = req.body;
      const filter = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: { status },
      };
      const result = await ordersCollection.updateOne(filter, updateDoc);
      res.send(result);
    });

    // admin stat
    app.get('/admin-stat', verifyToken, verifyAdmin, async (req, res) => {
      // total user, total medicine
      const totalUser = await userCollection.countDocuments();
      const totalMedicines = await medicinesCollection.estimatedDocumentCount();
      const allOrder = await ordersCollection.find().toArray();
      // const totalOrders = allOrder.length
      // const totalPrice = allOrder.reduce((sum, order) => sum + order.price, 0)
      //  get total revenue, total order
      const orderDetails = await ordersCollection
        .aggregate([
          {
            $group: {
              _id: null,
              totalRevenue: { $sum: '$price' },
              totalOrder: { $sum: 1 },
            },
          },
          {
            $project: {
              _id: 0,
            },
          },
        ])
        .next();
      res.send({ totalMedicines, totalUser, ...orderDetails, chartData });
    });

    // chart data
    const chartData = await ordersCollection
      .aggregate([
        {
          $group: {
            _id: {
              $dateToString: {
                format: '%Y-%m-%d',
                date: { $toDate: '$_id' },
              },
            },
            quantity: {
              $sum: '$quantity',
            },
            price: { $sum: '$price' },
            order: { $sum: 1 },
          },
        },
        {
          $project: {
            _id: 0,
            date: '$_id',
            quantity: 1,
            order: 1,
            price: 1,
          },
        },
      ])
      .next();

    // create payment intent
    app.post('/create-payment-intent/', verifyToken, async (req, res) => {
      const { quantity, medId } = req.body;
      const med = await medicinesCollection.findOne({
        _id: new ObjectId(medId),
      });
      if (!med) {
        return res.status(400).send({ message: 'product not found' });
      }
      const totalPrice = quantity * med.price * 100;
      // res.send({totalPrice})
      // console.log(totalPrice);
      const { client_secret } = await stripe.paymentIntents.create({
        amount: totalPrice,
        currency: 'usd',
        automatic_payment_methods: {
          enabled: true,
        },
      });
      res.send({ clientSecret: client_secret });
    });

    // console.log(chartData);
    // Send a ping to confirm a successful connection
    // await client.db('admin').command({ ping: 1 })
    // console.log(
    //   'Pinged your deployment. You successfully connected to MongoDB!'
    // )
  } finally {
    // Ensures that the client will close when you finish/error
  }
}
run().catch(console.dir);

app.get('/', (req, res) => {
  res.send('Hello from TradeNest Server..');
});

app.listen(port, () => {
  console.log(`TradeNest is running on port ${port}`);
});
