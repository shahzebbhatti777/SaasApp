const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const passport = require('passport');

dotenv.config();

const authRoutes = require('./auth');

const app = express();

app.use(cors());
app.use(express.json());
app.use(passport.initialize());

app.use('/api/auth', authRoutes);

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
