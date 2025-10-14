const express = require('express');
const app = express();

app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.post('/users', (req, res) => {
  res.json({});
});

app.put('/users/:id', (req, res) => {
  res.json({});
});

app.delete('/users/:id', (req, res) => {
  res.json({});
});

const router = express.Router();

router.get('/products', (req, res) => {
  res.json([]);
});

router.post('/products', (req, res) => {
  res.json({});
});

app.use('/api', router);

app.listen(3000);