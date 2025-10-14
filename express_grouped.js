const express = require('express');
const axios = require('axios');
const app = express();

// API v1 routes
app.use('/api/v1', (req, res, next) => {
  console.log('API v1 middleware');
  next();
});

const v1Router = express.Router();

v1Router.get('/users', async (req, res) => {
  // External API call
  const users = await axios.get('https://jsonplaceholder.typicode.com/users');
  res.json(users.data);
});

v1Router.post('/users', async (req, res) => {
  // External API call for validation
  await axios.post('https://api.validation-service.com/validate', req.body);
  res.json({ id: 1, ...req.body });
});

v1Router.get('/users/:id', (req, res) => {
  res.json({ id: req.params.id });
});

// External service call using fetch
v1Router.get('/users/:id/profile', async (req, res) => {
  const profile = await fetch('https://profile-service.com/api/profile/' + req.params.id);
  res.json(await profile.json());
});

app.use('/api/v1', v1Router);

// API v2 routes with different prefix
app.use('/api/v2', require('./v2-routes'));

app.listen(3000);