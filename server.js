const express = require('express');

const app = express();

app.get('/', (req, res) => {
  res.send('Webshop server werkt 🚀');
});

app.listen(3000, () => {
  console.log('Server draait op poort 3000');
});
