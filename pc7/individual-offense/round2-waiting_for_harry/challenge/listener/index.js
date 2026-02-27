const express = require('express');

const app = express();



class RingBuffer {
  constructor(capacity) {
    this.buffer = Array(capacity).fill(undefined);
    this.start = 0;
    this.current = 0;
    this.length = 0;
  }
  
  push(element) {
    this.buffer[(this.start + this.length) % this.buffer.length] = element;
    if(this.length < this.buffer.length) {
      this.length += 1;
    }
    else if (this.length === this.buffer.length) {
      this.start = (this.start + 1) % this.buffer.length;
    }
    return this.length;
  }

  *[Symbol.iterator]() {
    for (let i = 0; i < this.length; i += 1) {
      yield this.buffer[(this.start + i) % this.buffer.length];
    }
  }

}


const logs = new RingBuffer(100);

// app.use((req, res, next) => {
//   res.set('Cross-Origin-Opener-Policy', 'same-origin');
//   res.set('Cross-Origin-Embedder-Policy', 'require-corp');
//   next();
// });

app.get('/logs', (req, res) => {
  res.json([...logs]);
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.text());

app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "X-Requested-With");
  res.header("Cross-Origin-Resource-Policy", "cross-origin");
  next();
 });


// eslint-disable-next-line no-unused-vars
app.all('/:statusCode/:log', (req, res, next) => {
  const { statusCode, log } = req.params;

  logs.push({
    body : req.body,
    method : req.method,
    path : req.path,
    query : req.query,
    log : log,
    timestamp : new Date()
  });
  res.sendStatus(parseInt(statusCode));
});


// eslint-disable-next-line no-unused-vars
app.use((req, res, next) => {
  logs.push({
    body : req.body,
    method : req.method,
    path : req.path,
    query : req.query,
    timestamp : new Date()
  });
  res.sendStatus(200);
});

app.listen(80, () => {
  console.log('Server is running on port 80');
});
