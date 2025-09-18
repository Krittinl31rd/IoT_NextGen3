var express = require('express');
var router = express.Router();

const WebSocketAdminManager = require('../server/websocketadminserver');
/* GET home page. */
router.get('/', function(req, res, next) {
  
  res.render('index', { title: 'Express' });
});
router.get('/dashboard/log/', function(req, res, next) {
  res.send('Logger');
});

module.exports = router;
