const MongoClient = require('mongodb').MongoClient;
const assert = require('assert');

/*
 * Requires the MongoDB Node.js Driver
 * https://mongodb.github.io/node-mongodb-native
 */

const filter = {
    'email': 'test@gmail.com'
  };
  
  MongoClient.connect(
    'mongodb://root:1234@localhost:27017/?authSource=admin&readPreference=primary&appname=MongoDB+Compass&ssl=false',
    { useNewUrlParser: true, useUnifiedTopology: true },
    function(connectErr, client) {
      assert.equal(null, connectErr);
      const coll = client.db('test').collection('users');
      coll.find(filter, (cmdErr, result) => {
        assert.equal(null, cmdErr);
      });
      client.close();
    });