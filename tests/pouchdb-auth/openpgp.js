const {BASE_URL, HTTP_AUTH, PouchDB, should, shouldThrowError} = require('./utils');
const openpgp = require('openpgp');
const request = require('request');

function generate() {
  var opts = {
    userIds: [{ name:'test', email:'test@test.net' }],
    curve: "ed25519"
    // passphrase: 'super long and hard to guess secret'         // protects the private key
  };
  return openpgp.generateKey(opts);//.then(function(key){return key.privateKeyArmored});
}

describe('SyncHTTPOpenPGPAuthTests', () => {
  it('should work with http dbs', () => {
    const db = new PouchDB(BASE_URL + "/_users", {auth: HTTP_AUTH});
    let key;
    let passwd;

    return db.useAsAuthenticationDB()

    .then((response) => {
      should.not.exist(response);
      return generate();
    })
    .then((aKey) => {
      key = aKey;
      return db.signUp("username", key.publicKeyArmored, {roles: ["test"]});
    })

    .then((signUpData) => {
      signUpData.rev.indexOf("1-").should.equal(0);
      signUpData.ok.should.be.ok;
      signUpData.id.should.equal("org.couchdb.user:username");

      return db.get("org.couchdb.user:username");
    })

    .then((doc) => {
      doc._rev.indexOf("1-").should.equal(0);
      doc.should.not.have.property("derived_key");
      doc.iterations.should.equal(10);
      doc.name.should.equal("username");
      doc.password_scheme.should.equal("openpgp");
      doc.roles.should.eql(["test"]);
      doc.should.have.property("salt");
      doc.type.should.equal("user");

      doc.should.have.property("password");
      doc.password.should.equal(key.publicKeyArmored);
      return new Promise((resolve,reject)=>{
        request.get({url: BASE_URL + "/_sys", json: true}, (err, res, data)=>{
          if (err) return reject(err);
          resolve(data);
        })
      })

    }).then((data) => {
      const publicKeys = openpgp.key.readArmored(data.pk).keys;
      delete data.pk;
      data.name = "username";
      //expired(time) after 15 seconds
      data.time = new Date((new Date(data.time)).valueOf() + 15000);
      // delete data.time; //this password never expired if no time.
      return openpgp.encrypt({data: JSON.stringify(data), publicKeys, privateKeys:key.key, armor:true});
    }).then((encrypted) => {
      passwd = encrypted.data;
      return db.session();
    })

    .then((session) => {
      //basic auth active
      shouldBeAdmin(session);

      return db.logIn("username", passwd);
    })

    .then((logInData) => {
      logInData.should.eql({
        ok: true,
        name: "username",
        roles: ["test"]
      });

      return db.session();
    })

    .then((session2) => {
      session2.userCtx.should.eql({
        name: "username",
        roles: ["test"]
      });
      session2.info.authenticated.should.equal("cookie");

      return db.logOut();
    })

    .then((logOutData) => {
      logOutData.ok.should.be.ok;

      return db.session();
    })

    .then((/*session3*/) => {
      // TODO: session is {name: "username",roles: ["test"]}, but shoudl be admin?
      // shouldBeAdmin(session3);

      return db.logOut();
    })

    .then((logOutData2) => {
      logOutData2.ok.should.be.ok;

      return shouldThrowError(() => db.logIn("username", "wrongPassword"));
    })

    .then((error) => {
      error.status.should.equal(401);
      error.name.should.equal("unauthorized");
      error.message.should.equal("Name or password is incorrect.");

      return db.get("org.couchdb.user:username");
    })

    .then((doc) => {
      return db.remove(doc);
    })

    .then((removeResponse) => {
      removeResponse.ok.should.be.ok;

      db.stopUsingAsAuthenticationDB();
    });
  });

  function shouldBeAdmin(session) {
    session.info.authentication_handlers.should.contain("cookie");
    session.info.authentication_db.should.equal("_users");
    session.userCtx.should.eql({
      name: (HTTP_AUTH || {}).username || null,
      roles: ["_admin"]
    });
    session.ok.should.be.ok;
  }
});
